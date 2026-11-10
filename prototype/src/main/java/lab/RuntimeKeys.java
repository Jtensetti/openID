package lab;

import java.io.ByteArrayInputStream;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import javax.net.ssl.*;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;

/** Explicit file-backed runtime credentials. Not an HSM or a release approval. */
public final class RuntimeKeys implements ServiceKeys {
  private final Path directory;
  private final String role;
  private final Map<String, KeyStore> stores = new HashMap<>();
  private final Map<String, String> passwords = new HashMap<>();
  private final Map<String, X509Certificate> certificates = new HashMap<>();
  private final String subjectSecret;

  public RuntimeKeys(Path path, String role) throws Exception {
    if (!Set.of("idp", "sp").contains(role)) throw new IllegalArgumentException("Service role required");
    this.role = role;
    directory = path.toAbsolutePath().normalize();
    if (!directory.equals(directory.toRealPath()) || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)
        || !Files.getPosixFilePermissions(directory).equals(PosixFilePermissions.fromString("rwx------")))
      throw new IllegalArgumentException("Private real credential directory required");
    String peer = role.equals("idp") ? "sp" : "idp";
    Set<String> expected = new HashSet<>(Set.of("tls.p12", "tls.password", role + ".p12",
        role + ".password", peer + ".crt"));
    if (role.equals("idp")) expected.add("subject-secret");
    try (var files = Files.list(directory)) {
      if (!files.map(p -> p.getFileName().toString()).collect(java.util.stream.Collectors.toSet()).equals(expected))
        throw new IllegalArgumentException("Unexpected or missing service credential file");
    }
    for (String alias : List.of("tls", role)) {
      String password = new String(readPrivate(alias + ".password", 256), java.nio.charset.StandardCharsets.US_ASCII).strip();
      if (!password.matches("[A-Za-z0-9_-]{43,128}")) throw new IllegalArgumentException("Strong private store password required");
      var store = KeyStore.getInstance("PKCS12");
      store.load(new ByteArrayInputStream(readPrivate(alias + ".p12", 1_048_576)), password.toCharArray());
      if (!new HashSet<>(Collections.list(store.aliases())).equals(Set.of(alias)) || !store.isKeyEntry(alias))
        throw new IllegalArgumentException("Exactly one service private key required");
      var cert = (X509Certificate) store.getCertificate(alias);
      validateCertificate(cert);
      var challenge = new byte[32]; new SecureRandom().nextBytes(challenge);
      var signature = Signature.getInstance("SHA256withRSA");
      signature.initSign((PrivateKey) store.getKey(alias, password.toCharArray())); signature.update(challenge);
      byte[] signed = signature.sign(); signature.initVerify(cert); signature.update(challenge);
      if (!signature.verify(signed)) throw new IllegalArgumentException("Private key and certificate mismatch");
      stores.put(alias, store); passwords.put(alias, password); certificates.put(alias, cert);
    }
    var input = new ByteArrayInputStream(readPrivate(peer + ".crt", 65_536));
    var peerCertificates = CertificateFactory.getInstance("X.509").generateCertificates(input);
    if (peerCertificates.size() != 1) throw new IllegalArgumentException("Exactly one pinned peer certificate required");
    var peerCertificate = (X509Certificate) peerCertificates.iterator().next();
    validateCertificate(peerCertificate); certificates.put(peer, peerCertificate);
    if (Arrays.equals(certificate(role).getPublicKey().getEncoded(), peerCertificate.getPublicKey().getEncoded()))
      throw new IllegalArgumentException("Distinct issuer and recipient keys required");
    if (Arrays.equals(certificate("tls").getPublicKey().getEncoded(), certificate(role).getPublicKey().getEncoded())
        || Arrays.equals(certificate("tls").getPublicKey().getEncoded(), peerCertificate.getPublicKey().getEncoded()))
      throw new IllegalArgumentException("Separate TLS and federation keys required");
    var names = certificate("tls").getSubjectAlternativeNames();
    var usages = certificate("tls").getExtendedKeyUsage();
    if (names == null || !names.contains(List.of(2, "localhost")) || !names.contains(List.of(7, "127.0.0.1"))
        || usages == null || !usages.contains("1.3.6.1.5.5.7.3.1"))
      throw new IllegalArgumentException("Loopback TLS certificate with server authentication required");
    subjectSecret = role.equals("idp")
        ? new String(readPrivate("subject-secret", 256), java.nio.charset.StandardCharsets.US_ASCII).strip() : null;
    if (subjectSecret != null && !subjectSecret.matches("[A-Za-z0-9_-]{43,128}"))
      throw new IllegalArgumentException("Persistent private subject secret required");
  }

  private byte[] readPrivate(String name, int limit) throws Exception {
    Path file = directory.resolve(name);
    if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
        || !Files.getPosixFilePermissions(file).equals(PosixFilePermissions.fromString("rw-------"))
        || !Files.getOwner(directory).equals(Files.getOwner(file)))
      throw new IllegalArgumentException("Private regular credential file required");
    try (var input = Files.newInputStream(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
      byte[] bytes = input.readNBytes(limit + 1);
      if (bytes.length == 0 || bytes.length > limit) throw new IllegalArgumentException("Credential file size");
      return bytes;
    }
  }

  private static void validateCertificate(X509Certificate certificate) throws Exception {
    certificate.checkValidity();
    if (certificate.getSubjectX500Principal().getName().contains("SYNTHETIC-LAB-")
        || !(certificate.getPublicKey() instanceof RSAPublicKey rsa) || rsa.getModulus().bitLength() < 3072)
      throw new IllegalArgumentException("Runtime requires non-lab RSA certificates of at least 3072 bits");
  }

  private void requirePrivate(String alias) {
    if (!stores.containsKey(alias)) throw new IllegalArgumentException("Private key unavailable to service role");
  }
  public Path directory() { return directory; }
  public Path storePath(String alias) { requirePrivate(alias); return directory.resolve(alias + ".p12"); }
  public String password(String alias) { requirePrivate(alias); return passwords.get(alias); }
  public X509Certificate certificate(String alias) {
    var certificate = certificates.get(alias);
    if (certificate == null) throw new IllegalArgumentException("Unpinned certificate");
    return certificate;
  }
  public PkiCredential credential(String alias) throws Exception {
    requirePrivate(alias);
    return new KeyStoreCredential(stores.get(alias), alias, password(alias).toCharArray());
  }
  public String subjectSecret() {
    if (!role.equals("idp")) throw new IllegalArgumentException("Issuer role required");
    return subjectSecret;
  }
  public SSLContext sslContext() throws Exception {
    var manager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    manager.init(stores.get("tls"), password("tls").toCharArray());
    var trust = KeyStore.getInstance("PKCS12"); trust.load(null, null);
    trust.setCertificateEntry("tls", certificate("tls"));
    var trustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); trustManager.init(trust);
    var context = SSLContext.getInstance("TLS"); context.init(manager.getKeyManagers(), trustManager.getTrustManagers(), null);
    return context;
  }
}
