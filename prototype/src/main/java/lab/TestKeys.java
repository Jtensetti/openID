package lab;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;

/** Fresh disposable test keys; JDK keytool supplies the cryptography. No production import path. */
public final class TestKeys {
  public static final String PASSWORD = "test-only-changeit";
  private final Path directory;

  public TestKeys(Path directory) throws Exception {
    this.directory = directory.toAbsolutePath().normalize();
    if (!Files.readString(this.directory.resolve("SYNTHETIC-LAB-ONLY")).equals("Disposable test keys\n")) {
      throw new IllegalArgumentException("Initialize a disposable lab key directory first");
    }
    for (String alias : new String[]{"tls", "idp", "sp"}) {
      var cert = certificate(alias);
      if (!cert.getSubjectX500Principal().getName().contains("CN=SYNTHETIC-LAB-" + alias)) {
        throw new IllegalArgumentException("Only generated lab keys are accepted");
      }
      cert.checkValidity();
    }
  }

  public static void initialize(Path directory) throws Exception {
    if (Files.exists(directory)) throw new IllegalArgumentException("Key directory already exists; refusing overwrite");
    Files.createDirectories(directory);
    try { Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------")); }
    catch (UnsupportedOperationException ignored) { /* Windows uses the user's directory ACL. */ }
    String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
    for (String alias : new String[]{"tls", "idp", "sp"}) {
      var args = new java.util.ArrayList<>(java.util.List.of(keytool, "-genkeypair", "-alias", alias,
          "-keyalg", "RSA", "-keysize", "3072", "-sigalg", "SHA256withRSA", "-validity", "30",
          "-dname", "CN=SYNTHETIC-LAB-" + alias, "-storetype", "PKCS12", "-keystore",
          directory.resolve(alias + ".p12").toString(), "-storepass", PASSWORD, "-keypass", PASSWORD));
      if (alias.equals("tls")) args.addAll(java.util.List.of("-ext", "SAN=IP:127.0.0.1,DNS:localhost", "-ext", "EKU=serverAuth"));
      Process process = new ProcessBuilder(args).redirectErrorStream(true).start();
      process.getInputStream().transferTo(java.io.OutputStream.nullOutputStream());
      if (process.waitFor() != 0) throw new IllegalStateException("keytool failed: " + alias);
    }
    Files.writeString(directory.resolve("SYNTHETIC-LAB-ONLY"), "Disposable test keys\n");
    var keys = new TestKeys(directory);
    Files.writeString(directory.resolve("tls.crt"), "-----BEGIN CERTIFICATE-----\n" +
        java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(keys.certificate("tls").getEncoded()) +
        "\n-----END CERTIFICATE-----\n");
  }

  public KeyStore store(String alias) throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");
    try (var in = Files.newInputStream(directory.resolve(alias + ".p12"))) { store.load(in, PASSWORD.toCharArray()); }
    return store;
  }
  public X509Certificate certificate(String alias) throws Exception {
    return (X509Certificate) store(alias).getCertificate(alias);
  }
  public PkiCredential credential(String alias) throws Exception {
    return new KeyStoreCredential(store(alias), alias, PASSWORD.toCharArray());
  }
  public SSLContext sslContext() throws Exception {
    var km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    km.init(store("tls"), PASSWORD.toCharArray());
    KeyStore trust = KeyStore.getInstance("PKCS12");
    trust.load(null, null); trust.setCertificateEntry("tls", certificate("tls"));
    var tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); tm.init(trust);
    var context = SSLContext.getInstance("TLS"); context.init(km.getKeyManagers(), tm.getTrustManagers(), null);
    return context;
  }
  public Path directory() { return directory; }
}
