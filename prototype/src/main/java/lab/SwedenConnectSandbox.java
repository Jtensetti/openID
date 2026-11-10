package lab;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** Optional SAML Sandbox connection for the existing app authenticator. */
public final class SwedenConnectSandbox {
  private SwedenConnectSandbox() {}
  private static final String CERTIFICATE = "sandbox-saml-metadata-signing.crt";
  private static final String FINGERPRINT = "86b5306355636b184de4b0e29c7c417429ece79164fb4680acf0b5f28b1cc0ea";

  public static void initialize(Path directory) throws Exception {
    new TestKeys(directory);
    Path encryption = directory.resolve("encryption.p12");
    if (Files.exists(encryption) || Files.exists(directory.resolve(CERTIFICATE)) || Files.exists(directory.resolve("idp-encryption.crt")))
      throw new IllegalArgumentException("Sandbox keys already exist; refusing overwrite");
    String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
    Process process = new ProcessBuilder(List.of(keytool, "-genkeypair", "-alias", "encryption",
        "-keyalg", "RSA", "-keysize", "3072", "-sigalg", "SHA256withRSA", "-validity", "30",
        "-dname", "CN=Tjipp-Sandbox-Encryption", "-storetype", "PKCS12", "-keystore", encryption.toString(),
        "-storepass", TestKeys.PASSWORD, "-keypass", TestKeys.PASSWORD)).redirectErrorStream(true).start();
    process.getInputStream().transferTo(java.io.OutputStream.nullOutputStream());
    if (process.waitFor() != 0) throw new IllegalStateException("Sandbox encryption key generation failed");
    Files.setPosixFilePermissions(encryption, PosixFilePermissions.fromString("rw-------"));
    try (var source = SwedenConnectSandbox.class.getResourceAsStream("/sandbox/saml-metadata-signing.crt")) {
      Files.copy(java.util.Objects.requireNonNull(source), directory.resolve(CERTIFICATE));
    }
    var keys = new TestKeys(directory);
    validate(keys);
    Files.writeString(directory.resolve("idp-encryption.crt"), "-----BEGIN CERTIFICATE-----\n" +
        java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(keys.certificate("encryption").getEncoded()) +
        "\n-----END CERTIFICATE-----\n");
  }

  static void validate(TestKeys keys) throws Exception {
    var encryption = keys.certificate("encryption");
    if (encryption == null || !"CN=Tjipp-Sandbox-Encryption".equals(encryption.getSubjectX500Principal().getName()) ||
        !keys.store("encryption").isKeyEntry("encryption") ||
        Arrays.equals(encryption.getPublicKey().getEncoded(), keys.certificate("idp").getPublicKey().getEncoded()))
      throw new IllegalStateException("Separate Sandbox encryption key required");
    encryption.checkValidity();
    try (var input = Files.newInputStream(keys.directory().resolve(CERTIFICATE))) {
      var certificate = CertificateFactory.getInstance("X.509").generateCertificate(input);
      if (!FINGERPRINT.equals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()))))
        throw new IllegalStateException("Unexpected Sweden Connect Sandbox trust anchor");
    }
  }

  static void apply(Map<String, Object> p, TestKeys keys, String origin) throws Exception {
    validate(keys);
    apply(p, keys, origin, keys.directory(), keys.directory().resolve(CERTIFICATE).toUri().toString());
  }

  static void apply(Map<String, Object> p, RuntimeKeys keys, String origin, Path state) throws Exception {
    try (var input = SwedenConnectSandbox.class.getResourceAsStream("/sandbox/saml-metadata-signing.crt")) {
      var certificate = CertificateFactory.getInstance("X.509").generateCertificate(java.util.Objects.requireNonNull(input));
      if (!FINGERPRINT.equals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()))))
        throw new IllegalStateException("Unexpected packaged Sandbox trust anchor");
    }
    apply(p, keys, origin, state, "classpath:/sandbox/saml-metadata-signing.crt");
  }

  static void encryption(Map<String, Object> p, ServiceKeys keys) throws Exception {
    var certificate = keys.encryptionCertificate();
    if (certificate == null || Arrays.equals(certificate.getPublicKey().getEncoded(), keys.certificate("idp").getPublicKey().getEncoded()))
      throw new IllegalStateException("Separate issuer encryption key required");
    p.put("authn-server.saml.credentials.encrypt.bundle", "issuer-encryption");
    p.put("credential.bundles.jks.issuer-encryption.key.alias", "encryption");
    p.put("credential.bundles.jks.issuer-encryption.key.key-password", keys.password("encryption"));
    p.put("credential.bundles.jks.issuer-encryption.store.location", keys.storePath("encryption").toUri().toString());
    p.put("credential.bundles.jks.issuer-encryption.store.password", keys.password("encryption"));
    p.put("credential.bundles.jks.issuer-encryption.store.type", "PKCS12");
  }

  private static void apply(Map<String, Object> p, ServiceKeys keys, String origin, Path state, String anchor) throws Exception {
    encryption(p, keys);
    p.put("authn-server.saml.metadata-providers[2].location", "https://md.sandbox.swedenconnect.se/metadata/mdx/role/sp.xml");
    p.put("authn-server.saml.metadata-providers[2].validation-certificate", anchor);
    p.put("authn-server.saml.metadata-providers[2].backup-location", state.resolve("sandbox-sp-metadata-backup.xml").toUri().toString());
    p.put("authn-server.saml.metadata-providers[2].skip-hostname-verification", false);
    p.put("server.servlet.session.cookie.same-site", "lax");
    p.remove("authn-server.saml.metadata.ui-info.display-names.sv");
    for (String language : List.of("sv", "en")) {
      p.put("authn-server.entity-information.ui-info.display-names." + language, "Tjipp");
      p.put("authn-server.entity-information.organization.names." + language, "Karl Jonatan Tensetti");
      p.put("authn-server.entity-information.organization.display-names." + language, "Karl Jonatan Tensetti");
      p.put("authn-server.entity-information.organization.urls." + language, "https://tensetti.se");
    }
    p.put("authn-server.entity-information.ui-info.descriptions.sv", "Legitimering och underskrift med Tjipp i Sweden Connects testmiljö.");
    p.put("authn-server.entity-information.ui-info.descriptions.en", "Authentication and signing with Tjipp in the Sweden Connect test environment.");
    p.put("authn-server.entity-information.ui-info.logotypes[0].url", origin + "/logo.png");
    p.put("authn-server.entity-information.ui-info.logotypes[0].width", 256);
    p.put("authn-server.entity-information.ui-info.logotypes[0].height", 256);
    p.put("authn-server.entity-information.contact-persons.technical.email-addresses[0]", "Jonatan@tensetti.se");
    p.put("authn-server.entity-information.contact-persons.support.email-addresses[0]", "Jonatan@tensetti.se");
  }
}
