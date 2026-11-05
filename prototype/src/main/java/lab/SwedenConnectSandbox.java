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
    if (Files.exists(encryption) || Files.exists(directory.resolve(CERTIFICATE)))
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
    validate(new TestKeys(directory));
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
    p.put("authn-server.saml.metadata-providers[2].location", "https://md.sandbox.swedenconnect.se/metadata/mdx/role/sp.xml");
    p.put("authn-server.saml.metadata-providers[2].validation-certificate", keys.directory().resolve(CERTIFICATE).toUri().toString());
    p.put("authn-server.saml.metadata-providers[2].backup-location", keys.directory().resolve("sandbox-sp-metadata-backup.xml").toUri().toString());
    p.put("authn-server.saml.metadata-providers[2].skip-hostname-verification", false);
    p.put("authn-server.saml.credentials.encrypt.bundle", "sandbox-encryption");
    p.put("credential.bundles.jks.sandbox-encryption.key.alias", "encryption");
    p.put("credential.bundles.jks.sandbox-encryption.key.key-password", TestKeys.PASSWORD);
    p.put("credential.bundles.jks.sandbox-encryption.store.location", keys.directory().resolve("encryption.p12").toUri().toString());
    p.put("credential.bundles.jks.sandbox-encryption.store.password", TestKeys.PASSWORD);
    p.put("credential.bundles.jks.sandbox-encryption.store.type", "PKCS12");
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
