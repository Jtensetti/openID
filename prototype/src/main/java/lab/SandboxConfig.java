package lab;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;

/**
 * Explicit, synthetic-only Sweden Connect Sandbox configuration.
 *
 * No production/QA metadata, real identity or dynamic trust anchors are accepted.
 * The two public trust anchors are pinned to Sweden Connect's October 2026 Sandbox publications.
 */
public record SandboxConfig(String idp, String organization, String contact) {
  public static final String SP_METADATA = "https://md.sandbox.swedenconnect.se/metadata/mdx/role/sp.xml";
  public static final String INTERMEDIATE = "https://fed.sandbox.swedenconnect.se/im-reg-sc-op";
  public static final String TRUST_ANCHOR = "https://fed.sandbox.swedenconnect.se/trustanchor";
  public static final String TEST_CLIENT = "https://testclient.sandbox.swedenconnect.se";
  public static final String SAML_CERT_FILE = "sandbox-saml-metadata-signing.crt";
  public static final String OIDC_ANCHOR_FILE = "sandbox-oidc-trust-anchor.jwks.json";
  private static final String SAML_CERT_SHA256 = "86b5306355636b184de4b0e29c7c417429ece79164fb4680acf0b5f28b1cc0ea";
  private static final String OIDC_X = "AMrYWpNjfV_olprpgUyKVcn8ZxZOUyxTMgXukqyo-mV2mNykmaTduZ7J3hLRmbCQApqPHAu4gh75CWPHSYHuOMkF";
  private static final String OIDC_Y = "AQpPeyt5YmLMtfwWGEOGGSKhqPWQBIW-BbIW9KjJ44Ks144xdARSH8EX3WedHqPpJfR_6BfC4cNRd3jWG2bGPXaf";
  private static final String OIDC_KID = "x8vWKOCUciPdbte5wyXkY4404TSwi8cok3Zrfj-f7PQ";
  private static final ObjectMapper JSON = new ObjectMapper();

  public SandboxConfig {
    URI uri = URI.create(idp);
    if (!"https".equals(uri.getScheme()) || !"idp-sandbox.tensetti.io".equals(uri.getHost()) ||
        uri.getPort() != -1 || uri.getRawUserInfo() != null ||
        !"".equals(uri.getRawPath()) || uri.getRawQuery() != null || uri.getRawFragment() != null ||
        !idp.equals("https://idp-sandbox.tensetti.io"))
      throw new IllegalArgumentException("Use the dedicated Tjipp HTTPS sandbox origin only");
    if (organization == null || organization.isBlank() || organization.length() > 100 ||
        organization.codePoints().anyMatch(c -> Character.isISOControl(c)))
      throw new IllegalArgumentException("Non-empty organization name required");
    if (contact == null || contact.length() > 254 ||
        !contact.matches("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"))
      throw new IllegalArgumentException("Technical contact email required");
  }

  public static SandboxConfig read(Path file) throws Exception {
    JsonNode root = JSON.readTree(Files.readString(file));
    if (!root.isObject()) throw new IllegalArgumentException("Sandbox configuration must be an object");
    Set<String> names = new HashSet<>();
    root.fieldNames().forEachRemaining(names::add);
    if (!names.equals(Set.of("idp", "organization", "contact")))
      throw new IllegalArgumentException("Expected idp, organization and contact only");
    for (String field : names) if (!root.get(field).isTextual())
      throw new IllegalArgumentException("Sandbox configuration values must be strings");
    return new SandboxConfig(root.get("idp").textValue(), root.get("organization").textValue(),
        root.get("contact").textValue());
  }

  /** Copy public, published trust material from the JAR, never fetch a new trust anchor at startup. */
  public static void initializeTrust(Path directory) throws Exception {
    for (var entry : Map.of(
        SAML_CERT_FILE, "/sandbox/saml-metadata-signing.crt",
        OIDC_ANCHOR_FILE, "/sandbox/oidc-trust-anchor.jwks.json").entrySet()) {
      Path target = directory.resolve(entry.getKey());
      try (InputStream input = SandboxConfig.class.getResourceAsStream(entry.getValue())) {
        if (input == null) throw new IllegalStateException("Missing bundled Sandbox trust material");
        Files.copy(input, target);
      }
    }
    validateTrust(directory);
  }

  /** Verify exact pinned public trust keys. An unrelated or substituted certificate must fail closed. */
  public static void validateTrust(Path directory) throws Exception {
    Path certificatePath = directory.resolve(SAML_CERT_FILE);
    var factory = CertificateFactory.getInstance("X.509");
    var cert = Files.readAllBytes(certificatePath);
    var x509 = factory.generateCertificate(new java.io.ByteArrayInputStream(cert));
    String fingerprint = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(x509.getEncoded()));
    if (!SAML_CERT_SHA256.equals(fingerprint))
      throw new IllegalStateException("Unexpected Sweden Connect Sandbox SAML metadata signing certificate");

    JsonNode root = JSON.readTree(Files.readString(directory.resolve(OIDC_ANCHOR_FILE)));
    JsonNode keys = root.path("keys");
    if (!keys.isArray() || keys.size() != 1) throw new IllegalStateException("Unexpected OIDC trust anchor JWK set");
    JsonNode jwk = keys.get(0);
    if (!"EC".equals(jwk.path("kty").asText()) || !"P-521".equals(jwk.path("crv").asText()) ||
        !"ES512".equals(jwk.path("alg").asText()) || !"sig".equals(jwk.path("use").asText()) ||
        !OIDC_X.equals(jwk.path("x").asText()) || !OIDC_Y.equals(jwk.path("y").asText()) ||
        !OIDC_KID.equals(jwk.path("kid").asText()))
      throw new IllegalStateException("Unexpected Sweden Connect Sandbox OIDC trust anchor key");
  }

  public void apply(Map<String, Object> p, TestKeys keys) throws Exception {
    validateTrust(keys.directory());
    if (!Files.isRegularFile(keys.directory().resolve("federation.p12")))
      throw new IllegalStateException("Missing separate Sandbox federation signing key; run sandbox-init");
    p.put("authn-server.saml.metadata-providers[0].location", SP_METADATA);
    p.put("authn-server.saml.metadata-providers[0].validation-certificate",
        keys.directory().resolve(SAML_CERT_FILE).toUri().toString());
    p.put("authn-server.saml.metadata-providers[0].backup-location",
        keys.directory().resolve("sandbox-sp-metadata-backup.xml").toUri().toString());
    p.put("authn-server.saml.metadata-providers[0].skip-hostname-verification", false);

    p.put("authn-server.oidc.issuer", idp);
    p.put("authn-server.oidc.keys.signing[0].credential.bundle", "lab-idp");
    p.put("authn-server.oidc.keys.signing[0].default-key", true);
    p.put("authn-server.oidc.authorization-request.require-pkce", true);
    p.put("authn-server.oidc.client-authentication-methods", "private_key_jwt");

    p.put("authn-server.oidc.federation.enabled", true);
    p.put("authn-server.oidc.federation.authority-hints[0]", INTERMEDIATE);
    p.put("authn-server.oidc.federation.keys[0].credential.bundle", "sandbox-federation");
    p.put("authn-server.oidc.federation.trust-anchor.entity-id", TRUST_ANCHOR);
    p.put("authn-server.oidc.federation.trust-anchor.jwks",
        keys.directory().resolve(OIDC_ANCHOR_FILE).toUri().toString());
    p.put("authn-server.oidc.federation.clients.enabled", true);

    p.put("credential.bundles.jks.sandbox-federation.key.alias", "federation");
    p.put("credential.bundles.jks.sandbox-federation.key.key-password", TestKeys.PASSWORD);
    p.put("credential.bundles.jks.sandbox-federation.store.location",
        keys.directory().resolve("federation.p12").toUri().toString());
    p.put("credential.bundles.jks.sandbox-federation.store.password", TestKeys.PASSWORD);
    p.put("credential.bundles.jks.sandbox-federation.store.type", "PKCS12");

    p.put("authn-server.entity-information.ui-info.display-names.sv", "Tjipp Sandbox – ENDAST TEST");
    p.put("authn-server.entity-information.ui-info.display-names.en", "Tjipp Sandbox – SYNTHETIC ONLY");
    p.put("authn-server.entity-information.organization.names.sv", organization);
    p.put("authn-server.entity-information.organization.names.en", organization);
    p.put("authn-server.entity-information.organization.urls.sv", "https://tensetti.se");
    p.put("authn-server.entity-information.contact-persons.technical.email-addresses[0]", contact);
    p.put("authn-server.oidc.entity-information.logo-uri", idp + "/logo.svg");
    p.put("authn-server.oidc.entity-information.contacts[0]", contact);
    p.put("authn-server.oidc.ui-locales[0]", "sv");
    p.put("authn-server.oidc.ui-locales[1]", "en");
    p.put("authn-server.saml.metadata.ui-info.display-names.sv", "Tjipp Sandbox – SIMULERAD");
  }
}
