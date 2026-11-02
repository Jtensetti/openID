package lab;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class SandboxConfigTest {
  @TempDir Path temporary;

  @Test void syntheticSandboxHasPinnedTrustAndSeparateFederationKey() throws Exception {
    Path keysPath = temporary.resolve("keys");
    SandboxKeys.initialize(keysPath);
    SandboxKeys.validate(keysPath);
    var config = new SandboxConfig("https://idp-sandbox.tensetti.io", "Tjipp sandbox test", "operator@example.org");
    var properties = new HashMap<String, Object>();
    config.apply(properties, new TestKeys(keysPath));

    assertEquals(SandboxConfig.SP_METADATA, properties.get("authn-server.saml.metadata-providers[0].location"));
    assertNotNull(properties.get("authn-server.saml.metadata-providers[0].validation-certificate"));
    assertEquals(SandboxConfig.INTERMEDIATE, properties.get("authn-server.oidc.federation.authority-hints[0]"));
    assertEquals(SandboxConfig.TRUST_ANCHOR, properties.get("authn-server.oidc.federation.trust-anchor.entity-id"));
    assertEquals(true, properties.get("authn-server.oidc.federation.enabled"));
    assertEquals("sandbox-federation", properties.get("authn-server.oidc.federation.keys[0].credential.bundle"));
    assertFalse(properties.toString().contains("loa3")); // Must never fabricate assurance or trust marks.

    var jwks = keysPath.resolve(SandboxConfig.OIDC_ANCHOR_FILE);
    String original = Files.readString(jwks);
    Files.writeString(jwks, original.replace("x8vWKOCUciPdbte5wyXkY4404TSwi8cok3Zrfj-f7PQ", "attacker-kid"));
    assertThrows(IllegalStateException.class, () -> SandboxConfig.validateTrust(keysPath));
    Files.writeString(jwks, original);
    assertDoesNotThrow(() -> SandboxConfig.validateTrust(keysPath));

    var certificate = keysPath.resolve(SandboxConfig.SAML_CERT_FILE);
    Files.writeString(certificate, "not a certificate");
    assertThrows(Exception.class, () -> SandboxConfig.validateTrust(keysPath));
  }

  @Test void sandboxConfigRejectsProductionOriginsAndUnexpectedFields() throws Exception {
    for (String bad : new String[]{
        "https://idp.openid.tensetti.io", "https://idp-sandbox.tensetti.io/",
        "http://idp-sandbox.tensetti.io", "https://idp-sandbox.tensetti.io:443",
        "https://idp-sandbox.tensetti.io?skip=1", "https://evil.example.org"
    }) assertThrows(IllegalArgumentException.class,
        () -> new SandboxConfig(bad, "Tjipp", "admin@example.org"), bad);
    Path file = temporary.resolve("settings.json");
    Files.writeString(file, """
      {"idp":"https://idp-sandbox.tensetti.io","organization":"Tjipp","contact":"admin@example.org","production":true}
      """);
    assertThrows(IllegalArgumentException.class, () -> SandboxConfig.read(file));
  }
}
