package lab;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Set;
import lab.phone.PhoneBridge;
import lab.phone.SandboxRelyingParties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import se.swedenconnect.spring.authnserver.autoconfigure.EntityInformationProperties;
import static org.junit.jupiter.api.Assertions.*;

class SwedenConnectSandboxTest {
  @TempDir Path temporary;

  @Test void metadataHasNamesLogoSupportAndDistinctEncryptionWithoutReplacingSigningKey() throws Exception {
    Path directory = temporary.resolve("keys");
    TestKeys.initialize(directory);
    byte[] signing = Files.readAllBytes(directory.resolve("idp.p12"));
    SwedenConnectSandbox.initialize(directory);
    var keys = new TestKeys(directory);
    var properties = new HashMap<String, Object>();
    properties.put("authn-server.saml.metadata.ui-info.display-names.sv", "openID");
    SwedenConnectSandbox.apply(properties, keys, "https://idp.openid.tensetti.io");
    assertArrayEquals(signing, Files.readAllBytes(directory.resolve("idp.p12")));
    assertNotEquals(keys.certificate("idp").getPublicKey(), keys.certificate("encryption").getPublicKey());
    assertTrue(Metadata.idp(keys, "https://localhost:8443").contains("<md:KeyDescriptor use=\"encryption\">"));
    assertTrue(Metadata.idp(keys, "https://localhost:8443").contains(java.util.Base64.getEncoder().encodeToString(keys.certificate("encryption").getEncoded())));
    var binder = new Binder(new MapConfigurationPropertySource(properties));
    var information = binder.bind("authn-server.entity-information", EntityInformationProperties.class).orElseThrow(AssertionError::new).toEntityInformation();
    assertEquals(Set.of("sv", "en"), information.uiInfo().displayNames().keySet());
    assertEquals(Set.of("sv", "en"), information.uiInfo().descriptions().keySet());
    assertEquals("https://idp.openid.tensetti.io/logo.png", information.uiInfo().logotypes().getFirst().url());
    assertFalse(binder.bind("authn-server.saml.metadata.ui-info", EntityInformationProperties.UiInfo.class).isBound());
    assertFalse(properties.toString().contains("loa3"));
    assertThrows(IllegalArgumentException.class, () -> SwedenConnectSandbox.initialize(directory));
    Files.write(directory.resolve("sandbox-saml-metadata-signing.crt"), Files.readAllBytes(directory.resolve("tls.crt")));
    assertThrows(IllegalStateException.class, () -> SwedenConnectSandbox.validate(keys));
    Files.delete(directory.resolve("encryption.p12"));
    assertNotNull(keys.encryptionCertificate());
    assertTrue(Metadata.idp(keys, "https://localhost:8443").contains("<md:KeyDescriptor use=\"encryption\">"));
  }

  @Test void externalRequestersRequireExplicitSandboxMode() {
    String local = "https://openid.tensetti.io/sp";
    var ordinary = new PhoneBridge(temporary.resolve("unused.sock"), local);
    var sandbox = new PhoneBridge(temporary.resolve("unused.sock"), local, true);
    assertEquals(local, sandbox.audienceForRequester("https://openid.tensetti.io/sign"));
    for (String requester : SandboxRelyingParties.NAMES.keySet()) {
      assertThrows(IllegalStateException.class, () -> ordinary.audienceForRequester(requester));
      assertEquals(requester, sandbox.audienceForRequester(requester));
    }
    assertThrows(IllegalStateException.class, () -> sandbox.audienceForRequester("https://testclient.sandbox.swedenconnect.se/attacker"));
    assertThrows(IllegalStateException.class, () -> sandbox.startFor("https://attacker.invalid", "binding", null, null));
  }
}
