package lab;

import java.util.*;
import lab.phone.PhoneIdentity;
import lab.phone.PhoneAttributes;
import lab.phone.SandboxIdentity;
import org.junit.jupiter.api.Test;
import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;
import static org.junit.jupiter.api.Assertions.*;

class PhoneIdentityTest {
  @org.junit.jupiter.api.BeforeAll static void initialize() throws Exception {
    se.swedenconnect.opensaml.OpenSAMLInitializer.getInstance().initialize();
  }
  private PhoneIdentity identity() { return new PhoneIdentity("a".repeat(64),"b".repeat(64),"c".repeat(64),"ALICE SYNTHETIC","900101","/9j/2Q=="); }
  private SandboxIdentity passport() { return new SandboxIdentity("ALICE", "SYNTHETIC", "195704133106"); }
  @Test void sandboxDisclosesPassportFieldsWithoutPortraitOrInternalReferences() {
    var attributes = PhoneAttributes.sandboxValues(identity(), passport());
    assertEquals(Set.of(PhoneIdentity.SUBJECT,
        se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers.DISPLAY_NAME,
        se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers.GIVEN_NAME,
        se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers.SURNAME,
        se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER),
        attributes.stream().map(a -> a.getIdentifier()).collect(java.util.stream.Collectors.toSet()));
  }
  @Test void externalReleaseIncludesTheSadSubjectEvenWhenSpMetadataOnlyRequestsPersonalNumber() {
    var user = new se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser(
        PhoneAttributes.sandboxValues(identity(), passport()), PhoneIdentity.SUBJECT, PhoneIdentity.CONTEXT,
        java.time.Instant.now(), "127.0.0.1");
    var authentication = new se.swedenconnect.spring.authnserver.authentication.UserAuthentication(user);
    var requested = List.of(se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute.of(
        se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, true));
    authentication.registerUse(se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol.SAML,
        "https://testclient.sandbox.swedenconnect.se/test-signservice1", "_request", List.of());
    var released = PhoneAttributes.sandboxRelease(authentication);
    var mapped = PhoneAttributes.mapping().toSaml(released, requested);
    assertEquals(Set.of(PhoneIdentity.SUBJECT, Metadata.DISPLAY_NAME,
        "urn:oid:2.5.4.4", "urn:oid:2.5.4.42", "urn:oid:1.2.752.29.4.13"),
        mapped.stream().map(a -> a.getName()).collect(java.util.stream.Collectors.toSet()));
    assertEquals(identity().subject(), se.swedenconnect.opensaml.saml2.attribute.AttributeUtils.getAttributeStringValue(
        mapped.stream().filter(a -> a.getName().equals(PhoneIdentity.SUBJECT)).findFirst().orElseThrow()));
    authentication.registerUse(se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol.SAML,
        "https://testclient.sandbox.swedenconnect.se/testsp2", "_second", List.of());
    assertFalse(PhoneAttributes.sandboxRelease(authentication).stream().anyMatch(a ->
        a.getIdentifier().equals(se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER)));
    authentication.registerUse(se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol.SAML,
        "https://attacker.invalid", "_other", List.of());
    assertTrue(PhoneAttributes.sandboxRelease(authentication).isEmpty());
  }
  @Test void sandboxDoesNotInventMissingNumbersOrExposeThemInDiagnostics() {
    var attributes = PhoneAttributes.sandboxValues(identity(), new SandboxIdentity("ALICE", "SYNTHETIC", null));
    assertFalse(attributes.stream().anyMatch(a -> a.getIdentifier().equals(
        se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER)));
    assertThrows(IllegalArgumentException.class, () -> new SandboxIdentity("ALICE", "SYNTHETIC", "5704133106"));
    assertThrows(IllegalArgumentException.class, () -> new SandboxIdentity("<script>", "SYNTHETIC", null));
    assertFalse(passport().toString().contains(passport().personalNumber()));
  }
  @Test void requiresExactSingleValuedClaims() {
    var expected = identity();
    var attributes = new ArrayList<org.opensaml.saml.saml2.core.Attribute>();
    expected.attributes().forEach((name,value) -> attributes.add(AttributeBuilder.builder(name).value(value).build()));
    assertEquals(expected, PhoneIdentity.fromAttributes(attributes));
    attributes.add(attributes.getFirst());
    assertThrows(IllegalArgumentException.class, () -> PhoneIdentity.fromAttributes(attributes));
    attributes.removeLast(); attributes.removeLast();
    assertThrows(IllegalArgumentException.class, () -> PhoneIdentity.fromAttributes(attributes));
  }
  @Test void refusesMarkupAndFullBirthDateClaims() {
    assertThrows(IllegalArgumentException.class, () -> new PhoneIdentity("a".repeat(64),"b".repeat(64),"c".repeat(64),"<script>","900101","/9j/2Q=="));
    assertThrows(IllegalArgumentException.class, () -> new PhoneIdentity("a".repeat(64),"b".repeat(64),"c".repeat(64),"ALICE","19900101","/9j/2Q=="));
    assertThrows(IllegalArgumentException.class, () -> new PhoneIdentity("a".repeat(64),"b".repeat(64),"c".repeat(64),"ALICE","900230","/9j/2Q=="));
  }
  @Test void identityToStringDoesNotExposePersonData() {
    String message = identity().toString();
    assertFalse(message.contains("ALICE")); assertFalse(message.contains("900101"));
  }
  @Test void providerAndRequestedAttributesSurviveSwedenConnectMapping() {
    var mapping = PhoneAttributes.mapping();
    var requested = mapping.toGeneric(PhoneIdentity.ATTRIBUTES.stream()
        .map(name -> se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute.of(name, null, true)).toList());
    assertEquals(PhoneIdentity.ATTRIBUTES.size(), requested.size());
    var provider = new ArrayList<se.swedenconnect.spring.authnserver.attributes.GenericAttribute<? extends java.io.Serializable>>();
    for (var value : PhoneAttributes.values(identity())) provider.add(se.swedenconnect.spring.authnserver.attributes.GenericAttribute.of(value.getIdentifier(), value.getStringValues()));
    assertEquals(identity(), PhoneIdentity.fromAttributes(mapping.toSaml(provider, requested)));
  }
}
