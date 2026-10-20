package lab;

import java.util.*;
import lab.phone.PhoneIdentity;
import org.junit.jupiter.api.Test;
import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;
import static org.junit.jupiter.api.Assertions.*;

class PhoneIdentityTest {
  @org.junit.jupiter.api.BeforeAll static void initialize() throws Exception {
    se.swedenconnect.opensaml.OpenSAMLInitializer.getInstance().initialize();
  }
  private PhoneIdentity identity() { return new PhoneIdentity("a".repeat(64),"b".repeat(64),"c".repeat(64),"ALICE SYNTHETIC","900101","/9j/2Q=="); }
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
}
