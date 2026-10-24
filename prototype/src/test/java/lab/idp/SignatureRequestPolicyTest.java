package lab.idp;

import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import lab.SyntheticRegistry;
import lab.phone.PhoneBridge;
import org.junit.jupiter.api.Test;
import se.swedenconnect.spring.authnserver.authentication.*;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.message.*;
import se.swedenconnect.spring.authnserver.oidc.authentication.OidcAuthenticationRequirements;
import se.swedenconnect.spring.authnserver.saml.authentication.*;
import static org.junit.jupiter.api.Assertions.*;

class SignatureRequestPolicyTest {
  private static UserAuthenticationInputToken token(AuthenticationRequirements requirements) {
    return new UserAuthenticationInputToken(requirements, new Requester(
        requirements instanceof OidcAuthenticationRequirements ? AuthenticationProtocol.OIDC : AuthenticationProtocol.SAML, "https://localhost:8444/sign"));
  }
  private static SamlAuthenticationRequirements saml(GenericSignMessage message, boolean sad) {
    var requirements = new SamlAuthenticationRequirements(); requirements.setSignMessage(message);
    if (sad) requirements.setSadRequestExtension(new SadRequestExtension("id", "service", "sign-request", 1));
    return requirements;
  }

  @Test void simulatedLabRefusesEveryFederatedSignature() throws Exception {
    var registry = SyntheticRegistry.fixtures();
    var lab = new LabProvider(registry, new WebAuthnService(registry, "https://localhost:8443", Clock.systemUTC(), false));
    var oidc = new OidcAuthenticationRequirements(); oidc.setSignMessage(GenericSignMessage.ofText("sv", "SYNTHETIC signing"));
    for (AuthenticationRequirements requirements : List.of(saml(GenericSignMessage.ofText("sv", "SYNTHETIC signing"), false), oidc, saml(null, true)))
      assertThrows(AuthenticationErrorException.class, () -> lab.authenticateUser(token(requirements)));
  }

  @Test void phoneShowsBoundedPlainTextAndOtherwiseFails() throws Exception {
    assertNull(SignatureRequestPolicy.signMessage(new SamlAuthenticationRequirements()));
    assertEquals("Jag skriver under\nrad två", SignatureRequestPolicy.signMessage(saml(GenericSignMessage.ofText("sv", "Jag skriver under\nrad två"), true)));
    // Swedish is preferred over other languages.
    var languages = new GenericSignMessage(List.of(LocalizedMessage.ofText("en", "I sign"), LocalizedMessage.ofText("sv", "Jag skriver under")),
        MessageMimeType.TEXT_PLAIN, true, null);
    assertEquals("Jag skriver under", SignatureRequestPolicy.signMessage(saml(languages, false)));
    assertEquals("sv", SignatureRequestPolicy.language(saml(languages, false)));
    var cannotShow = List.of(
        new GenericSignMessage(List.of(LocalizedMessage.ofText(null, "<p>Jag skriver under</p>")), MessageMimeType.TEXT_HTML, true, null),
        GenericSignMessage.ofText("sv", "x".repeat(PhoneBridge.SIGN_MESSAGE_LIMIT + 1)),
        GenericSignMessage.ofText("sv", "Jag skriver under ‮dlrow"),
        GenericSignMessage.ofText("sv", "Kontroll\u0007tecken"));
    for (var message : cannotShow) assertThrows(AuthenticationErrorException.class, () -> SignatureRequestPolicy.signMessage(saml(message, false)));
    // A SAD asserts a displayed text: never without one.
    assertThrows(AuthenticationErrorException.class, () -> SignatureRequestPolicy.signMessage(saml(null, true)));
    // An optional message that cannot be shown is not shown, and the request stays a login without a digest.
    var optional = new GenericSignMessage(List.of(LocalizedMessage.ofText(null, "<p>x</p>")), MessageMimeType.TEXT_HTML, false, null);
    assertNull(SignatureRequestPolicy.signMessage(saml(optional, false)));
    assertThrows(AuthenticationErrorException.class, () -> SignatureRequestPolicy.signMessage(saml(optional, true)));
  }

  @Test void serviceDecidesTheLevelAndTheLowerAcceptedLevelIsUsed() throws Exception {
    var requirements = new SamlAuthenticationRequirements();
    assertNull(SignatureRequestPolicy.level(requirements)); // nothing requested: Face ID level
    requirements.setAuthnContextRequirements(List.of(lab.phone.PhoneIdentity.PIN_CONTEXT));
    assertEquals("pin", SignatureRequestPolicy.level(requirements));
    assertEquals(lab.phone.PhoneIdentity.PIN_CONTEXT, SignatureRequestPolicy.context("pin"));
    requirements.setAuthnContextRequirements(List.of(lab.phone.PhoneIdentity.PIN_CONTEXT, lab.phone.PhoneIdentity.CONTEXT));
    assertNull(SignatureRequestPolicy.level(requirements)); // both accepted: no unnecessary code
    requirements.setAuthnContextRequirements(List.of("http://id.elegnamnden.se/loa/1.0/loa3"));
    assertThrows(AuthenticationErrorException.class, () -> SignatureRequestPolicy.level(requirements));
    assertTrue(new PhoneProvider(new PhoneBridge(Path.of("/nonexistent-test-only.sock"), "https://localhost:8444/sp"))
        .getSupportedAuthnContextUris().containsAll(List.of(lab.phone.PhoneIdentity.CONTEXT, lab.phone.PhoneIdentity.PIN_CONTEXT)));
  }

  @Test void phoneProviderFailsBeforeDisplayWhenTextCannotBeShown() {
    var phone = new PhoneProvider(new PhoneBridge(Path.of("/nonexistent-test-only.sock"), "https://localhost:8444/sp"));
    var html = new GenericSignMessage(List.of(LocalizedMessage.ofText(null, "<b>x</b>")), MessageMimeType.TEXT_HTML, true, null);
    assertThrows(AuthenticationErrorException.class, () -> phone.authenticateUser(token(saml(html, true))));
    assertThrows(AuthenticationErrorException.class, () -> phone.authenticateUser(token(saml(null, true))));
    assertTrue(phone.getEntityCategories().contains("http://id.elegnamnden.se/sprop/1.0/scal2"));
  }
}
