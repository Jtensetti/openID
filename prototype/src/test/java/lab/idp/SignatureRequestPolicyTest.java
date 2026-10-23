package lab.idp;

import java.nio.file.Path;
import java.time.Clock;
import lab.SyntheticRegistry;
import lab.phone.PhoneBridge;
import org.junit.jupiter.api.Test;
import se.swedenconnect.spring.authnserver.authentication.*;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.message.GenericSignMessage;
import se.swedenconnect.spring.authnserver.oidc.authentication.OidcAuthenticationRequirements;
import se.swedenconnect.spring.authnserver.saml.authentication.*;
import static org.junit.jupiter.api.Assertions.*;

class SignatureRequestPolicyTest {
  @Test void bothProvidersRefuseSamlAndOidcSigningBeforeShowingLogin() throws Exception {
    var registry = SyntheticRegistry.fixtures();
    var web = new WebAuthnService(registry, "https://localhost:8443", Clock.systemUTC(), false);
    var lab = new LabProvider(registry, web);
    var phone = new PhoneProvider(new PhoneBridge(Path.of("/nonexistent-test-only.sock"), "https://localhost:8444/sp"));
    var saml = new SamlAuthenticationRequirements(); saml.setSignMessage(GenericSignMessage.ofText("sv", "SYNTHETIC signing"));
    var oidc = new OidcAuthenticationRequirements(); oidc.setSignMessage(GenericSignMessage.ofText("sv", "SYNTHETIC signing"));
    var sad = new SamlAuthenticationRequirements(); sad.setSadRequestExtension(new SadRequestExtension("id", "service", "sign-request", 1));
    for (AuthenticationRequirements requirements : java.util.List.of(saml, oidc, sad)) {
      var token = new UserAuthenticationInputToken(requirements,
          new Requester(requirements instanceof OidcAuthenticationRequirements ? AuthenticationProtocol.OIDC : AuthenticationProtocol.SAML,
              "https://localhost:8444/sp"));
      assertThrows(AuthenticationErrorException.class, () -> lab.authenticateUser(token));
      assertThrows(AuthenticationErrorException.class, () -> phone.authenticateUser(token));
    }
  }
}
