package lab.idp;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.error.*;
import se.swedenconnect.spring.authnserver.saml.authentication.SamlAuthenticationRequirements;

/** Login approval must never be presented as approval of an undisplayed signature message. */
final class SignatureRequestPolicy {
  private SignatureRequestPolicy() {}
  static void requireLoginOnly(AuthenticationRequirements requirements) throws AuthenticationErrorException {
    if (requirements.getSignMessage() != null || requirements instanceof SamlAuthenticationRequirements saml
        && saml.getSadRequestExtension() != null)
      throw new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "Federated signing is not enabled");
  }
}
