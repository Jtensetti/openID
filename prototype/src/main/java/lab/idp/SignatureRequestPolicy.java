package lab.idp;

import lab.phone.PhoneBridge;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.error.*;
import se.swedenconnect.spring.authnserver.message.*;
import se.swedenconnect.spring.authnserver.saml.authentication.SamlAuthenticationRequirements;

/**
 * Login approval must never be presented as approval of an undisplayed signature message.
 * Sweden Connect Deployment Profile 1.9 §7.1.1: a sign message is shown in full and approved separately,
 * or the request fails.
 */
final class SignatureRequestPolicy {
  /** Language preference of the app. A message without language tag is used when Swedish is not given. */
  static final String LANGUAGE = "sv";
  private SignatureRequestPolicy() {}

  /** Simulated lab: no signing over federation at all. */
  static void requireLoginOnly(AuthenticationRequirements requirements) throws AuthenticationErrorException {
    if (requirements.getSignMessage() != null || requirements instanceof SamlAuthenticationRequirements saml
        && saml.getSadRequestExtension() != null)
      throw new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "Federated signing is not enabled");
  }

  /** Phone provider: the exact text the app will show, or {@code null} for an ordinary login. */
  static String signMessage(AuthenticationRequirements requirements) throws AuthenticationErrorException {
    GenericSignMessage message = requirements.getSignMessage();
    boolean sad = requirements instanceof SamlAuthenticationRequirements saml && saml.getSadRequestExtension() != null;
    if (message == null) {
      // SAD asserts that the signer approved a displayed message; without one it cannot be issued.
      if (sad) throw new AuthenticationErrorException(AuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED, "SAD requires a sign message");
      return null;
    }
    String text = null;
    if (message.getMimeType() == MessageMimeType.TEXT_PLAIN) {
      LocalizedMessage localized = message.getMessage(LANGUAGE);
      if (localized == null) localized = message.getMessages().getFirst();
      try { text = PhoneBridge.requireSignMessage(localized.getText()); }
      catch (IllegalArgumentException e) { text = null; }
    }
    // Only bounded plain text is rendered, without interpretation. Anything else is not displayed; with MustShow
    // (always for OIDC) or SAD the request fails instead of silently continuing as a login.
    if (text == null && (message.isMustShow() || sad))
      throw new AuthenticationErrorException(AuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED, "Sign message cannot be displayed");
    return text;
  }

  /** Language tag of the displayed text, for the assertion's signMessageDigest. */
  static String language(AuthenticationRequirements requirements) {
    GenericSignMessage message = requirements.getSignMessage();
    if (message == null) return null;
    LocalizedMessage localized = message.getMessage(LANGUAGE);
    return localized != null ? localized.language() : message.getMessages().getFirst().language();
  }
}
