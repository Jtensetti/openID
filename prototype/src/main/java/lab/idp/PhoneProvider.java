package lab.idp;

import java.time.*;
import java.util.*;
import lab.phone.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import se.swedenconnect.spring.authnserver.attributes.*;
import se.swedenconnect.spring.authnserver.authentication.*;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.*;
import se.swedenconnect.spring.authnserver.error.*;
import se.swedenconnect.spring.authnserver.sso.SsoPolicy;

@Component
@ConditionalOnProperty(name="lab.phone", havingValue="true")
public final class PhoneProvider extends AbstractUserRedirectAuthenticationProvider {
  private final PhoneBridge bridge;
  public PhoneProvider(PhoneBridge bridge) {
    super("/phone", "/phone/resume"); this.bridge = bridge; setSsoPolicy(SsoPolicy.none());
    var repository = new SessionBasedRedirectAuthenticationRepository(); repository.setMaxAge(Duration.ofSeconds(120)); setRepository(repository);
  }
  @Override public String getName() { return "PASSPORT-DEVICE"; }
  @Override public List<String> getSupportedAuthnContextUris() { return List.of(PhoneIdentity.CONTEXT); }
  @Override public List<String> getSupportedAttributes() { return PhoneAttributes.supported(); }
  /** Deployment Profile §2.1.3: SAD support (SCAL2) is advertised; sign messages are shown in the app. */
  @Override public List<String> getEntityCategories() {
    return List.of(se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants.SERVICE_PROPERTY_CATEGORY_SCAL2.getUri());
  }
  @Override public Authentication authenticateUser(UserAuthenticationInputToken token) throws AuthenticationErrorException {
    SignatureRequestPolicy.signMessage(token.getAuthnRequirements()); // Fails before any display if it cannot be shown.
    return super.authenticateUser(token);
  }
  @Override public boolean supportsUserAuthenticationToken(Authentication token) { return token instanceof Approval; }
  @Override protected UserAuthentication createUserAuthentication(ResumedAuthenticationToken token) throws AuthenticationErrorException {
    try {
      var approval = (Approval)token.getAuthnToken();
      var requirements = token.getAuthnInputToken().getAuthnRequirements();
      String expected = SignatureRequestPolicy.signMessage(requirements);
      // The registry request must carry exactly the text of THIS authentication request.
      if (!java.util.Objects.equals(expected, approval.pending.signMessage())) throw new IllegalStateException("Sign message binding");
      var approved = bridge.approve(approval.pending);
      var user = new AuthenticatedUser(PhoneAttributes.values(approved.identity()), PhoneIdentity.SUBJECT, PhoneIdentity.CONTEXT, Instant.now(), "127.0.0.1");
      // Set only after the registry confirmed a separate signing approval of the SHA-256 of this exact text.
      if (expected != null && approved.signMessageSha256() != null) user.setSignMessageDisplayed(true, SignatureRequestPolicy.language(requirements));
      return new UserAuthentication(user);
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "Device approval unavailable");
    }
  }
  static final class Approval extends AbstractAuthenticationToken {
    final PhoneBridge.Pending pending;
    Approval(PhoneBridge.Pending pending) { super(List.of()); this.pending = pending; }
    @Override public Object getPrincipal() { return "phone"; }
    @Override public Object getCredentials() { return null; }
  }
}
