package lab.idp;

import java.time.*;
import java.util.*;
import lab.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;
import se.swedenconnect.spring.authnserver.attributes.*;
import se.swedenconnect.spring.authnserver.authentication.*;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.*;
import se.swedenconnect.spring.authnserver.error.*;
import se.swedenconnect.spring.authnserver.sso.SsoPolicy;

@Component
@org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(name="lab.phone", havingValue="false", matchIfMissing=true)
public final class LabProvider extends AbstractUserRedirectAuthenticationProvider {
  private final SyntheticRegistry registry;
  private final WebAuthnService webAuthn;
  public LabProvider(SyntheticRegistry registry, WebAuthnService webAuthn) {
    super("/lab", "/lab/resume"); this.registry = registry; this.webAuthn = webAuthn; setSsoPolicy(SsoPolicy.none());
    var repository = new SessionBasedRedirectAuthenticationRepository(); repository.setMaxAge(Duration.ofSeconds(60)); setRepository(repository);
  }
  @Override public String getName() { return webAuthn.enabled() ? "WEBAUTHN-SYNTHETIC-PROOFING" : "SIMULATED-ONLY"; }
  @Override public List<String> getSupportedAuthnContextUris() { return List.of(Metadata.LAB_CONTEXT); }
  @Override public List<String> getSupportedAttributes() { return List.of(AttributeIdentifiers.DISPLAY_NAME); }
  @Override public Authentication authenticateUser(UserAuthenticationInputToken token) throws AuthenticationErrorException {
    SignatureRequestPolicy.requireLoginOnly(token.getAuthnRequirements());
    return super.authenticateUser(token);
  }
  @Override public boolean supportsUserAuthenticationToken(Authentication token) {
    return webAuthn.enabled() ? token instanceof PasskeyAuthenticationToken : token instanceof UsernamePasswordAuthenticationToken;
  }
  @Override protected UserAuthentication createUserAuthentication(ResumedAuthenticationToken token) throws AuthenticationErrorException {
    try {
      String credential = token.getAuthnToken().getName();
      var entry = registry.authorize(credential);
      var user = new AuthenticatedUser(List.of(GenericAttribute.of(AttributeIdentifiers.DISPLAY_NAME, entry.identity())),
          AttributeIdentifiers.DISPLAY_NAME, Metadata.LAB_CONTEXT, Instant.now(), "127.0.0.1");
      return new UserAuthentication(user);
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "Test credential is unavailable");
    }
  }
}
