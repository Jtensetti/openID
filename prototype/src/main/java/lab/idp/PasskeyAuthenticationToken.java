package lab.idp;

import java.util.List;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/** Issued by the controller only after server-side WebAuthn validation. */
final class PasskeyAuthenticationToken extends AbstractAuthenticationToken {
  private final String credential;
  PasskeyAuthenticationToken(String credential) { super(List.of()); this.credential = credential; }
  @Override public Object getPrincipal() { return credential; }
  @Override public Object getCredentials() { return null; }
}
