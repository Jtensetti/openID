package lab.idp;

import jakarta.servlet.http.HttpServletRequest;
import lab.SyntheticRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.AbstractAuthenticationController;
import se.swedenconnect.spring.authnserver.error.*;

@Controller
@org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(name="lab.phone", havingValue="false", matchIfMissing=true)
public final class LabController extends AbstractAuthenticationController<LabProvider> {
  private final LabProvider provider;
  private final SyntheticRegistry registry;
  private final String sp;
  private final WebAuthnService webAuthn;
  LabController(LabProvider provider, SyntheticRegistry registry, @Value("${lab.sp-base}") String sp, WebAuthnService webAuthn) {
    this.provider = provider; this.registry = registry; this.sp = sp; this.webAuthn = webAuthn;
  }
  @Override protected LabProvider getProvider() { return provider; }
  @GetMapping("/") ModelAndView home() { return webAuthn.enabled() ? new ModelAndView("redirect:/wallet/") : new ModelAndView("home", "sp", sp); }
  @GetMapping("/lab") ModelAndView page(HttpServletRequest request) {
    var token = getInputToken(request);
    return new ModelAndView(webAuthn.enabled() ? "web-approve" : "approve", java.util.Map.of("authnId", token.getAuthnId(), "requester", token.getAuthnInputToken().getRequester().identifier()));
  }
  @PostMapping("/lab") ModelAndView approve(HttpServletRequest request, @RequestParam String action,
      @RequestParam(defaultValue = "") String credential, @RequestParam(defaultValue = "") String simulatedProofing) {
    getInputToken(request);
    if (action.equals("cancel")) { webAuthn.clear(request.getSession(false)); return cancel(request); }
    if (webAuthn.enabled()) return complete(request, new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "WebAuthn is required"));
    if (!action.equals("approve") || !simulatedProofing.equals("acknowledged"))
      return complete(request, new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "Explicit simulation acknowledgement required"));
    try { registry.authorize(credential); }
    catch (IllegalArgumentException | IllegalStateException e) {
      return complete(request, new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "Test credential is unavailable"));
    }
    return complete(request, UsernamePasswordAuthenticationToken.unauthenticated(credential, null));
  }
  @PostMapping(value="/lab/webauthn/options", produces="application/json") @ResponseBody
  String assertionOptions(HttpServletRequest request, @RequestParam String credential) {
    var input = getInputToken(request);
    return webAuthn.beginAuthentication(request.getSession(), credential, "saml:" + input.getAuthnId());
  }
  @PostMapping("/lab/webauthn/finish")
  ModelAndView assertionResult(HttpServletRequest request, @RequestParam String response) {
    var input = getInputToken(request);
    String credential = webAuthn.finishAuthentication(request.getSession(false), "saml:" + input.getAuthnId(), response);
    return complete(request, new PasskeyAuthenticationToken(credential));
  }
  @PostMapping("/lab/revoke") ModelAndView revoke() {
    registry.revoke("TEST-CREDENTIAL-alice");
    return new ModelAndView("revoked");
  }
  @ExceptionHandler(UnrecoverableErrorException.class) @ResponseStatus(org.springframework.http.HttpStatus.BAD_REQUEST)
  @ResponseBody String invalidFlow() { return "Ogiltigt eller för gammalt labbflöde. Börja om i testtjänsten."; }
  @ExceptionHandler({WebAuthnService.Rejected.class, IllegalArgumentException.class, IllegalStateException.class})
  @ResponseStatus(org.springframework.http.HttpStatus.BAD_REQUEST) @ResponseBody
  String rejectedPasskey() { return "Testnyckeln kunde inte verifieras. Börja om i testtjänsten."; }
}
