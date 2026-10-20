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
public final class LabController extends AbstractAuthenticationController<LabProvider> {
  private final LabProvider provider;
  private final SyntheticRegistry registry;
  private final String sp;
  LabController(LabProvider provider, SyntheticRegistry registry, @Value("${lab.sp-base}") String sp) {
    this.provider = provider; this.registry = registry; this.sp = sp;
  }
  @Override protected LabProvider getProvider() { return provider; }
  @GetMapping("/") ModelAndView home() { return new ModelAndView("home", "sp", sp); }
  @GetMapping("/lab") ModelAndView page(HttpServletRequest request) {
    var token = getInputToken(request);
    return new ModelAndView("approve", java.util.Map.of("authnId", token.getAuthnId(), "requester", token.getAuthnInputToken().getRequester().identifier()));
  }
  @PostMapping("/lab") ModelAndView approve(HttpServletRequest request, @RequestParam String action,
      @RequestParam(defaultValue = "") String credential, @RequestParam(defaultValue = "") String simulatedProofing) {
    getInputToken(request);
    if (action.equals("cancel")) return cancel(request);
    if (!action.equals("approve") || !simulatedProofing.equals("acknowledged"))
      return complete(request, new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "Explicit simulation acknowledgement required"));
    try { registry.authorize(credential); }
    catch (IllegalArgumentException | IllegalStateException e) {
      return complete(request, new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED, "Test credential is unavailable"));
    }
    return complete(request, UsernamePasswordAuthenticationToken.unauthenticated(credential, null));
  }
  @PostMapping("/lab/revoke") ModelAndView revoke() {
    registry.revoke("TEST-CREDENTIAL-alice");
    return new ModelAndView("revoked");
  }
  @ExceptionHandler(UnrecoverableErrorException.class) @ResponseStatus(org.springframework.http.HttpStatus.BAD_REQUEST)
  @ResponseBody String invalidFlow() { return "Ogiltigt eller för gammalt labbflöde. Börja om i testtjänsten."; }
}
