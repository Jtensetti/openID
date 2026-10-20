package lab.idp;

import jakarta.servlet.http.HttpServletRequest;
import lab.SyntheticRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

/** Registration endpoints for lab test keys. */
@Controller
@org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(name="lab.phone", havingValue="false", matchIfMissing=true)
public final class WalletController {
  private final WebAuthnService webAuthn;
  private final SyntheticRegistry registry;
  private final String sp;
  WalletController(WebAuthnService webAuthn, SyntheticRegistry registry, @Value("${lab.sp-base}") String sp) {
    this.webAuthn = webAuthn; this.registry = registry; this.sp = sp;
  }
  @GetMapping("/wallet/") ModelAndView wallet() {
    if (!webAuthn.enabled()) throw new WebAuthnService.Rejected();
    boolean available;
    try { registry.authorize("TEST-CREDENTIAL-alice"); available = true; }
    catch (IllegalStateException e) { available = false; }
    return new ModelAndView("wallet", java.util.Map.of("sp", sp,
        "registered", registry.passkeys().containsKey("TEST-CREDENTIAL-alice"), "available", available));
  }
  @PostMapping(value="/wallet/register/options", produces="application/json") @ResponseBody
  String registrationOptions(HttpServletRequest request, @RequestParam String credential,
      @RequestParam(defaultValue="") String simulatedProofing) {
    return webAuthn.beginRegistration(request.getSession(), credential, simulatedProofing);
  }
  @PostMapping(value="/wallet/register/finish", produces="application/json") @ResponseBody
  String register(HttpServletRequest request, @RequestParam String response) {
    webAuthn.finishRegistration(request.getSession(false), response);
    request.changeSessionId();
    return "{\"registered\":true,\"proofing\":\"SIMULATED\"}";
  }
  @ExceptionHandler({WebAuthnService.Rejected.class, IllegalArgumentException.class, IllegalStateException.class})
  @ResponseStatus(HttpStatus.BAD_REQUEST) @ResponseBody
  String rejected() { return "Registreringen nekades. Kontrollera att testidentiteten är aktiv och inte redan har en nyckel."; }
}
