package lab.idp;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import lab.phone.PhoneBridge;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.AbstractAuthenticationController;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

@Controller
@ConditionalOnProperty(name="lab.phone", havingValue="true")
public final class PhoneController extends AbstractAuthenticationController<PhoneProvider> {
  private static final String PENDING = PhoneController.class.getName()+".pending";
  private final PhoneProvider provider;
  private final PhoneBridge bridge;
  private final String sp;
  PhoneController(PhoneProvider provider, PhoneBridge bridge, @Value("${lab.sp-base}") String sp) {
    this.provider = provider; this.bridge = bridge; this.sp = sp;
  }
  @Override protected PhoneProvider getProvider() { return provider; }
  @GetMapping("/") ModelAndView home() { return new ModelAndView("redirect:"+sp); }
  private String binding(HttpServletRequest request) {
    var token = getInputToken(request);
    // The account service and its signature service are the only configured requesters.
    if (!java.util.Set.of(sp+"/sp", sp+"/sign").contains(token.getAuthnInputToken().getRequester().identifier())) throw new IllegalArgumentException();
    return token.getAuthnId();
  }
  private String signMessage(HttpServletRequest request) {
    try { return SignatureRequestPolicy.signMessage(getInputToken(request).getAuthnInputToken().getAuthnRequirements()); }
    catch (se.swedenconnect.spring.authnserver.error.AuthenticationErrorException e) { throw new IllegalStateException(); }
  }
  private PhoneBridge.Pending pending(HttpServletRequest request) {
    String binding = binding(request);
    Object value = request.getSession().getAttribute(PENDING);
    if (!(value instanceof PhoneBridge.Pending pending) || !pending.binding().equals(binding)) throw new IllegalStateException();
    return pending;
  }
  @GetMapping("/phone") ModelAndView page(HttpServletRequest request) {
    String binding = binding(request), message = signMessage(request);
    PhoneBridge.Pending pending;
    synchronized (request.getSession()) {
      Object value = request.getSession().getAttribute(PENDING);
      if (value instanceof PhoneBridge.Pending old && old.binding().equals(binding) && java.util.Objects.equals(old.signMessage(), message)) pending = old;
      else {
        if (value instanceof PhoneBridge.Pending old) bridge.exchange("cancel", old);
        pending = bridge.start(binding, message); request.getSession().setAttribute(PENDING, pending);
      }
    }
    var model = new java.util.HashMap<String, Object>(Map.of("restartUrl", sp+(pending.signing() ? "/sign" : "/login"), "authnId", binding, "code", pending.code(),
        "requestId", pending.id(), "service", PhoneBridge.SERVICE, "purpose", pending.signing() ? PhoneBridge.SIGN_PURPOSE : PhoneBridge.PURPOSE, "signing", pending.signing()));
    if (pending.signing()) model.put("signMessage", pending.signMessage());
    return new ModelAndView("phone", model);
  }
  @GetMapping(value="/phone/qr", produces="image/svg+xml") @ResponseBody String qr(HttpServletRequest request) {
    return PhoneBridge.text(bridge.exchange("qr", pending(request)), "svg");
  }
  @PostMapping(value="/phone/poll", produces="application/json") @ResponseBody Map<String, String> poll(HttpServletRequest request) {
    return Map.of("state", PhoneBridge.text(bridge.exchange("poll", pending(request)), "state"));
  }
  @PostMapping("/phone/complete") ModelAndView finish(HttpServletRequest request) {
    var pending = pending(request);
    request.getSession().removeAttribute(PENDING);
    return complete(request, new PhoneProvider.Approval(pending));
  }
  /** Ends the registry request. The page then offers to return to the service with SAML status cancel. */
  @PostMapping("/phone/cancel") org.springframework.http.ResponseEntity<Void> stop(HttpServletRequest request) {
    var pending = pending(request); bridge.exchange("cancel", pending);
    request.getSession().removeAttribute(PENDING); return org.springframework.http.ResponseEntity.noContent().build();
  }
  /** Deployment Profile §6.4: the requester learns that the user cancelled (status .../status/1.0/cancel). */
  @PostMapping("/phone/return") ModelAndView back(HttpServletRequest request) {
    String binding = binding(request);
    synchronized (request.getSession()) {
      if (request.getSession().getAttribute(PENDING) instanceof PhoneBridge.Pending old && old.binding().equals(binding)) {
        bridge.exchange("cancel", old); request.getSession().removeAttribute(PENDING);
      }
    }
    return cancel(request);
  }
  @ExceptionHandler({IllegalArgumentException.class, IllegalStateException.class, UnrecoverableErrorException.class})
  @ResponseStatus(HttpStatus.BAD_REQUEST) ModelAndView rejected() {
    return new ModelAndView("phone-error", Map.of("restartUrl", sp+"/login"));
  }
}
