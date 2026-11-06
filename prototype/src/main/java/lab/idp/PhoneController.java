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
    bridge.audienceForRequester(token.getAuthnInputToken().getRequester().identifier());
    return token.getAuthnId();
  }
  private String signMessage(HttpServletRequest request) {
    try { return SignatureRequestPolicy.signMessage(getInputToken(request).getAuthnInputToken().getAuthnRequirements()); }
    catch (se.swedenconnect.spring.authnserver.error.AuthenticationErrorException e) { throw new IllegalStateException(); }
  }
  private String level(HttpServletRequest request) {
    try { return SignatureRequestPolicy.level(getInputToken(request).getAuthnInputToken().getAuthnRequirements()); }
    catch (se.swedenconnect.spring.authnserver.error.AuthenticationErrorException e) { throw new IllegalStateException(); }
  }
  private PhoneBridge.Pending pending(HttpServletRequest request) {
    String binding = binding(request);
    Object value = request.getSession().getAttribute(PENDING);
    if (!(value instanceof PhoneBridge.Pending pending) || !pending.binding().equals(binding) ||
        !pending.audience().equals(audience(request))) throw new IllegalStateException();
    return pending;
  }
  private String audience(HttpServletRequest request) {
    return bridge.audienceForRequester(getInputToken(request).getAuthnInputToken().getRequester().identifier());
  }
  @GetMapping("/phone") ModelAndView page(HttpServletRequest request) {
    String binding = binding(request), message = signMessage(request), level = level(request);
    PhoneBridge.Pending pending;
    synchronized (request.getSession()) {
      Object value = request.getSession().getAttribute(PENDING);
      if (value instanceof PhoneBridge.Pending old && old.binding().equals(binding) && java.util.Objects.equals(old.signMessage(), message)
          && java.util.Objects.equals(old.level(), level) && audience(request).equals(old.audience())) pending = old;
      else {
        if (value instanceof PhoneBridge.Pending old) bridge.exchange("cancel", old);
        pending = bridge.startFor(audience(request), binding, message, level); request.getSession().setAttribute(PENDING, pending);
      }
    }
    String restart = bridge.external(pending) ? "https://testclient.sandbox.swedenconnect.se/" : sp+(pending.signing() ? "/sign" : "/login");
    var model = new java.util.HashMap<String, Object>(Map.of("restartUrl", restart, "authnId", binding, "code", pending.code(),
        "requestId", pending.id(), "service", bridge.service(pending), "purpose", bridge.purpose(pending), "signing", pending.signing(),
        "securityCode", pending.securityCode()));
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
