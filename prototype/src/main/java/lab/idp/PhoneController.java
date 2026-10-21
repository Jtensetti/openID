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
    if (!(sp+"/sp").equals(token.getAuthnInputToken().getRequester().identifier())) throw new IllegalArgumentException();
    return token.getAuthnId();
  }
  private PhoneBridge.Pending pending(HttpServletRequest request) {
    String binding = binding(request);
    Object value = request.getSession().getAttribute(PENDING);
    if (!(value instanceof PhoneBridge.Pending pending) || !pending.binding().equals(binding)) throw new IllegalStateException();
    return pending;
  }
  @GetMapping("/phone") ModelAndView page(HttpServletRequest request) {
    String binding = binding(request);
    PhoneBridge.Pending pending;
    synchronized (request.getSession()) {
      Object value = request.getSession().getAttribute(PENDING);
      if (value instanceof PhoneBridge.Pending old && old.binding().equals(binding)) pending = old;
      else {
        if (value instanceof PhoneBridge.Pending old) bridge.exchange("cancel", old);
        pending = bridge.start(binding); request.getSession().setAttribute(PENDING, pending);
      }
    }
    return new ModelAndView("phone", Map.of("restartUrl", sp+"/login", "authnId", binding, "code", pending.code(), "requestId", pending.id(), "service", PhoneBridge.SERVICE, "purpose", PhoneBridge.PURPOSE));
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
  @PostMapping("/phone/cancel") ModelAndView stop(HttpServletRequest request) {
    var pending = pending(request); bridge.exchange("cancel", pending);
    request.getSession().removeAttribute(PENDING); return cancel(request);
  }
  @ExceptionHandler({IllegalArgumentException.class, IllegalStateException.class, UnrecoverableErrorException.class})
  @ResponseStatus(HttpStatus.BAD_REQUEST) ModelAndView rejected() {
    return new ModelAndView("phone-error", Map.of("restartUrl", sp+"/login"));
  }
}
