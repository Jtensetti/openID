package lab.idp;

import jakarta.servlet.http.*;
import java.time.Clock;
import java.util.Map;
import lab.SyntheticRegistry;
import lab.signing.SigningCeremony;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

/** Only enabled by start-web. Never mounted in the passport/iPhone pilot. */
@Controller
@ConditionalOnProperty(name="lab.webauthn", havingValue="true")
public final class SigningController {
  private static final String TX = SigningController.class.getName() + ".transaction";
  private static final String RESULT = SigningController.class.getName() + ".result";
  private final WebAuthnService webAuthn;
  private final SyntheticRegistry registry;
  private final SigningCeremony ceremony;
  private final Clock clock = Clock.systemUTC();
  SigningController(WebAuthnService webAuthn, SyntheticRegistry registry) throws Exception {
    this.webAuthn = webAuthn; this.registry = registry; ceremony = new SigningCeremony(registry, clock);
  }
  @GetMapping("/sign/") ModelAndView document(HttpServletRequest request) throws Exception {
    synchronized (registry) {
      var session = request.getSession();
      ceremony.cancel((SigningCeremony.Transaction) session.getAttribute(TX));
      webAuthn.clear(session); session.removeAttribute(RESULT);
      if (!registry.passkeys().containsKey("TEST-CREDENTIAL-alice")) throw new IllegalStateException();
      var tx = ceremony.begin("TEST-CREDENTIAL-alice"); session.setAttribute(TX, tx);
      return new ModelAndView("sign-document", Map.of("tx", tx, "intent", SigningCeremony.INTENT));
    }
  }
  private SigningCeremony.Transaction transaction(HttpServletRequest request, String id, String digest) {
    var session = request.getSession(false);
    var tx = session == null ? null : (SigningCeremony.Transaction) session.getAttribute(TX);
    ceremony.check(tx, id, digest); return tx;
  }
  @PostMapping(value="/sign/options", produces="application/json") @ResponseBody
  String options(HttpServletRequest request, @RequestParam String transaction, @RequestParam String digest,
      @RequestParam(defaultValue="") String intent) {
    synchronized (registry) {
      var tx = transaction(request, transaction, digest);
      if (!"sign-this-document".equals(intent)) { ceremony.cancel(tx); throw new IllegalArgumentException(); }
      return webAuthn.beginAuthentication(request.getSession(false), tx.credential(), tx.flow());
    }
  }
  @PostMapping("/sign/finish") ModelAndView finish(HttpServletRequest request, @RequestParam String transaction,
      @RequestParam String digest, @RequestParam String response) throws Exception {
    synchronized (registry) {
      var session = request.getSession(false);
      var tx = session == null ? null : (SigningCeremony.Transaction) session.getAttribute(TX);
      try {
        ceremony.check(tx, transaction, digest);
        String credential = webAuthn.finishAuthentication(session, tx.flow(), response);
        var result = ceremony.finish(tx, credential, transaction, digest);
        session.setAttribute(RESULT, result);
        request.changeSessionId();
        return redirect("/sign/result");
      } finally {
        ceremony.cancel(tx); webAuthn.clear(session);
        if (session != null) session.removeAttribute(TX);
      }
    }
  }
  @PostMapping("/sign/cancel") ModelAndView cancel(HttpServletRequest request) {
    synchronized (registry) {
      var session = request.getSession(false);
      if (session != null) { ceremony.cancel((SigningCeremony.Transaction) session.getAttribute(TX)); session.removeAttribute(TX); }
      webAuthn.clear(session); return redirect("/wallet/");
    }
  }
  private SigningCeremony.Result result(HttpServletRequest request) {
    var session = request.getSession(false);
    var result = session == null ? null : (SigningCeremony.Result) session.getAttribute(RESULT);
    if (result == null || !result.expires().isAfter(clock.instant())) {
      if (session != null) session.removeAttribute(RESULT);
      throw new IllegalStateException();
    }
    return result;
  }
  private static ModelAndView redirect(String path) {
    var view = new ModelAndView("redirect:" + path); view.setStatus(HttpStatus.SEE_OTHER); return view;
  }
  @GetMapping("/sign/result") ModelAndView completed(HttpServletRequest request) {
    result(request); return new ModelAndView("sign-result");
  }
  @GetMapping("/sign/download") @ResponseBody ResponseEntity<byte[]> download(HttpServletRequest request) {
    return ResponseEntity.ok().contentType(MediaType.parseMediaType("application/zip"))
        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=synthetic-signature.zip")
        .body(result(request).archive());
  }
  @ExceptionHandler({WebAuthnService.Rejected.class, IllegalArgumentException.class, IllegalStateException.class})
  @ResponseStatus(HttpStatus.BAD_REQUEST) @ResponseBody String rejected() {
    return "Underskriften kunde inte slutföras. Öppna testdokumentet på nytt och kontrollera testnyckelns status.";
  }
}
