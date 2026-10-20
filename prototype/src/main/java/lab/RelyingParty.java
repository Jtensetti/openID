package lab;

import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import lab.phone.*;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.metadata.resolver.impl.DOMMetadataResolver;
import org.springframework.web.util.HtmlUtils;
import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;
import se.swedenconnect.opensaml.saml2.core.build.RequestedAuthnContextBuilder;
import se.swedenconnect.opensaml.saml2.request.*;
import se.swedenconnect.opensaml.saml2.response.*;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;

/** Local SAML service provider. */
public final class RelyingParty implements AutoCloseable {
  static final String COOKIE = "__Host-lab-sp";
  private record Session(AuthnRequest request, String relay, String identity, String csrf, Instant expires,
      Map<String, Long> revocations, PhoneIdentity person) {}
  private final Map<String, Session> sessions = new HashMap<>();
  private final HttpsServer server;
  // HttpServer dispatch threads do not carry Boot's nested-JAR class loader.
  // OpenSAML's ServiceLoader must see its actual validation providers in packaged runs too.
  private final ExecutorService executor = Executors.newFixedThreadPool(4, task -> {
    Thread thread = new Thread(task, "lab-sp-request");
    thread.setContextClassLoader(RelyingParty.class.getClassLoader());
    return thread;
  });
  private final DOMMetadataResolver resolver;
  private final LabResponseProcessor processor;
  private final AbstractAuthnRequestGenerator generator;
  private final EntityDescriptor idpMetadata;
  private final SyntheticRegistry registry;
  private final PhoneBridge phone;
  private final String base, idpBase;

  public RelyingParty(TestKeys keys, String idpBase, String base, SyntheticRegistry registry) throws Exception {
    this(keys, idpBase, base, registry, null);
  }
  public RelyingParty(TestKeys keys, String idpBase, String base, SyntheticRegistry registry, PhoneBridge phone) throws Exception {
    this.base = base; this.idpBase = idpBase; this.registry = registry; this.phone = phone;
    idpMetadata = Metadata.parse(Metadata.idp(keys, idpBase));
    EntityDescriptor spMetadata = Metadata.parse(Metadata.sp(keys, base, phone != null));
    resolver = new DOMMetadataResolver(org.opensaml.core.xml.util.XMLObjectSupport.marshall(idpMetadata)); resolver.setId("local-test-idp"); resolver.initialize();
    processor = new LabResponseProcessor(resolver, List.of(keys.credential("sp")));
    generator = new AbstractAuthnRequestGenerator(base + "/sp", new OpenSamlCredential(keys.credential("sp"))) {
      @Override protected EntityDescriptor getSpMetadata() { return spMetadata; }
      @Override protected EntityDescriptor getIdpMetadata(String entity) { return idpMetadata.getEntityID().equals(entity) ? idpMetadata : null; }
    };
    generator.initialize();
    server = HttpsServer.create(new InetSocketAddress("127.0.0.1", URI.create(base).getPort()), 20);
    server.setHttpsConfigurator(new HttpsConfigurator(keys.sslContext()));
    server.setExecutor(executor); server.createContext("/", this::handle); server.start();
  }

  // Package-visible test seam: not reachable from HTTP; uses the same signed request generator as /login.
  RequestHttpObject<AuthnRequest> generate(String relay, Consumer<AuthnRequest> customize) throws Exception {
    return generator.generateAuthnRequest(idpMetadata, relay, new AuthnRequestGeneratorContext() {
      @Override public String getPreferredBinding() { return SAMLConstants.SAML2_REDIRECT_BINDING_URI; }
      @Override public AuthnRequestCustomizer getAuthnRequestCustomizer() { return request -> {
        request.setForceAuthn(true);
        request.setRequestedAuthnContext(RequestedAuthnContextBuilder.builder()
            .comparison(AuthnContextComparisonTypeEnumeration.EXACT).authnContextClassRefs(phone == null ? Metadata.LAB_CONTEXT : PhoneIdentity.CONTEXT).build());
        customize.accept(request);
      }; }
    });
  }
  private void handle(HttpExchange x) throws IOException {
    String consumedTransaction = null;
    boolean terminalRecorded = false;
    try {
      if (!x.getRemoteAddress().getAddress().getHostAddress().equals("127.0.0.1") ||
          !URI.create(base).getAuthority().equals(x.getRequestHeaders().getFirst("Host")) ||
          x.getRequestHeaders().containsKey("Forwarded") || x.getRequestHeaders().containsKey("X-Forwarded-Host")) {
        send(x, 403, "Fel lokal motpart"); return;
      }
      String path = x.getRequestURI().getPath(), method = x.getRequestMethod();
      if (path.equals("/health/ready") && method.equals("GET")) {
        boolean ready = phone == null ? registry.ready() : phone.ready();
        send(x, ready ? 200 : 503, ready ? (phone == null ? "SYNTHETIC_ONLY: READY" : "READY") : "STORAGE_UNAVAILABLE");
      } else if (path.equals("/") && method.equals("GET")) {
        send(x, 200, phone == null ? "<h1>Lokal testtjänst</h1><p>Identitetskontrollen är simulerad.</p><p><a href='/login'>Starta testinloggning</a></p><p><a href='/me'>Visa min testsession</a></p><p><a href='" + idpBase + "'>Spärra testidentitet</a></p>" :
            "<p class='brand'>openID kontotjänst</p><h1>Ditt konto</h1><p><a href='/login'>Logga in med openID</a></p><p><a href='/me'>Visa min session</a></p>");
      } else if (path.equals("/login") && method.equals("GET")) {
        String sid = UUID.randomUUID().toString(), relay = UUID.randomUUID().toString();
        Map<String, Long> revocations = phone == null ? registry.revocationVersions() : Map.of();
        var authn = generate(relay, r -> {});
        synchronized (sessions) {
          sessions.values().removeIf(s -> !s.expires().isAfter(Instant.now()));
          if (sessions.size() >= 512) { send(x, 503, "Labben har för många öppna sessioner"); return; }
          sessions.remove(cookie(x));
          sessions.put(sid, new Session(authn.getRequest(), relay, null, null, Instant.now().plusSeconds(phone == null ? 60 : 120), revocations, null));
        }
        setCookie(x, sid); redirect(x, authn.getSendUrl());
      } else if (path.equals("/acs") && method.equals("POST")) {
        if (!idpBase.equals(x.getRequestHeaders().getFirst("Origin"))) { send(x, 403, "Fel svarskälla"); return; }
        Map<String, String> form = form(x);
        Session pending;
        synchronized (sessions) { pending = sessions.remove(cookie(x)); }
        if (pending == null || pending.request() == null || !pending.expires().isAfter(Instant.now())) {
          send(x, 400, "Ingen aktiv begäran i denna webbläsarsession"); return;
        }
        consumedTransaction = HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
            .digest(pending.request().getID().getBytes(StandardCharsets.UTF_8)));
        var result = processor.processSamlResponse(Objects.requireNonNull(form.get("SAMLResponse")), form.get("RelayState"), input(pending), null);
        if (phone != null) {
          if (!PhoneIdentity.CONTEXT.equals(result.getAuthnContextClassUri())) throw new IllegalArgumentException("Authentication context");
          var person = PhoneIdentity.fromAttributes(result.getAttributes());
          if (!phone.active(person)) throw new IllegalStateException("Credential inactive");
          String sid = UUID.randomUUID().toString();
          synchronized (sessions) { sessions.put(sid, new Session(null, null, person.displayName(), UUID.randomUUID().toString(), Instant.now().plusSeconds(300), Map.of(), person)); }
          setCookie(x, sid); redirect(x, "/me"); return;
        }
        if (!Metadata.LAB_CONTEXT.equals(result.getAuthnContextClassUri()) || result.getAttributes().size() != 1 ||
            !Metadata.DISPLAY_NAME.equals(result.getAttributes().getFirst().getName())) throw new IllegalArgumentException("Unexpected lab claims");
        String identity = AttributeUtils.getAttributeStringValue(result.getAttributes().getFirst());
        synchronized (registry) {
          if (!registry.activeIdentity(identity, pending.revocations().get(identity))) throw new IllegalStateException("Test identity no longer active");
          String sid = UUID.randomUUID().toString();
          registry.recordOutcome(consumedTransaction, OfflineReport.Outcome.SUCCESS);
          terminalRecorded = true;
          synchronized (sessions) { sessions.put(sid, new Session(null, null, identity, UUID.randomUUID().toString(), Instant.now().plusSeconds(300), pending.revocations(), null)); }
          setCookie(x, sid); redirect(x, "/me");
        }
      } else if (path.equals("/me") && method.equals("GET")) {
        Session session = current(x);
        if (session == null) { send(x, 401, "Ingen aktiv session"); return; }
        if (phone != null) {
          send(x, 200, "<p class='brand'>openID kontotjänst</p><h1>Inloggad</h1><img src='/portrait' width='160' alt='Passfoto'><h2 id='identity'>" + HtmlUtils.htmlEscape(session.person().displayName()) +
              "</h2><p>Födelsedatum (MRZ): <span id='birth-date'>"+session.person().birthDateMrz()+"</span></p><form action='/logout' method='post'><input type='hidden' name='csrf' value='"+session.csrf()+"'><button>Logga ut</button></form>"); return;
        }
        send(x, 200, "<h1>Inloggad</h1><p id='identity'>" + HtmlUtils.htmlEscape(session.identity()) +
            "</p><p>Identitetskontrollen är simulerad.</p><form action='/logout' method='post'><input type='hidden' name='csrf' value='" + session.csrf() + "'><button>Avsluta testsession</button></form>");
      } else if (path.equals("/portrait") && method.equals("GET") && phone != null) {
        Session session = current(x);
        if (session == null) { send(x, 401, "Ingen aktiv session"); return; }
        byte[] image = Base64.getDecoder().decode(session.person().portrait());
        headers(x); x.getResponseHeaders().set("Content-Type", "image/jpeg");
        x.sendResponseHeaders(200, image.length); x.getResponseBody().write(image);
      } else if (path.equals("/style.css") && method.equals("GET")) {
        byte[] css;
        try (var stream = RelyingParty.class.getResourceAsStream("/static/phone/page.css")) { css = Objects.requireNonNull(stream).readAllBytes(); }
        headers(x); x.getResponseHeaders().set("Content-Type", "text/css"); x.sendResponseHeaders(200, css.length); x.getResponseBody().write(css);
      } else if (path.equals("/logout") && method.equals("POST")) {
        Session session = current(x);
        if (session == null || !base.equals(x.getRequestHeaders().getFirst("Origin")) || !session.csrf().equals(form(x).get("csrf"))) {
          send(x, 403, "Ogiltigt utloggningsförsök"); return;
        }
        synchronized (sessions) { sessions.remove(cookie(x)); }
        x.getResponseHeaders().add("Set-Cookie", COOKIE + "=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"); redirect(x, "/");
      } else send(x, 404, "Sidan finns inte");
    } catch (Exception e) {
      if (phone == null && consumedTransaction != null && !terminalRecorded) {
        try { registry.recordOutcome(consumedTransaction, OfflineReport.Outcome.FAILED); }
        catch (IllegalStateException ignored) { /* Login is denied below even if audit storage fails. */ }
      }
      // Never log SAML payloads, cookies, identities, request parameters or exception text.
      send(x, 400, "Inloggningen nekades. Börja om i tjänsten.");
    } finally { x.close(); }
  }
  private ResponseProcessingInput input(Session s) {
    Instant received = Instant.now();
    return new ResponseProcessingInput() {
      @Override public AuthnRequest getAuthnRequest(String id) { return s.request().getID().equals(id) ? s.request() : null; }
      @Override public String getRequestRelayState(String id) { return s.request().getID().equals(id) ? s.relay() : null; }
      @Override public String getReceiveURL() { return base + "/acs"; }
      @Override public Instant getReceiveInstant() { return received; }
      @Override public String getClientIpAddress() { return null; }
      @Override public X509Certificate getClientCertificate() { return null; }
    };
  }
  private Session current(HttpExchange x) {
    Session s;
    synchronized (sessions) { s = sessions.get(cookie(x)); }
    if (s == null || s.identity() == null || !s.expires().isAfter(Instant.now())) return null;
    if (phone == null ? !registry.activeIdentity(s.identity(), s.revocations().get(s.identity())) : s.person() == null || !phone.active(s.person())) {
      synchronized (sessions) { sessions.remove(cookie(x)); } return null;
    }
    return s;
  }
  private static Map<String, String> form(HttpExchange x) throws IOException {
    String type = x.getRequestHeaders().getFirst("Content-Type");
    if (type == null || !type.startsWith("application/x-www-form-urlencoded")) throw new IllegalArgumentException("Form required");
    byte[] bytes = x.getRequestBody().readNBytes(131073);
    if (bytes.length > 131072) throw new IllegalArgumentException("Form too large");
    Map<String, String> map = new HashMap<>();
    for (String part : new String(bytes, StandardCharsets.UTF_8).split("&")) {
      String[] kv = part.split("=", 2);
      if (kv.length != 2 || map.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), URLDecoder.decode(kv[1], StandardCharsets.UTF_8)) != null)
        throw new IllegalArgumentException("Duplicate or malformed form parameter");
    }
    return map;
  }
  private static String cookie(HttpExchange x) {
    String raw = x.getRequestHeaders().getFirst("Cookie");
    if (raw == null) return "";
    for (String part : raw.split(";")) { String[] kv = part.trim().split("=", 2); if (kv.length == 2 && kv[0].equals(COOKIE)) return kv[1]; }
    return "";
  }
  private static void setCookie(HttpExchange x, String sid) { x.getResponseHeaders().add("Set-Cookie", COOKIE + "=" + sid + "; Path=/; Secure; HttpOnly; SameSite=Strict"); }
  private static void redirect(HttpExchange x, String uri) throws IOException {
    x.getResponseHeaders().set("Location", uri); headers(x); x.sendResponseHeaders(303, -1);
  }
  private static void headers(HttpExchange x) {
    x.getResponseHeaders().set("Cache-Control", "no-store"); x.getResponseHeaders().set("Referrer-Policy", "strict-origin");
    x.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
    x.getResponseHeaders().set("Content-Security-Policy", "default-src 'none'; img-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
  }
  private static void send(HttpExchange x, int status, String body) throws IOException {
    headers(x); x.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
    byte[] bytes = ("<!doctype html><html lang='sv'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>openID</title><link rel='stylesheet' href='/style.css'></head><body><main>" + body + "</main></body></html>").getBytes(StandardCharsets.UTF_8);
    x.sendResponseHeaders(status, bytes.length); x.getResponseBody().write(bytes);
  }
  @Override public void close() { server.stop(0); executor.shutdownNow(); resolver.destroy(); }
}
