package lab;

import com.sun.net.httpserver.HttpExchange;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.Consumer;
import lab.phone.*;
import lab.signing.PadesSigner;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.springframework.web.util.HtmlUtils;
import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;
import se.swedenconnect.opensaml.saml2.core.build.RequestedAuthnContextBuilder;
import se.swedenconnect.opensaml.saml2.request.*;
import se.swedenconnect.opensaml.saml2.response.*;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.signservice.*;
import se.swedenconnect.opensaml.sweid.saml2.signservice.build.*;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.*;
import se.swedenconnect.opensaml.sweid.saml2.signservice.sap.*;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectEncrypter;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;

/**
 * Test console of the account service: Sweden Connect technical framework cases run against the real IdP and app.
 * Each response is validated by the Sweden Connect response processor and then checked against the expected
 * outcome of the case. The signature cases act as a signature service (entity category sigservice).
 * This is a technical self-test, not Digg's approval process or an external interoperability test.
 */
final class TestConsole {
  static final String COOKIE = "__Host-openid-test";
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final ZoneId ZONE = ZoneId.of("Europe/Stockholm");
  private static final String NO_PASSIVE = StatusCode.NO_PASSIVE, NO_CONTEXT = StatusCode.NO_AUTHN_CONTEXT,
      CANCEL = "http://id.elegnamnden.se/status/1.0/cancel", AUTHN_FAILED = StatusCode.AUTHN_FAILED;
  private static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  enum Entity { SERVICE, SIGNATURE_SERVICE }
  enum Request { LOGIN, LOGIN_PIN, NO_FORCE, PASSIVE, LOA3, SIGN, SIGN_PIN, SIGN_ENCRYPTED, SIGN_HTML, SAD_ONLY, SIGN_FROM_SERVICE }
  record Case(String id, String group, String title, String purpose, String reference, String instruction,
      Entity entity, Request request, String expectedTop, String expectedSecond) {
    boolean expectsSuccess() { return expectedTop == null; }
    boolean signs() { return request == Request.SIGN || request == Request.SIGN_PIN || request == Request.SIGN_ENCRYPTED; }
    boolean securityCode() { return request == Request.LOGIN_PIN || request == Request.SIGN_PIN; }
    /** The context the service asks for; the security-code cases accept only the code level. */
    String context() { return request == Request.LOA3 ? LOA3 : securityCode() ? PhoneIdentity.PIN_CONTEXT : PhoneIdentity.CONTEXT; }
  }
  static final List<Case> CASES = List.of(
      new Case("login", "Legitimering", "Grundinloggning", "Signerad AuthnRequest med ForceAuthn och exakt autentiseringskontext. Svaret ska vara signerat och krypterat, bundet till begäran och innehålla alla begärda attribut men inga andra.",
          "Deployment Profile §§5.3–6.2", "Skanna QR-koden och godkänn i appen.", Entity.SERVICE, Request.LOGIN, null, null),
      new Case("login-pin", "Legitimering", "Inloggning med säkerhetskod", "Tjänsten begär nivån med säkerhetskod, som BankID:s krav på säkerhetskod. Appen ska kräva koden utöver Face ID, och svaret ska intyga den nivån.",
          "Egen kontext urn:openid:authn:passport-native:pin:v1; DP §5.4.4", "Skriv din säkerhetskod i appen och godkänn med Face ID.", Entity.SERVICE, Request.LOGIN_PIN, null, null),
      new Case("no-force", "Legitimering", "Ny legitimering utan ForceAuthn", "IdP:n får inte återanvända en tidigare session när policyn inte tillåter det. AuthnInstant ska vara färskare än begäran.",
          "Deployment Profile §5.4.5", "Godkänn i appen. Kör gärna direkt efter grundinloggningen.", Entity.SERVICE, Request.NO_FORCE, null, null),
      new Case("passive", "Felhantering", "Passiv begäran (IsPassive)", "Utan befintlig session ska IdP:n svara med fel utan att visa något för användaren.",
          "Deployment Profile §5.3; SAML Core §3.4.1", "Ingen åtgärd. Svaret kommer direkt.", Entity.SERVICE, Request.PASSIVE, StatusCode.REQUESTER, NO_PASSIVE),
      new Case("loa3", "Felhantering", "Tillitsnivå som inte stöds", "Begäran om LoA3 ska avvisas med NoAuthnContext. Nivån får aldrig sänkas i tysthet.",
          "Deployment Profile §5.4.4", "Ingen åtgärd. Svaret kommer direkt.", Entity.SERVICE, Request.LOA3, StatusCode.REQUESTER, NO_CONTEXT),
      new Case("cancel", "Felhantering", "Användaren avbryter", "När användaren avbryter eller nekar ska tjänsten få statuskoden för avbrott och ingen assertion.",
          "Deployment Profile §6.4; Registry §3.1.4", "Välj Avbryt på sidan eller Neka i appen, och sedan Tillbaka till tjänsten.", Entity.SERVICE, Request.LOGIN, StatusCode.RESPONDER, CANCEL),
      new Case("sign", "Underskrift", "Underskrift med SignMessage och SAD", "Underskriftstjänsten skickar en text som ska visas (MustShow) och begär SAD. Svaret ska innehålla signMessageDigest för exakt texten och en SAD som är bunden till begäran. Därefter skapas en PAdES-signerad PDF.",
          "Deployment Profile §7; Signature Activation Protocol §3", "Läs texten i appen och välj Skriv under.", Entity.SIGNATURE_SERVICE, Request.SIGN, null, null),
      new Case("sign-pin", "Underskrift", "Stort åtagande med säkerhetskod", "Ett lånelöfte på 250 000 kr. Underskriftstjänsten kräver säkerhetskod; Face ID räcker inte. Svaret, SAD och PDF:en ska alla bära kodnivån.",
          "Deployment Profile §7; SAP §3 (SAD-loa)", "Läs texten, skriv säkerhetskoden och välj Skriv under.", Entity.SIGNATURE_SERVICE, Request.SIGN_PIN, null, null),
      new Case("sign-encrypted", "Underskrift", "Krypterat SignMessage", "Samma underskrift, men texten är krypterad till IdP:ns nyckel. Bara IdP:n kan läsa och visa den.",
          "DSS Extension §3.1.2", "Läs texten i appen och välj Skriv under.", Entity.SIGNATURE_SERVICE, Request.SIGN_ENCRYPTED, null, null),
      new Case("sign-html", "Underskrift", "Text som inte kan visas", "SignMessage i HTML med MustShow. Appen visar bara ren text, så IdP:n måste avbryta med fel i stället för att visa något annat.",
          "Deployment Profile §7.1.1", "Ingen åtgärd. Svaret kommer direkt.", Entity.SIGNATURE_SERVICE, Request.SIGN_HTML, StatusCode.RESPONDER, AUTHN_FAILED),
      new Case("sad-only", "Underskrift", "SAD utan text att visa", "En SADRequest utan SignMessage ska avvisas: SAD intygar att en visad text godkändes.",
          "Signature Activation Protocol §3.1", "Ingen åtgärd. Svaret kommer direkt.", Entity.SIGNATURE_SERVICE, Request.SAD_ONLY, StatusCode.RESPONDER, AUTHN_FAILED),
      new Case("sign-from-service", "Underskrift", "SignMessage från vanlig tjänst", "Bara tjänster med kategorin sigservice får begära underskrift. IdP:n ska ignorera texten och genomföra en vanlig inloggning utan signMessageDigest.",
          "Deployment Profile §7; Entity Categories §5", "Godkänn inloggningen i appen. Appen ska visa Logga in, inte Skriv under.", Entity.SERVICE, Request.SIGN_FROM_SERVICE, null, null));

  record Run(String owner, Case kase, AuthnRequest request, String relay, Instant created, String signMessage, byte[] document, String reference, String signRequestId) {}
  record Check(String label, boolean ok, String detail) {}
  record Report(String id, String owner, Case kase, boolean passed, List<Check> checks, List<String[]> facts, Instant at,
      PadesSigner.Signed signed, byte[] document, String reference, String evidence) {}

  private final Map<String, Run> runs = new HashMap<>();
  private final Map<String, Report> reports = new LinkedHashMap<>();
  private final String base, idpBase;
  private final AbstractAuthnRequestGenerator service, signature;
  private final EntityDescriptor idpMetadata;
  private final String serviceMetadata, signatureMetadata;
  private final LabResponseProcessor processor;
  private final PhoneBridge phone;
  private final MetadataResolver resolver;
  private final PadesSigner signer;
  /** Pinned IdP signing certificate, the same anchor as the SP's metadata. */
  private final X509Certificate idpCertificate;

  TestConsole(TestKeys keys, String base, String idpBase, EntityDescriptor idpMetadata, MetadataResolver resolver,
      LabResponseProcessor processor, PhoneBridge phone) throws Exception {
    this.base = base; this.idpBase = idpBase; this.idpMetadata = idpMetadata; this.resolver = resolver;
    this.processor = processor; this.phone = phone;
    serviceMetadata = Metadata.sp(keys, base, true);
    signatureMetadata = Metadata.signService(keys, base);
    service = generator(base + "/sp", Metadata.parse(serviceMetadata), keys);
    signature = generator(base + "/sign", Metadata.parse(signatureMetadata), keys);
    signer = new PadesSigner(Clock.systemUTC());
    idpCertificate = keys.certificate("idp");
  }
  private AbstractAuthnRequestGenerator generator(String entity, EntityDescriptor metadata, TestKeys keys) throws Exception {
    var generator = new AbstractAuthnRequestGenerator(entity, new OpenSamlCredential(keys.credential("sp"))) {
      @Override protected EntityDescriptor getSpMetadata() { return metadata; }
      @Override protected EntityDescriptor getIdpMetadata(String id) { return idpMetadata.getEntityID().equals(id) ? idpMetadata : null; }
    };
    generator.initialize();
    return generator;
  }

  boolean handle(HttpExchange x) throws IOException {
    String path = x.getRequestURI().getPath(), method = x.getRequestMethod();
    if (!(path.equals("/test") || path.startsWith("/test/") || path.equals("/sign") || path.startsWith("/sign/") || path.equals("/console.css"))) return false;
    try {
      if (method.equals("GET") && path.equals("/console.css")) asset(x, "/static/console/console.css", "text/css");
      else if (method.equals("GET") && path.equals("/test")) console(x);
      else if (method.equals("GET") && path.equals("/sign")) chooser(x);
      else if (method.equals("GET") && path.startsWith("/test/run/")) start(x, path.substring("/test/run/".length()));
      else if (method.equals("POST") && (path.equals("/test/acs") || path.equals("/sign/acs"))) receive(x, path);
      else if (method.equals("GET") && path.startsWith("/test/report/")) report(x, path.substring("/test/report/".length()));
      else if (method.equals("GET") && path.equals("/test/metadata/sp.xml")) bytes(x, serviceMetadata.getBytes(StandardCharsets.UTF_8), "application/samlmetadata+xml", null);
      else if (method.equals("GET") && path.equals("/test/metadata/sign.xml")) bytes(x, signatureMetadata.getBytes(StandardCharsets.UTF_8), "application/samlmetadata+xml", null);
      else if (method.equals("GET") && path.equals("/test/ca.pem")) bytes(x, PadesSigner.pem(signer.authority()).getBytes(StandardCharsets.US_ASCII), "application/x-pem-file", "openid-test-ca.pem");
      else page(x, 404, "Sidan finns inte", "<h1>Sidan finns inte</h1><p><a href='/test'>Till testkonsolen</a></p>");
    } catch (Exception e) {
      // Never echo SAML payloads, identities or exception text.
      page(x, 400, "Testet kunde inte köras", "<h1>Testet kunde inte köras</h1><p>Begäran var ogiltig eller har gått ut.</p><p><a class='button' href='/test'>Till testkonsolen</a></p>");
    }
    return true;
  }

  // ---------------------------------------------------------------- pages

  /** Two documents, two levels: like BankID, the service decides when Face ID is enough. */
  private void chooser(HttpExchange x) throws IOException {
    owner(x);
    page(x, 200, "Skriv under", "<header class='hero'><p class='eyebrow'>openID kontotjänst · underskrift</p><h1>Välj vad du vill skriva under</h1>"
        + "<p class='lead'>Tjänsten bestämmer hur säker underskriften måste vara. Små åtaganden räcker med Face ID. Stora kräver även din säkerhetskod.</p></header>"
        + "<div class='cards'><article class='card'><div class='card-head'><h3>Avtal om provtjänst</h3><span class='badge'>Face ID</span></div>"
        + "<p>Ett litet åtagande. Du läser texten i appen och skriver under med Face ID.</p><p class='actions'><a class='button' href='/test/run/sign'>Skriv under avtalet</a></p></article>"
        + "<article class='card'><div class='card-head'><h3>Lånelöfte 250 000 kr</h3><span class='badge ok'>Säkerhetskod</span></div>"
        + "<p>Ett stort åtagande. Appen kräver din sexsiffriga säkerhetskod utöver Face ID. Fem fel spärrar koden.</p><p class='actions'><a class='button' href='/test/run/sign-pin'>Skriv under lånelöftet</a></p></article></div>"
        + "<p class='ref'><a href='/test'>Alla tester</a></p>");
  }

  private void console(HttpExchange x) throws IOException {
    String owner = owner(x);
    var html = new StringBuilder();
    html.append("<header class='hero'><p class='eyebrow'>openID kontotjänst · testkonsol</p><h1>Prova IdP:n mot Sweden Connects tekniska ramverk</h1>")
        .append("<p class='lead'>Varje test skickar en riktig, signerad SAML-begäran till openID och kontrollerar svaret punkt för punkt. ")
        .append("Du godkänner med appen när testet kräver det. Resultaten är en egen teknisk kontroll, inte Diggs granskning.</p></header>");
    String group = null;
    for (Case c : CASES) {
      if (!c.group().equals(group)) {
        if (group != null) html.append("</div></section>");
        group = c.group();
        html.append("<section class='group'><h2>").append(group).append("</h2><div class='cards'>");
      }
      Report last = latest(owner, c);
      html.append("<article class='card'><div class='card-head'><h3>").append(esc(c.title())).append("</h3>")
          .append(last == null ? "<span class='badge'>Ej kört</span>" : last.passed() ? "<span class='badge ok'>Godkänt</span>" : "<span class='badge fail'>Underkänt</span>")
          .append("</div><p>").append(esc(c.purpose())).append("</p><p class='ref'>").append(esc(c.reference())).append("</p>")
          .append("<p class='expect'><strong>Förväntat:</strong> ").append(c.expectsSuccess() ? "lyckat svar" : esc(short_(c.expectedTop()) + " / " + short_(c.expectedSecond()))).append("</p>")
          .append("<p class='do'>").append(esc(c.instruction())).append("</p><p class='actions'><a class='button' href='/test/run/").append(c.id()).append("'>Kör testet</a>");
      if (last != null) html.append(" <a href='/test/report/").append(last.id()).append("'>Senaste resultat</a>");
      html.append("</p></article>");
    }
    html.append("</div></section>");
    html.append("<section class='group'><h2>OpenID Connect</h2><div class='cards'>")
        .append("<article class='card'><div class='card-head'><h3>Authorization Code med PKCE</h3></div><p>Samma godkännande i appen via OIDC: S256 PKCE, state, nonce, private_key_jwt och färsk auth_time.</p><p class='ref'>Swedish OIDC Profile 1.0 · Sweden Connect OIDC Profile 1.1</p><p class='actions'><a class='button' href='/oidc/login'>Kör testet</a></p></article>")
        .append("<article class='card'><div class='card-head'><h3>Krav på LoA3 via OIDC</h3></div><p>Ett essentiellt acr-krav på LoA3 ska stoppas innan något godkännande skapas.</p><p class='ref'>Sweden Connect OIDC Profile §3.1.1</p><p class='actions'><a class='button' href='/oidc/login?loa=3'>Kör testet</a></p></article>")
        .append("</div></section>");
    html.append("<section class='group'><h2>Metadata och nycklar</h2><div class='cards'><article class='card'><p>Metadata som IdP:n använder för att lita på tjänsterna. Underskriftstjänsten har kategorin <code>sigservice</code>; IdP:n annonserar <code>scal2</code>.</p><p class='actions'>")
        .append("<a href='/test/metadata/sp.xml'>Kontotjänstens metadata</a> · <a href='/test/metadata/sign.xml'>Underskriftstjänstens metadata</a> · <a href='").append(esc(idpBase)).append("/saml2/metadata'>IdP:ns metadata</a> · <a href='/test/ca.pem'>Test-CA för underskrifter</a></p></article></div></section>");
    page(x, 200, "Testkonsol", html.toString());
  }

  private void start(HttpExchange x, String id) throws Exception {
    if (x.getRequestURI().getRawQuery() != null) throw new IllegalArgumentException("No parameters");
    Case c = CASES.stream().filter(k -> k.id().equals(id)).findFirst().orElseThrow();
    String owner = owner(x), relay = token(16), signRequestId = token(16), reference = reference();
    byte[] document = null; String message = null;
    if (c.entity() == Entity.SIGNATURE_SERVICE || c.request() == Request.SIGN_FROM_SERVICE) {
      Instant now = Instant.now();
      boolean high = c.request() == Request.SIGN_PIN;
      document = PadesSigner.demoDocument(reference, now, high);
      String digest = PadesSigner.sha256Hex(document);
      message = "Jag skriver under ”" + (high ? "Lånelöfte 250 000 kr" : "Avtal om provtjänst") + "”, dokument " + reference + ".\n"
          + "Kontrollsumma (SHA-256): " + digest.substring(0, 8) + " " + digest.substring(8, 16) + " … " + digest.substring(56) + "\n"
          + "Underskriften är en test utan rättslig verkan.";
    }
    String text = message;
    var generator = c.entity() == Entity.SIGNATURE_SERVICE ? signature : service;
    String acs = c.entity() == Entity.SIGNATURE_SERVICE ? base + "/sign/acs" : base + "/test/acs";
    var http = generator.generateAuthnRequest(idpMetadata, relay, new AuthnRequestGeneratorContext() {
      @Override public String getPreferredBinding() { return SAMLConstants.SAML2_REDIRECT_BINDING_URI; }
      @Override public AuthnRequestCustomizer getAuthnRequestCustomizer() { return request -> customize(request, c, acs, text, signRequestId); }
    });
    synchronized (this) {
      runs.values().removeIf(r -> r.created().isBefore(Instant.now().minusSeconds(180)));
      if (runs.size() >= 256) throw new IllegalStateException("Too many runs");
      runs.put(owner, new Run(owner, c, http.getRequest(), relay, Instant.now(), message, document, reference, signRequestId));
    }
    RelyingParty.redirect(x, http.getSendUrl());
  }

  private void customize(AuthnRequest request, Case c, String acs, String message, String signRequestId) {
    request.setAssertionConsumerServiceIndex(null);
    request.setAssertionConsumerServiceURL(acs);
    request.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
    request.setForceAuthn(c.request() != Request.NO_FORCE && c.request() != Request.PASSIVE);
    request.setIsPassive(c.request() == Request.PASSIVE ? Boolean.TRUE : null);
    request.setRequestedAuthnContext(RequestedAuthnContextBuilder.builder().comparison(AuthnContextComparisonTypeEnumeration.EXACT)
        .authnContextClassRefs(c.context()).build());
    var extensions = (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
    if (message != null && c.request() != Request.SAD_ONLY) {
      SignMessage signMessage = SignMessageBuilder.builder().message(message).displayEntity(idpMetadata.getEntityID()).mustShow(true)
          .mimeType(c.request() == Request.SIGN_HTML ? SignMessageMimeTypeEnum.TEXT_HTML : SignMessageMimeTypeEnum.TEXT).build();
      if (c.request() == Request.SIGN_HTML) signMessage.getMessage().setContent("<p>" + HtmlUtils.htmlEscape(message) + "</p>");
      if (c.request() == Request.SIGN_ENCRYPTED) {
        try { new SignMessageEncrypter(new SAMLObjectEncrypter(resolver)).encrypt(signMessage, idpMetadata.getEntityID()); }
        catch (Exception e) { throw new IllegalStateException("Sign message encryption failed", e); }
      }
      extensions.getUnknownXMLObjects().add(signMessage);
    }
    if (c.entity() == Entity.SIGNATURE_SERVICE || c.request() == Request.SIGN_FROM_SERVICE) {
      extensions.getUnknownXMLObjects().add(SADRequestBuilder.builder().id(token(16)).requesterID(request.getIssuer().getValue())
          .signRequestID(signRequestId).docCount(1).requestedVersion(SADVersion.VERSION_10).build());
    }
    request.setExtensions(extensions.getUnknownXMLObjects().isEmpty() ? null : extensions);
  }

  private void receive(HttpExchange x, String path) throws Exception {
    if (!idpBase.equals(x.getRequestHeaders().getFirst("Origin"))) throw new IllegalArgumentException("Origin");
    Map<String, String> form = RelyingParty.form(x);
    String owner = RelyingParty.cookie(x, COOKIE);
    Run run;
    synchronized (this) { run = runs.remove(owner); }
    if (run == null || run.created().isBefore(Instant.now().minusSeconds(180))) {
      page(x, 400, "Testet har gått ut", "<h1>Testet har gått ut eller redan avslutats</h1><p>Starta testet igen i samma webbläsare.</p><p><a class='button' href='/test'>Till testkonsolen</a></p>");
      return;
    }
    boolean signatureService = run.kase().entity() == Entity.SIGNATURE_SERVICE;
    if (!path.equals(signatureService ? "/sign/acs" : "/test/acs")) throw new IllegalArgumentException("ACS");
    String encoded = Objects.requireNonNull(form.get("SAMLResponse"));
    var input = input(run, base + path);
    var checks = new ArrayList<Check>(); var facts = new ArrayList<String[]>();
    PadesSigner.Signed signed = null; String evidence = null;
    facts.add(new String[]{"Begäran", run.request().getID()});
    facts.add(new String[]{"Avsändare (SP)", run.request().getIssuer().getValue()});
    ResponseProcessingResult result = null; Status status = null;
    try { result = processor.processSamlResponse(encoded, form.get("RelayState"), input, null); }
    catch (ResponseStatusErrorException e) { status = e.getStatus(); }
    catch (ResponseProcessingException e) {
      checks.add(new Check("Svaret klarar tjänstens SAML-validering", false, "Signatur, kryptering, mottagare, tid eller bindning till begäran stämde inte."));
    }
    var response = decode(encoded);
    if (response != null) {
      facts.add(new String[]{"Svar", response.getID()});
      facts.add(new String[]{"Status", statusText(response.getStatus())});
    }
    if (status != null || (result == null && response != null && !StatusCode.SUCCESS.equals(code(response.getStatus(), 0)))) {
      Status s = status != null ? status : response.getStatus();
      checks.add(new Check("Svaret är ett felsvar", !run.kase().expectsSuccess(), statusText(s)));
      if (!run.kase().expectsSuccess()) {
        checks.add(new Check("Statuskod på första nivån är " + short_(run.kase().expectedTop()), run.kase().expectedTop().equals(code(s, 0)), String.valueOf(code(s, 0))));
        checks.add(new Check("Statuskod på andra nivån är " + short_(run.kase().expectedSecond()), run.kase().expectedSecond().equals(code(s, 1)), String.valueOf(code(s, 1))));
      }
      checks.add(new Check("Felsvaret innehåller ingen assertion", response != null && response.getAssertions().isEmpty() && response.getEncryptedAssertions().isEmpty(), ""));
      checks.add(new Check("Svaret är bundet till begäran (InResponseTo)", response != null && run.request().getID().equals(response.getInResponseTo()), ""));
    } else if (result != null) {
      var assertion = result.getAssertion();
      checks.add(new Check("Svaret är lyckat", run.kase().expectsSuccess(), "Status Success"));
      checks.add(new Check("Signerat och krypterat svar validerat", true, "Sweden Connect-processorn kräver krypterad, signerad assertion, rätt mottagare, InResponseTo, RelayState och giltighetstid."));
      checks.add(new Check("Utfärdare är openID IdP", idpMetadata.getEntityID().equals(result.getIssuer()), result.getIssuer()));
      checks.add(new Check("Mottagare (Audience) är den begärande tjänsten", audience(assertion, run.request().getIssuer().getValue()), run.request().getIssuer().getValue()));
      checks.add(new Check(run.kase().securityCode() ? "Säkerhetskoden kontrollerades (kodnivån intygas)" : "Autentiseringskontext är den begärda",
          run.kase().context().equals(result.getAuthnContextClassUri()), result.getAuthnContextClassUri()));
      boolean fresh = result.getAuthnInstant() != null && !result.getAuthnInstant().isBefore(run.request().getIssueInstant().minusSeconds(5));
      checks.add(new Check("Ny legitimering, ingen återanvänd session", fresh, "AuthnInstant " + time(result.getAuthnInstant()) + ", begäran " + time(run.request().getIssueInstant())));
      var identityAttributes = new ArrayList<Attribute>(); Attribute digest = null, sad = null;
      for (var a : result.getAttributes()) {
        if (AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST.equals(a.getName())) digest = a;
        else if (AttributeConstants.ATTRIBUTE_NAME_SAD.equals(a.getName())) sad = a;
        else identityAttributes.add(a);
      }
      PhoneIdentity person = null;
      try { person = PhoneIdentity.fromAttributes(identityAttributes); }
      catch (IllegalArgumentException e) { /* reported below */ }
      checks.add(new Check("Alla begärda attribut och inga andra", person != null, identityAttributes.size() + " identitetsattribut"));
      if (person != null) {
        checks.add(new Check("Ditt ID är aktivt i registret just nu", phone.active(person), "Spärr eller utgång stoppar resultatet"));
        facts.add(new String[]{"Namn", person.displayName()});
        facts.add(new String[]{"Födelsedatum (MRZ)", person.birthDateMrz()});
        facts.add(new String[]{"Tjänstesubjekt", person.subject().substring(0, 16) + "…"});
      }
      facts.add(new String[]{"Assertion", assertion.getID()});
      facts.add(new String[]{"Legitimerad", time(result.getAuthnInstant())});
      try {
        processor.processSamlResponse(encoded, form.get("RelayState"), input, null);
        checks.add(new Check("Samma svar kan inte användas igen", false, "Återspelningen godtogs"));
      } catch (Exception e) { checks.add(new Check("Samma svar kan inte användas igen", true, "Andra försöket avvisades")); }

      if (run.kase().signs()) {
        String expected = expectedDigest(run.signMessage());
        String actual = digest == null ? null : AttributeUtils.getAttributeStringValue(digest);
        checks.add(new Check("signMessageDigest gäller exakt den visade texten", expected.equals(actual), actual == null ? "saknas" : actual.substring(0, Math.min(60, actual.length())) + "…"));
        SAD validated = null; String sadError = "Ogiltig eller saknad SAD";
        try { validated = new SADParser.SADValidator(idpCertificate).validate(run.request(), assertion); }
        catch (SADValidationException e) { sadError = "SAD avvisad: " + e.getErrorCode(); }
        catch (Exception e) { sadError = "SAD kunde inte kontrolleras"; }
        checks.add(new Check("SAD är signerad av IdP:n och bunden till begäran", validated != null && sad != null,
            validated == null ? sadError : "aud " + validated.getAudience() + ", inResponseTo " + validated.getSeElnSadext().getInResponseTo()));
        if (validated != null) {
          checks.add(new Check("SAD gäller ett dokument och rätt underskriftsbegäran", Integer.valueOf(1).equals(validated.getSeElnSadext().getNumberOfDocuments())
              && run.signRequestId().equals(validated.getSeElnSadext().getRequestID()), "SignRequestID " + validated.getSeElnSadext().getRequestID()));
          facts.add(new String[]{"SAD (jti)", validated.getJwtId()});
        }
        boolean ready = person != null && expected.equals(actual) && validated != null && checks.stream().allMatch(Check::ok);
        if (ready) {
          var who = new PadesSigner.Signer(person.displayName(), person.subject(), person.birthDateMrz());
          signed = signer.sign(run.document(), who, run.signRequestId());
          checks.add(new Check("PDF:en är underskriven (PAdES-B-B) och kontrollerad", true, "Certifikat utfärdat till " + person.displayName() + " av test-CA:n"));
          facts.add(new String[]{"Dokumentets SHA-256", signed.documentSha256()});
          facts.add(new String[]{"Underskriven fil, SHA-256", signed.signedSha256()});
          evidence = evidence(run, response, assertion, actual, sad == null ? null : AttributeUtils.getAttributeStringValue(sad), signed);
        } else checks.add(new Check("PDF:en skrivs bara under när alla kontroller ovan är godkända", false, "Ingen underskrift skapades"));
      } else if (run.kase().request() == Request.SIGN_FROM_SERVICE) {
        checks.add(new Check("Ingen signMessageDigest till en vanlig tjänst", digest == null, digest == null ? "saknas, som väntat" : "utfärdades"));
        checks.add(new Check("Ingen SAD till en vanlig tjänst", sad == null, sad == null ? "saknas, som väntat" : "utfärdades"));
      }
    } else checks.add(new Check("Ett tolkningsbart svar togs emot", false, ""));
    boolean passed = !checks.isEmpty() && checks.stream().allMatch(Check::ok);
    String id = token(16);
    synchronized (this) {
      reports.values().removeIf(r -> r.at().isBefore(Instant.now().minus(Duration.ofMinutes(30))));
      while (reports.size() >= 512) reports.remove(reports.keySet().iterator().next());
      reports.put(id, new Report(id, run.owner(), run.kase(), passed, checks, facts, Instant.now(), signed, run.document(), run.reference(), evidence));
    }
    RelyingParty.redirect(x, "/test/report/" + id);
  }

  private void report(HttpExchange x, String rest) throws Exception {
    String[] parts = rest.split("/", 2);
    Report r;
    synchronized (this) { r = reports.get(parts[0]); }
    if (r == null || !r.owner().equals(RelyingParty.cookie(x, COOKIE))) {
      page(x, 404, "Resultatet finns inte", "<h1>Resultatet finns inte längre</h1><p>Resultat sparas i 30 minuter och bara i webbläsaren som körde testet.</p><p><a class='button' href='/test'>Till testkonsolen</a></p>");
      return;
    }
    if (parts.length == 2) {
      switch (parts[1]) {
        case "signed.pdf" -> { if (r.signed() == null) throw new IllegalStateException(); bytes(x, r.signed().pdf(), "application/pdf", "avtal-" + r.reference() + "-underskrivet.pdf"); }
        case "document.pdf" -> { if (r.document() == null) throw new IllegalStateException(); bytes(x, r.document(), "application/pdf", "avtal-" + r.reference() + ".pdf"); }
        case "evidence.json" -> { if (r.evidence() == null) throw new IllegalStateException(); bytes(x, r.evidence().getBytes(StandardCharsets.UTF_8), "application/json", "underskrift-" + r.reference() + ".json"); }
        default -> throw new IllegalArgumentException();
      }
      return;
    }
    var html = new StringBuilder();
    html.append("<p class='eyebrow'><a href='/test'>Testkonsol</a> · ").append(esc(r.kase().group())).append("</p>")
        .append("<div class='verdict ").append(r.passed() ? "ok" : "fail").append("'><span class='mark' aria-hidden='true'>").append(r.passed() ? "✓" : "✕").append("</span><div><h1>")
        .append(esc(r.kase().title())).append("</h1><p>").append(r.passed() ? "Godkänt – IdP:n betedde sig som ramverket kräver." : "Underkänt – se kontrollerna nedan.").append("</p></div></div>");
    if (r.signed() != null) {
      html.append("<section class='signed'><h2>Dokumentet är underskrivet</h2><p>PDF:en visar ett underskriftskvitto med namn, tid och dokumentets kontrollsumma. ")
          .append("Kvittot omfattas av den digitala PAdES-signaturen. Utseendet kan kopieras; kontrollera själva PDF-filen i en läsare eller valideringstjänst med signaturstöd.</p>")
          .append("<p>Testutfärdaren är inte betrodd. En synlig ruta eller lokal tillit till testcertifikatet gör inte underskriften betrodd hos andra. ")
          .append("Tiden kommer från serverklockan, inte från en betrodd tidsstämplingstjänst.</p><p class='actions'>")
          .append("<a class='button' href='/test/report/").append(r.id()).append("/signed.pdf'>Hämta underskriven PDF</a> ")
          .append("<a href='/test/report/").append(r.id()).append("/document.pdf'>Originalet</a> · ")
          .append("<a href='/test/report/").append(r.id()).append("/evidence.json'>Underskriftsbevis (JSON)</a> · <a href='/test/ca.pem'>Test-CA</a></p></section>");
    }
    html.append("<section><h2>Kontroller</h2><ul class='checks'>");
    for (Check c : r.checks()) html.append("<li class='").append(c.ok() ? "ok" : "fail").append("'><span class='mark' aria-hidden='true'>").append(c.ok() ? "✓" : "✕")
        .append("</span><div><strong>").append(esc(c.label())).append("</strong>").append(c.detail().isEmpty() ? "" : "<small>" + esc(c.detail()) + "</small>")
        .append("</div><span class='sr'>").append(c.ok() ? "godkänd" : "underkänd").append("</span></li>");
    html.append("</ul></section><section><h2>Uppgifter från svaret</h2><dl class='facts'>");
    for (String[] f : r.facts()) html.append("<dt>").append(esc(f[0])).append("</dt><dd>").append(esc(f[1])).append("</dd>");
    html.append("</dl><p class='ref'>Referens: ").append(esc(r.kase().reference())).append(" · Kört ").append(time(r.at())).append("</p></section>")
        .append("<p class='actions'><a class='button' href='/test/run/").append(r.kase().id()).append("'>Kör igen</a> <a href='/test'>Alla tester</a></p>");
    page(x, 200, r.kase().title(), html.toString());
  }

  // ---------------------------------------------------------------- helpers

  private ResponseProcessingInput input(Run run, String receive) {
    Instant received = Instant.now();
    return new ResponseProcessingInput() {
      @Override public AuthnRequest getAuthnRequest(String id) { return run.request().getID().equals(id) ? run.request() : null; }
      @Override public String getRequestRelayState(String id) { return run.request().getID().equals(id) ? run.relay() : null; }
      @Override public String getReceiveURL() { return receive; }
      @Override public Instant getReceiveInstant() { return received; }
      @Override public String getClientIpAddress() { return null; }
      @Override public X509Certificate getClientCertificate() { return null; }
    };
  }
  /** What the IdP must assert: the digest of the Message element that it displayed. */
  static String expectedDigest(String message) {
    var element = (se.swedenconnect.opensaml.sweid.saml2.signservice.dss.Message) XMLObjectSupport.buildXMLObject(
        se.swedenconnect.opensaml.sweid.saml2.signservice.dss.Message.DEFAULT_ELEMENT_NAME);
    element.setContent(message);
    return AttributeUtils.getAttributeStringValue(new SignMessageDigestIssuer().create(element));
  }
  private static boolean audience(Assertion assertion, String entity) {
    return assertion.getConditions() != null && assertion.getConditions().getAudienceRestrictions().stream()
        .flatMap(a -> a.getAudiences().stream()).anyMatch(a -> entity.equals(a.getURI()));
  }
  private static Response decode(String encoded) {
    try {
      var xml = Base64.getDecoder().decode(encoded);
      return (Response) XMLObjectSupport.unmarshallFromInputStream(org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.getParserPool(), new ByteArrayInputStream(xml));
    } catch (Exception e) { return null; }
  }
  private static String code(Status status, int level) {
    if (status == null || status.getStatusCode() == null) return null;
    var code = status.getStatusCode();
    return level == 0 ? code.getValue() : code.getStatusCode() == null ? null : code.getStatusCode().getValue();
  }
  private static String statusText(Status status) {
    if (status == null) return "saknas";
    String text = short_(code(status, 0)) + (code(status, 1) != null ? " / " + short_(code(status, 1)) : "");
    return status.getStatusMessage() != null && status.getStatusMessage().getValue() != null && status.getStatusMessage().getValue().length() < 120
        ? text + " – " + status.getStatusMessage().getValue() : text;
  }
  private static String short_(String uri) {
    if (uri == null) return "saknas";
    int i = Math.max(uri.lastIndexOf(':'), uri.lastIndexOf('/'));
    return i >= 0 && i < uri.length() - 1 ? uri.substring(i + 1) : uri;
  }
  private String evidence(Run run, Response response, Assertion assertion, String digest, String sad, PadesSigner.Signed signed) throws Exception {
    var map = new LinkedHashMap<String, Object>();
    map.put("profile", "openID test signature service; not a qualified or production signature");
    map.put("document", Map.of("reference", run.reference(), "sha256", signed.documentSha256()));
    map.put("signedFileSha256", signed.signedSha256());
    map.put("signMessage", run.signMessage());
    map.put("signMessageDigest", digest);
    map.put("authnRequestId", run.request().getID());
    map.put("signRequestId", run.signRequestId());
    map.put("responseId", response.getID());
    map.put("assertionId", assertion.getID());
    map.put("idp", idpMetadata.getEntityID());
    map.put("signatureService", run.request().getIssuer().getValue());
    map.put("sad", sad);
    map.put("signerCertificate", PadesSigner.pem(signed.signer()));
    map.put("testCa", PadesSigner.pem(signed.authority()));
    map.put("signedAt", signed.time().toString());
    return new com.fasterxml.jackson.databind.ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(map);
  }
  private Report latest(String owner, Case c) {
    synchronized (this) {
      Report found = null;
      for (var r : reports.values()) if (r.owner().equals(owner) && r.kase().id().equals(c.id())) found = r;
      return found;
    }
  }
  private String owner(HttpExchange x) {
    String value = RelyingParty.cookie(x, COOKIE);
    if (!value.matches("[A-Za-z0-9_-]{22}")) {
      value = token(16);
      x.getResponseHeaders().add("Set-Cookie", COOKIE + "=" + value + "; Path=/; Secure; HttpOnly; SameSite=Lax");
    }
    return value;
  }
  private static String token(int bytes) {
    byte[] value = new byte[bytes]; RANDOM.nextBytes(value);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
  }
  private static String reference() {
    return "OID-" + Integer.toString(100000 + RANDOM.nextInt(900000));
  }
  private static String time(Instant instant) {
    return instant == null ? "saknas" : DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").format(instant.atZone(ZONE));
  }
  private static String esc(String value) { return HtmlUtils.htmlEscape(value == null ? "" : value); }
  private void asset(HttpExchange x, String resource, String type) throws IOException {
    byte[] data;
    try (var stream = TestConsole.class.getResourceAsStream(resource)) { data = Objects.requireNonNull(stream).readAllBytes(); }
    bytes(x, data, type, null);
  }
  private static void bytes(HttpExchange x, byte[] data, String type, String download) throws IOException {
    RelyingParty.headers(x); x.getResponseHeaders().set("Content-Type", type);
    if (download != null) x.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"" + download + "\"");
    x.sendResponseHeaders(200, data.length); x.getResponseBody().write(data);
  }
  static void page(HttpExchange x, int status, String title, String body) throws IOException {
    RelyingParty.headers(x); x.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
    byte[] bytes = ("<!doctype html><html lang='sv'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>"
        + esc(title) + " · openID</title><link rel='stylesheet' href='/console.css'></head><body><main>" + body
        + "</main><footer>openID testmiljö · inget Digg-godkännande · identiteter och underskrifter här har ingen rättslig verkan</footer></body></html>").getBytes(StandardCharsets.UTF_8);
    x.sendResponseHeaders(status, bytes.length); x.getResponseBody().write(bytes);
  }
}
