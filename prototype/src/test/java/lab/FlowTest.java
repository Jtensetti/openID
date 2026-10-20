package lab;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.net.ServerSocket;
import java.util.Map;
import java.util.HashMap;
import java.time.Instant;
import java.net.http.*;
import java.net.URI;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import org.opensaml.saml.saml2.core.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class FlowTest {
  @TempDir static Path directory;
  Lab lab;
  @BeforeAll void start() throws Exception {
    TestKeys.initialize(directory.resolve("keys"));
    SyntheticRegistry.initialize(directory.resolve("keys"));
    lab = new Lab(directory.resolve("keys"), freePort(), freePort(), SyntheticRegistry.open(directory.resolve("keys"), java.time.Clock.systemUTC()));
  }
  @AfterAll void stop() { if (lab != null) lab.close(); }
  static int freePort() throws Exception { try (var s = new ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))) { return s.getLocalPort(); } }
  @Test void readinessUsesThePersistentRegistry() throws Exception {
    var b = new Browser(lab); assertEquals(200, b.get(lab.spBase + "/health/ready").statusCode());
  }

  @Test @Order(1) void signedEncryptedLoginWorks() throws Exception {
    var b = new Browser(lab);
    var page = b.start();
    assertEquals(200, page.statusCode(), page.body());
    assertEquals("strict-origin", page.headers().firstValue("Referrer-Policy").orElseThrow());
    assertTrue(page.body().contains("Identitetskontrollen är simulerad"), page.body());
    assertTrue(page.body().contains(lab.spBase + "/sp"));
    var response = b.approve(page, Map.of());
    assertEquals(200, response.statusCode(), response.body());
    assertEquals("strict-origin", response.headers().firstValue("Referrer-Policy").orElseThrow());
    assertTrue(Browser.hidden(response.body()).containsKey("SAMLResponse"), response.body());
    var saml = SamlTestMessages.decode(Browser.hidden(response.body()).get("SAMLResponse"));
    assertTrue(saml.isSigned()); assertEquals(1, saml.getEncryptedAssertions().size()); assertTrue(saml.getAssertions().isEmpty());
    var assertion = SamlTestMessages.decrypt(lab, saml);
    assertTrue(assertion.isSigned()); assertEquals(Metadata.LAB_CONTEXT, assertion.getAuthnStatements().getFirst().getAuthnContext().getAuthnContextClassRef().getURI());
    var result = b.receive(response);
    assertEquals(200, result.statusCode(), result.body());
    assertTrue(result.body().contains("SYNTHETIC-alice"), result.body());
  }

  @ParameterizedTest @ValueSource(strings={"TEST-CREDENTIAL-revoked", "TEST-CREDENTIAL-expired", "TEST-CREDENTIAL-unknown", "REAL-IDENTITY"})
  void invalidCredentialsCannotLogin(String credential) throws Exception {
    var b = new Browser(lab); var response = b.approve(b.start(), Map.of("credential", credential));
    assertDenied(b, response);
  }
  @Test void cancellationCannotLogin() throws Exception { var b = new Browser(lab); assertDenied(b, b.approve(b.start(), Map.of("action", "cancel"))); }
  @Test void simulationMustBeAcknowledged() throws Exception { var b = new Browser(lab); assertDenied(b, b.approve(b.start(), Map.of("simulatedProofing", ""))); }
  @Test void approvalRequiresCsrf() throws Exception {
    var b = new Browser(lab); var form = Browser.hidden(b.start().body()); form.remove("_csrf"); form.put("action", "approve");
    assertEquals(403, b.post(lab.idpBase + "/lab", form, lab.idpBase).statusCode());
  }
  @Test void approvalRequiresSameOrigin() throws Exception {
    var b = new Browser(lab); var form = Browser.hidden(b.start().body()); form.put("action", "approve");
    assertEquals(403, b.post(lab.idpBase + "/lab", form, "https://attacker.invalid").statusCode());
  }
  @Test void authnIdIsBoundToBrowserSession() throws Exception {
    var a = new Browser(lab); var pageA = a.start(); var b = new Browser(lab); var pageB = b.start();
    var result = b.approve(pageB, Map.of("authnId", Browser.hidden(pageA.body()).get("authnId")));
    assertEquals(400, result.statusCode()); assertEquals(401, b.get(lab.spBase + "/me").statusCode());
  }
  @Test void assertionIsBoundToBrowserSession() throws Exception {
    var a = new Browser(lab); var response = a.approve(a.start(), Map.of());
    var b = new Browser(lab); b.start();
    assertEquals(400, b.receive(response).statusCode()); assertEquals(401, b.get(lab.spBase + "/me").statusCode());
    assertEquals(200, a.receive(response).statusCode());
  }
  @Test void relayStateCannotBeReplaced() throws Exception {
    var b = new Browser(lab); var response = b.approve(b.start(), Map.of()); var form = Browser.hidden(response.body()); form.put("RelayState", "unbound");
    assertEquals(400, b.post(lab.spBase + "/acs", form, lab.idpBase).statusCode());
  }
  @Test void requestCannotBeReplayed() throws Exception {
    var b = new Browser(lab); var request = lab.sp.generate("test-relay", r -> {});
    assertTrue(b.follow(b.get(request.getSendUrl())).body().contains("Godkänn testinloggning"));
    assertFalse(b.follow(b.get(request.getSendUrl())).body().contains("Godkänn testinloggning"));
  }
  @Test void approvalCannotBeReplayed() throws Exception {
    var b = new Browser(lab); var page = b.start(); var response = b.approve(page, Map.of()); assertEquals(200, b.receive(response).statusCode());
    assertEquals(400, b.approve(page, Map.of()).statusCode());
  }
  @Test void responseCannotBeReplayed() throws Exception {
    long before = lab.registry.outcomes().stream().filter(e -> e.outcome() == OfflineReport.Outcome.SUCCESS).count();
    var b = new Browser(lab); var response = b.approve(b.start(), Map.of()); assertEquals(200, b.receive(response).statusCode());
    assertEquals(400, b.receive(response).statusCode());
    assertEquals(before + 1, lab.registry.outcomes().stream().filter(e -> e.outcome() == OfflineReport.Outcome.SUCCESS).count());
  }
  @Test void parallelResponseConsumptionSucceedsOnce() throws Exception {
    var b = new Browser(lab); var response = b.approve(b.start(), Map.of());
    String cookie = b.cookies.getCookieStore().getCookies().stream().filter(c -> c.getName().equals(RelyingParty.COOKIE)).findFirst().orElseThrow().getValue();
    String body = Browser.hidden(response.body()).entrySet().stream().map(e -> Browser.enc(e.getKey()) + "=" + Browser.enc(e.getValue())).collect(java.util.stream.Collectors.joining("&"));
    var request = HttpRequest.newBuilder(URI.create(lab.spBase + "/acs")).header("Cookie", RelyingParty.COOKIE + "=" + cookie)
        .header("Origin", lab.idpBase).header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(body)).build();
    try (var client = HttpClient.newBuilder().sslContext(lab.keys.sslContext()).build()) {
      var a = client.sendAsync(request, HttpResponse.BodyHandlers.ofString()); var c = client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
      var codes = java.util.List.of(a.get(10, TimeUnit.SECONDS).statusCode(), c.get(10, TimeUnit.SECONDS).statusCode());
      assertEquals(1, codes.stream().filter(n -> n == 303).count()); assertEquals(1, codes.stream().filter(n -> n == 400).count());
    }
  }
  @Test void unregisteredAcsIsDeniedEvenWhenRequestIsSigned() throws Exception { denyRequest(r -> r.setAssertionConsumerServiceURL("https://attacker.invalid/acs")); }
  @Test void wrongIssuerIsDeniedEvenWhenRequestIsSigned() throws Exception { denyRequest(r -> r.getIssuer().setValue("https://attacker.invalid/sp")); }
  @Test void staleRequestIsDenied() throws Exception { denyRequest(r -> r.setIssueInstant(Instant.now().minusSeconds(120))); }
  @Test void futureRequestIsDenied() throws Exception { denyRequest(r -> r.setIssueInstant(Instant.now().plusSeconds(120))); }
  @Test void realAssuranceLevelCannotBeRequested() throws Exception {
    denyRequest(r -> r.getRequestedAuthnContext().getAuthnContextClassRefs().getFirst().setURI("http://id.elegnamnden.se/loa/1.0/loa3"));
  }
  @Test void unsignedRequestIsDenied() throws Exception {
    var req = lab.sp.generate("test-relay", r -> {}); var b = new Browser(lab);
    String url = req.getSendUrl().replaceAll("&SigAlg=[^&]*", "").replaceAll("&Signature=[^&]*", "");
    assertFalse(b.follow(b.get(url)).body().contains("Godkänn testinloggning"));
  }
  @Test void corruptRequestSignatureIsDenied() throws Exception {
    var req = lab.sp.generate("test-relay", r -> {}); var b = new Browser(lab);
    String url = req.getSendUrl().replaceAll("Signature=[^&]*", "Signature=AAAA");
    assertFalse(b.follow(b.get(url)).body().contains("Godkänn testinloggning"));
  }
  @Test void corruptResponseSignatureIsDenied() throws Exception {
    var b = new Browser(lab); var response = b.approve(b.start(), Map.of()); var form = Browser.hidden(response.body());
    var saml = SamlTestMessages.decode(form.get("SAMLResponse")); saml.getIssuer().setValue(lab.idpBase + "/changed");
    form.put("SAMLResponse", SamlTestMessages.encode(saml)); assertEquals(400, b.post(lab.spBase + "/acs", form, lab.idpBase).statusCode());
  }
  @Test void validlyResignedControlStillWorks() throws Exception { mutate(r -> {}, a -> {}, "idp", 303); }
  @Test void wrongTrustAnchorIsDenied() throws Exception { mutate(r -> {}, a -> {}, "sp", 400); }
  @Test void wrongAudienceWithValidSignatureIsDenied() throws Exception { mutate(r -> {}, a -> a.getConditions().getAudienceRestrictions().getFirst().getAudiences().getFirst().setURI("https://attacker.invalid"), "idp", 400); }
  @Test void wrongRecipientWithValidSignatureIsDenied() throws Exception { mutate(r -> {}, a -> a.getSubject().getSubjectConfirmations().getFirst().getSubjectConfirmationData().setRecipient("https://attacker.invalid/acs"), "idp", 400); }
  @Test void wrongDestinationWithValidSignatureIsDenied() throws Exception { mutate(r -> r.setDestination("https://attacker.invalid/acs"), a -> {}, "idp", 400); }
  @Test void wrongInResponseToWithValidSignatureIsDenied() throws Exception { mutate(r -> r.setInResponseTo("unbound"), a -> {}, "idp", 400); }
  @Test void oldSignedResponseIsDenied() throws Exception { mutate(r -> r.setIssueInstant(Instant.now().minusSeconds(10)), a -> {}, "idp", 400); }
  @Test void futureSignedResponseIsDenied() throws Exception { mutate(r -> r.setIssueInstant(Instant.now().plusSeconds(10)), a -> {}, "idp", 400); }
  @Test void expiredSignedAssertionIsDenied() throws Exception { mutate(r -> {}, a -> a.getConditions().setNotOnOrAfter(Instant.now().minusSeconds(10)), "idp", 400); }
  @Test void futureSignedAssertionIsDenied() throws Exception { mutate(r -> {}, a -> a.getConditions().setNotBefore(Instant.now().plusSeconds(10)), "idp", 400); }
  @Test void unsignedAssertionInsideSignedResponseIsDenied() throws Exception {
    var b = new Browser(lab); var form = Browser.hidden(b.approve(b.start(), Map.of()).body());
    form.put("SAMLResponse", SamlTestMessages.signedMutation(lab, form.get("SAMLResponse"), r -> {}, a -> {}, "idp", false, null));
    assertEquals(400, b.post(lab.spBase + "/acs", form, lab.idpBase).statusCode());
  }
  @Test void sha1IsDeniedEvenWhenSignatureIsMathematicallyCorrect() throws Exception {
    var b = new Browser(lab); var form = Browser.hidden(b.approve(b.start(), Map.of()).body());
    var weak = new org.opensaml.xmlsec.impl.BasicSignatureSigningConfiguration();
    weak.setSignatureAlgorithms(java.util.List.of(org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1));
    weak.setSignatureReferenceDigestMethods(java.util.List.of(org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_DIGEST_SHA1));
    weak.setSignatureCanonicalizationAlgorithm(org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
    String encoded = SamlTestMessages.signedMutation(lab, form.get("SAMLResponse"), r -> {}, a -> {}, "idp", true, weak);
    var signed = SamlTestMessages.decode(encoded);
    org.opensaml.xmlsec.signature.support.SignatureValidator.validate(signed.getSignature(), new se.swedenconnect.security.credential.opensaml.OpenSamlCredential(lab.keys.credential("idp")));
    assertEquals(org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, signed.getSignature().getSignatureAlgorithm());
    form.put("SAMLResponse", encoded); assertEquals(400, b.post(lab.spBase + "/acs", form, lab.idpBase).statusCode());
  }
  @Test void signedUnrequestedAttributesAreDenied() throws Exception {
    mutate(r -> {}, a -> {
      var attribute = a.getAttributeStatements().getFirst().getAttributes().getFirst();
      attribute.setName("urn:openid:lab:unrequested");
    }, "idp", 400);
  }
  @Test void elevatedContextInSignedResponseIsDenied() throws Exception {
    mutate(r -> {}, a -> a.getAuthnStatements().getFirst().getAuthnContext().getAuthnContextClassRef().setURI("http://id.elegnamnden.se/loa/1.0/loa3"), "idp", 400);
  }
  @Test void logoutRequiresCsrfAndEndsSession() throws Exception {
    var b = new Browser(lab); var logged = b.receive(b.approve(b.start(), Map.of()));
    assertEquals(403, b.post(lab.spBase + "/logout", Map.of("csrf", "wrong"), lab.spBase).statusCode());
    assertEquals(303, b.post(lab.spBase + "/logout", Browser.hidden(logged.body()), lab.spBase).statusCode());
    assertEquals(401, b.get(lab.spBase + "/me").statusCode());
  }
  @Test void untrustedInputDoesNotLeakIntoLogs() throws Exception {
    var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
    var capture = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>(); capture.start(); logger.addAppender(capture);
    String canary = "SECRET-CANARY-NOT-TO-BE-LOGGED";
    try {
      var b = new Browser(lab); var req = lab.sp.generate("test-relay", r -> r.getIssuer().setValue("https://attacker.invalid/" + canary));
      assertEquals(400, b.follow(b.get(req.getSendUrl())).statusCode());
      assertDenied(b, b.approve(b.start(), Map.of("credential", canary)));
      assertTrue(capture.list.stream().noneMatch(e -> e.getFormattedMessage().contains(canary) || e.getFormattedMessage().contains("SAMLResponse=")));
    } finally { logger.detachAppender(capture); capture.stop(); }
  }
  @Test void xxeDoesNotMakeANetworkRequest() throws Exception {
    AtomicInteger calls = new AtomicInteger();
    var sink = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 1);
    sink.createContext("/", x -> { calls.incrementAndGet(); x.sendResponseHeaders(204, -1); x.close(); }); sink.start();
    try {
      var b = new Browser(lab); b.start();
      String xml = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://127.0.0.1:" + sink.getAddress().getPort() + "/'>]><foo>&xxe;</foo>";
      assertEquals(400, b.post(lab.spBase + "/acs", Map.of("SAMLResponse", java.util.Base64.getEncoder().encodeToString(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8))), lab.idpBase).statusCode());
      assertEquals(0, calls.get());
    } finally { sink.stop(0); }
  }
  @Test void replacementCannotResurrectOldSessionOrPendingResponse() throws Exception {
    var r = lab.registry;
    r.begin("SYNTHETIC-replaced", "TEST-CREDENTIAL-old");
    r.simulateProofing("TEST-CREDENTIAL-old", "SYNTHETIC-replaced");
    r.activate("TEST-CREDENTIAL-old", Instant.now().plusSeconds(300));
    var old = new Browser(lab);
    assertEquals(200, old.receive(old.approve(old.start(), Map.of("credential", "TEST-CREDENTIAL-old"))).statusCode());
    var pending = new Browser(lab);
    var response = pending.approve(pending.start(), Map.of("credential", "TEST-CREDENTIAL-old"));
    r.begin("SYNTHETIC-replaced", "TEST-CREDENTIAL-new");
    r.simulateProofing("TEST-CREDENTIAL-new", "SYNTHETIC-replaced");
    r.replace("TEST-CREDENTIAL-old", "TEST-CREDENTIAL-new", Instant.now().plusSeconds(300));
    assertEquals(401, old.get(lab.spBase + "/me").statusCode());
    assertEquals(400, pending.receive(response).statusCode());
    var replacement = new Browser(lab);
    assertEquals(200, replacement.receive(replacement.approve(replacement.start(), Map.of("credential", "TEST-CREDENTIAL-new"))).statusCode());
    assertEquals(401, old.get(lab.spBase + "/me").statusCode());
  }
  @Test void revokeBetweenApprovalAndResumeIsEnforced() throws Exception {
    lab.registry.begin("SYNTHETIC-between", "TEST-CREDENTIAL-between"); lab.registry.simulateProofing("TEST-CREDENTIAL-between", "SYNTHETIC-between"); lab.registry.activate("TEST-CREDENTIAL-between", Instant.now().plusSeconds(60));
    var b = new Browser(lab); var form = Browser.hidden(b.start().body()); form.putAll(Map.of("action", "approve", "credential", "TEST-CREDENTIAL-between", "simulatedProofing", "acknowledged"));
    var resume = b.post(lab.idpBase + "/lab", form, lab.idpBase); assertEquals(302, resume.statusCode());
    lab.registry.revoke("TEST-CREDENTIAL-between"); assertDenied(b, b.follow(resume));
  }
  @Test @Order(Integer.MAX_VALUE) void revokeInvalidatesActiveSessionAndPendingLogin() throws Exception {
    var loggedIn = new Browser(lab); assertEquals(200, loggedIn.receive(loggedIn.approve(loggedIn.start(), Map.of())).statusCode());
    var pending = new Browser(lab); var page = pending.start();
    var home = loggedIn.get(lab.idpBase + "/"); var csrf = Browser.hidden(home.body());
    assertEquals(403, loggedIn.post(lab.idpBase + "/lab/revoke", Map.of(), lab.idpBase).statusCode());
    assertEquals(200, loggedIn.post(lab.idpBase + "/lab/revoke", csrf, lab.idpBase).statusCode());
    assertEquals(401, loggedIn.get(lab.spBase + "/me").statusCode()); assertDenied(pending, pending.approve(page, Map.of()));
    assertDenied(loggedIn, loggedIn.approve(loggedIn.start(), Map.of()));
  }
  private void denyRequest(Consumer<AuthnRequest> change) throws Exception {
    var b = new Browser(lab); var req = lab.sp.generate("test-relay", change); var result = b.follow(b.get(req.getSendUrl()));
    assertFalse(result.body().contains("Godkänn testinloggning"), result.body()); assertEquals(401, b.get(lab.spBase + "/me").statusCode());
  }
  private void assertDenied(Browser b, HttpResponse<String> response) throws Exception {
    if (Browser.hidden(response.body()).containsKey("SAMLResponse")) {
      var saml = SamlTestMessages.decode(Browser.hidden(response.body()).get("SAMLResponse"));
      assertTrue(saml.getEncryptedAssertions().isEmpty()); assertNotEquals(StatusCode.SUCCESS, saml.getStatus().getStatusCode().getValue());
      assertEquals(400, b.receive(response).statusCode());
    }
    assertEquals(401, b.get(lab.spBase + "/me").statusCode());
  }
  private void mutate(Consumer<Response> responseChange, Consumer<Assertion> assertionChange, String signer, int expected) throws Exception {
    var b = new Browser(lab); var response = b.approve(b.start(), Map.of()); var form = Browser.hidden(response.body());
    form.put("SAMLResponse", SamlTestMessages.signedMutation(lab, form.get("SAMLResponse"), responseChange, assertionChange, signer));
    assertEquals(expected, b.post(lab.spBase + "/acs", form, lab.idpBase).statusCode());
    if (expected == 400) assertEquals(401, b.get(lab.spBase + "/me").statusCode());
  }
}
