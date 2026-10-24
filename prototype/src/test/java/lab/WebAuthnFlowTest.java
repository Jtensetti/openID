package lab;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.net.http.HttpResponse;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class WebAuthnFlowTest {
  @TempDir static Path directory;
  Lab lab;
  TestAuthenticator authenticator;
  long counter;
  @BeforeAll void start() throws Exception {
    var keys = directory.resolve("keys"); TestKeys.initialize(keys); SyntheticRegistry.initialize(keys);
    lab = new Lab(keys, FlowTest.freePort(), FlowTest.freePort(), SyntheticRegistry.open(keys, java.time.Clock.systemUTC()), true);
    authenticator = new TestAuthenticator(); authenticator.origin = lab.idpBase;
  }
  @AfterAll void stop() { if (lab != null) lab.close(); }
  Map<String, String> registrationForm(Browser b) throws Exception {
    var form = Browser.hidden(b.get(lab.idpBase + "/wallet/").body());
    form.put("credential", "TEST-CREDENTIAL-alice"); form.put("simulatedProofing", "acknowledged"); return form;
  }
  @Test @Order(1) void registrationNeedsCsrfOriginAndExplicitAcknowledgement() throws Exception {
    var b = new Browser(lab); var form = registrationForm(b);
    var missing = new HashMap<>(form); missing.remove("_csrf");
    assertEquals(403, b.post(lab.idpBase + "/wallet/register/options", missing, lab.idpBase).statusCode());
    for (String origin : List.of("null", "https://attacker.invalid", lab.spBase))
      assertEquals(403, b.post(lab.idpBase + "/wallet/register/options", form, origin).statusCode());
    form.remove("simulatedProofing");
    assertEquals(400, b.post(lab.idpBase + "/wallet/register/options", form, lab.idpBase).statusCode());
    assertTrue(lab.registry.passkeys().isEmpty());
  }
  @Test @Order(2) void registrationUsesRealHttpsAndRotatesSession() throws Exception {
    var b = new Browser(lab); var form = registrationForm(b);
    String before = b.cookies.getCookieStore().getCookies().stream().filter(c -> c.getName().equals("__Host-lab-idp")).findFirst().orElseThrow().getValue();
    var options = b.post(lab.idpBase + "/wallet/register/options", form, lab.idpBase);
    assertEquals(200, options.statusCode());
    form.put("response", authenticator.registration(options.body()));
    var finish = b.post(lab.idpBase + "/wallet/register/finish", form, lab.idpBase);
    assertEquals(200, finish.statusCode(), finish.body());
    assertTrue(finish.body().contains("SIMULATED"));
    String after = b.cookies.getCookieStore().getCookies().stream().filter(c -> c.getName().equals("__Host-lab-idp")).findFirst().orElseThrow().getValue();
    assertNotEquals(before, after);
    assertEquals(400, b.post(lab.idpBase + "/wallet/register/finish", form, lab.idpBase).statusCode());
  }
  Map<String, String> authentication(Browser b, HttpResponse<String> page) throws Exception {
    var form = Browser.hidden(page.body()); form.put("credential", "TEST-CREDENTIAL-alice");
    var options = b.post(lab.idpBase + "/lab/webauthn/options", form, lab.idpBase);
    assertEquals(200, options.statusCode(), options.body());
    form.put("response", authenticator.assertion(options.body(), ++counter)); return form;
  }
  @Test @Order(3) void webAuthnLeadsToSignedEncryptedSamlAndCannotBeReplayed() throws Exception {
    var b = new Browser(lab); var form = authentication(b, b.start());
    var response = b.follow(b.post(lab.idpBase + "/lab/webauthn/finish", form, lab.idpBase));
    assertEquals(200, response.statusCode(), response.body());
    var saml = SamlTestMessages.decode(Browser.hidden(response.body()).get("SAMLResponse"));
    assertTrue(saml.isSigned()); assertEquals(1, saml.getEncryptedAssertions().size());
    var assertion = SamlTestMessages.decrypt(lab, saml); assertTrue(assertion.isSigned());
    assertEquals(Metadata.LAB_CONTEXT, assertion.getAuthnStatements().getFirst().getAuthnContext().getAuthnContextClassRef().getURI());
    assertEquals(200, b.receive(response).statusCode());
    assertEquals(400, b.post(lab.idpBase + "/lab/webauthn/finish", form, lab.idpBase).statusCode());
    assertEquals(400, b.receive(response).statusCode());
  }
  @Test @Order(4) void simulationButtonCannotBypassWebAuthn() throws Exception {
    var b = new Browser(lab); var response = b.approve(b.start(), Map.of());
    assertEquals(400, b.receive(response).statusCode()); assertEquals(401, b.get(lab.spBase + "/me").statusCode());
  }
  @Test @Order(5) void finishRequiresCsrfOriginAndSamlSessionBinding() throws Exception {
    var a = new Browser(lab); var form = authentication(a, a.start());
    var missing = new HashMap<>(form); missing.remove("_csrf");
    assertEquals(403, a.post(lab.idpBase + "/lab/webauthn/finish", missing, lab.idpBase).statusCode());
    assertEquals(403, a.post(lab.idpBase + "/lab/webauthn/finish", form, "https://attacker.invalid").statusCode());
    var b = new Browser(lab); var bForm = Browser.hidden(b.start().body());
    bForm.put("response", form.get("response")); bForm.put("authnId", form.get("authnId"));
    assertEquals(400, b.post(lab.idpBase + "/lab/webauthn/finish", bForm, lab.idpBase).statusCode());
    assertEquals(401, b.get(lab.spBase + "/me").statusCode());
  }
  @Test @Order(6) void walletAndApprovalHaveRestrictiveBrowserHeaders() throws Exception {
    var b = new Browser(lab);
    for (var response : List.of(b.get(lab.idpBase + "/wallet/"), b.start())) {
      assertEquals(200, response.statusCode());
      assertTrue(response.headers().firstValue("Cache-Control").orElseThrow().contains("no-store"));
      String csp = response.headers().firstValue("Content-Security-Policy").orElseThrow();
      assertTrue(csp.contains("frame-ancestors 'none'")); assertFalse(csp.contains("unsafe-inline"));
      assertTrue(response.headers().firstValue("Permissions-Policy").orElseThrow().contains("camera=()"));
    }
    var manifest = b.get(lab.idpBase + "/wallet/manifest.webmanifest"); assertEquals(200, manifest.statusCode());
    assertEquals("/wallet/", TestAuthenticator.JSON.readTree(manifest.body()).get("start_url").asText());
  }
  @Test @Order(7) void storedWebAuthnKeyCannotBeUsedInLegacyApprovalMode() {
    assertThrows(IllegalStateException.class, () -> new Lab(directory.resolve("keys"), 18443, 18444, lab.registry, false));
  }
  @Test @Order(99) void revocationInvalidatesPendingChallengeAndExistingSpSession() throws Exception {
    var a = new Browser(lab); var form = authentication(a, a.start());
    assertEquals(200, a.receive(a.follow(a.post(lab.idpBase + "/lab/webauthn/finish", form, lab.idpBase))).statusCode());
    var b = new Browser(lab); var pending = authentication(b, b.start());
    lab.registry.revoke("TEST-CREDENTIAL-alice");
    assertEquals(400, b.post(lab.idpBase + "/lab/webauthn/finish", pending, lab.idpBase).statusCode());
    assertEquals(401, a.get(lab.spBase + "/me").statusCode());
    assertEquals(401, b.get(lab.spBase + "/me").statusCode());
    var fresh = new Browser(lab);
    var revoked = Browser.hidden(fresh.start().body());
    revoked.put("credential", "TEST-CREDENTIAL-alice");
    var denied = fresh.post(lab.idpBase + "/lab/webauthn/options", revoked, lab.idpBase);
    assertEquals(400, denied.statusCode(), denied.body());
  }
}
