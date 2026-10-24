package lab;

import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import java.io.*;
import java.security.cert.*;
import java.time.*;
import lab.signing.TestDocumentSigner;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SigningFlowTest {
  @TempDir static Path root;
  Lab lab;
  TestAuthenticator authenticator;
  long counter;
  @BeforeAll void start() throws Exception {
    var keys = root.resolve("keys"); TestKeys.initialize(keys); SyntheticRegistry.initialize(keys);
    lab = new Lab(keys, FlowTest.freePort(), FlowTest.freePort(), SyntheticRegistry.open(keys, Clock.systemUTC()), true);
    authenticator = new TestAuthenticator(); authenticator.origin = lab.idpBase;
    var b = new Browser(lab); var form = Browser.hidden(b.get(lab.idpBase + "/wallet/").body());
    form.put("credential", "TEST-CREDENTIAL-alice"); form.put("simulatedProofing", "acknowledged");
    var options = b.post(lab.idpBase + "/wallet/register/options", form, lab.idpBase);
    assertEquals(200, options.statusCode()); form.put("response", authenticator.registration(options.body()));
    assertEquals(200, b.post(lab.idpBase + "/wallet/register/finish", form, lab.idpBase).statusCode());
  }
  @AfterAll void stop() { if (lab != null) lab.close(); }
  Map<String, String> view(Browser b) throws Exception {
    var page = b.get(lab.idpBase + "/sign/"); assertEquals(200, page.statusCode(), page.body());
    assertTrue(page.body().contains("Hela dokumentet")); assertTrue(page.body().contains("Jag vill skriva under detta testdokument"));
    var form = Browser.hidden(page.body()); form.put("intent", "sign-this-document"); return form;
  }
  void approve(Browser b, Map<String, String> form) throws Exception {
    var options = b.post(lab.idpBase + "/sign/options", form, lab.idpBase);
    assertEquals(200, options.statusCode(), options.body()); form.put("response", authenticator.assertion(options.body(), ++counter));
  }
  HttpResponse<String> finish(Browser b, Map<String, String> form) throws Exception { return b.post(lab.idpBase + "/sign/finish", form, lab.idpBase); }
  @Test @Order(1) void explicitWebAuthnConsentProducesDownloadableSignatureOfDisplayedBytes() throws Exception {
    var b = new Browser(lab);
    var page = b.get(lab.idpBase + "/sign/"); assertEquals(200, page.statusCode());
    String rendered = org.jsoup.Jsoup.parse(page.body()).selectFirst("#document").wholeText();
    var form = Browser.hidden(page.body()); form.put("intent", "sign-this-document"); approve(b, form);
    assertEquals(303, finish(b, form).statusCode());
    var download = b.client.send(HttpRequest.newBuilder(URI.create(lab.idpBase + "/sign/download")).GET().build(), HttpResponse.BodyHandlers.ofByteArray());
    assertEquals(200, download.statusCode());
    Map<String, byte[]> files = archive(download.body());
    assertEquals(Set.of("document.txt", "document.p7s", "signer.crt", "test-ca.crt", "evidence.json"), files.keySet());
    assertEquals(rendered, new String(files.get("document.txt"), java.nio.charset.StandardCharsets.UTF_8));
    var cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(files.get("test-ca.crt")));
    TestDocumentSigner.verify(files.get("document.txt"), files.get("document.p7s"), cert, "SYNTHETIC-alice", Instant.now());
    assertEquals(400, finish(b, form).statusCode());
    assertEquals(400, new Browser(lab).get(lab.idpBase + "/sign/download").statusCode());
    String target = System.getProperty("signature.fixtureDirectory");
    if (target != null) { Files.createDirectories(Path.of(target)); Files.write(Path.of(target).resolve("synthetic-signature.zip"), download.body()); }
  }
  @Test void csrfOriginAndExplicitSigningIntentAreRequired() throws Exception {
    var b = new Browser(lab); var form = view(b); var missing = new HashMap<>(form); missing.remove("_csrf");
    assertEquals(403, b.post(lab.idpBase + "/sign/options", missing, lab.idpBase).statusCode());
    assertEquals(403, b.post(lab.idpBase + "/sign/options", form, lab.spBase).statusCode());
    form.remove("intent"); assertEquals(400, b.post(lab.idpBase + "/sign/options", form, lab.idpBase).statusCode());
    assertEquals(400, b.get(lab.idpBase + "/sign/download").statusCode());
  }
  @Test void changedDigestOrReplacedDocumentCannotReuseConsent() throws Exception {
    var b = new Browser(lab); var form = view(b); approve(b, form); form.put("digest", "0".repeat(64));
    assertEquals(400, finish(b, form).statusCode());
    assertEquals(400, finish(b, form).statusCode());
    form = view(b); approve(b, form); view(b);
    assertEquals(400, finish(b, form).statusCode()); assertEquals(400, b.get(lab.idpBase + "/sign/download").statusCode());
  }
  @Test void cancellationAndAnotherBrowserCannotCompleteSignature() throws Exception {
    var a = new Browser(lab); var form = view(a); approve(a, form);
    var b = new Browser(lab); var other = view(b); other.put("response", form.get("response"));
    assertEquals(400, finish(b, other).statusCode());
    assertEquals(303, a.post(lab.idpBase + "/sign/cancel", form, lab.idpBase).statusCode());
    assertEquals(400, finish(a, form).statusCode());
  }
  @Test void ordinaryLoginAssertionCannotAuthorizeDocumentSignature() throws Exception {
    var b = new Browser(lab); var form = view(b);
    var login = Browser.hidden(b.start().body()); login.put("credential", "TEST-CREDENTIAL-alice");
    var options = b.post(lab.idpBase + "/lab/webauthn/options", login, lab.idpBase); assertEquals(200, options.statusCode());
    form.put("response", authenticator.assertion(options.body(), ++counter));
    assertEquals(400, finish(b, form).statusCode()); assertEquals(400, b.get(lab.idpBase + "/sign/download").statusCode());
  }
  @Test @Order(Integer.MAX_VALUE) void revocationAfterApprovalBlocksSignatureCreation() throws Exception {
    var b = new Browser(lab); var form = view(b); approve(b, form); lab.registry.revoke("TEST-CREDENTIAL-alice");
    assertEquals(400, finish(b, form).statusCode()); assertEquals(400, b.get(lab.idpBase + "/sign/download").statusCode());
  }
  private static Map<String, byte[]> archive(byte[] bytes) throws IOException {
    Map<String, byte[]> files = new HashMap<>();
    try (var zip = new ZipInputStream(new ByteArrayInputStream(bytes))) {
      ZipEntry entry; while ((entry = zip.getNextEntry()) != null) files.put(entry.getName(), zip.readAllBytes());
    }
    return files;
  }
}
