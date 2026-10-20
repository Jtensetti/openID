package lab;

import lab.idp.WebAuthnService;
import org.springframework.mock.web.MockHttpSession;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.time.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

class WebAuthnServiceTest {
  static final String ALICE = "TEST-CREDENTIAL-alice", FLOW = "saml:test-flow";
  final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-10-19T00:00:00Z"));
  final Clock clock = new Clock() {
    public ZoneId getZone() { return ZoneOffset.UTC; }
    public Clock withZone(ZoneId zone) { return this; }
    public Instant instant() { return now.get(); }
  };
  SyntheticRegistry registry;
  WebAuthnService service;
  MockHttpSession session;
  TestAuthenticator authenticator;
  @BeforeEach void prepare() throws Exception {
    registry = new SyntheticRegistry(clock);
    registry.begin("SYNTHETIC-alice", ALICE); registry.simulateProofing(ALICE, "SYNTHETIC-alice");
    registry.activate(ALICE, now.get().plusSeconds(3600));
    service = new WebAuthnService(registry, "https://localhost:8443", clock, true);
    session = new MockHttpSession(); authenticator = new TestAuthenticator();
  }
  String registrationOptions() { return service.beginRegistration(session, ALICE, "acknowledged"); }
  void enroll() throws Exception { service.finishRegistration(session, authenticator.registration(registrationOptions())); }
  String options() { return service.beginAuthentication(session, ALICE, FLOW); }
  String finish(String response) { return service.finishAuthentication(session, FLOW, response); }
  @Test void keyRegistrationAndSignedAssertionWorkWithoutVendorAttestation() throws Exception {
    var options = registrationOptions();
    var json = TestAuthenticator.JSON.readTree(options).get("publicKey");
    assertEquals("none", json.get("attestation").asText());
    assertFalse(json.get("authenticatorSelection").hasNonNull("authenticatorAttachment"));
    assertEquals("required", json.get("authenticatorSelection").get("userVerification").asText());
    service.finishRegistration(session, authenticator.registration(options));
    assertEquals(ALICE, finish(authenticator.assertion(options(), 1)));
    assertEquals(1, registry.passkeys().get(ALICE).signatureCount());
  }
  @Test void explicitSimulationAcknowledgementIsRequired() {
    assertThrows(WebAuthnService.Rejected.class, () -> service.beginRegistration(session, ALICE, ""));
    assertTrue(registry.passkeys().isEmpty());
  }
  @Test void disabledWebAuthnCannotIssueOptions() {
    var disabled = new WebAuthnService(registry, "https://127.0.0.1:8443", clock, false);
    assertThrows(WebAuthnService.Rejected.class, () -> disabled.beginRegistration(session, ALICE, "acknowledged"));
  }
  @Test void registeredCredentialCannotBeOverwritten() throws Exception {
    enroll(); assertThrows(WebAuthnService.Rejected.class, this::registrationOptions);
  }
  @Test void unregisteredCredentialCannotAuthenticate() { assertThrows(WebAuthnService.Rejected.class, this::options); }
  @Test void registrationIsSessionBoundAndOneTime() throws Exception {
    String response = authenticator.registration(registrationOptions());
    assertThrows(WebAuthnService.Rejected.class, () -> service.finishRegistration(new MockHttpSession(), response));
    service.finishRegistration(session, response);
    assertThrows(WebAuthnService.Rejected.class, () -> service.finishRegistration(session, response));
  }
  @Test void authenticationIsSessionBoundAndOneTime() throws Exception {
    enroll(); String response = authenticator.assertion(options(), 1);
    assertThrows(WebAuthnService.Rejected.class, () -> service.finishAuthentication(new MockHttpSession(), FLOW, response));
    assertEquals(ALICE, finish(response)); assertThrows(WebAuthnService.Rejected.class, () -> finish(response));
  }
  @Test void authenticationIsBoundToSamlFlowAndFailedAttemptConsumesChallenge() throws Exception {
    enroll(); String response = authenticator.assertion(options(), 1);
    assertThrows(WebAuthnService.Rejected.class, () -> service.finishAuthentication(session, "saml:other", response));
    assertThrows(WebAuthnService.Rejected.class, () -> finish(response));
  }
  @Test void registrationChallengeExpiresAtDeadline() throws Exception {
    String response = authenticator.registration(registrationOptions()); now.set(now.get().plusSeconds(60));
    assertThrows(WebAuthnService.Rejected.class, () -> service.finishRegistration(session, response));
  }
  @Test void assertionChallengeExpiresAtDeadline() throws Exception {
    enroll(); String response = authenticator.assertion(options(), 1); now.set(now.get().plusSeconds(60));
    assertThrows(WebAuthnService.Rejected.class, () -> finish(response));
  }
  @Test void secondCeremonyInvalidatesFirstChallenge() throws Exception {
    enroll(); String response = authenticator.assertion(options(), 1); options();
    assertThrows(WebAuthnService.Rejected.class, () -> finish(response));
  }
  @ParameterizedTest @ValueSource(strings={"https://attacker.invalid", "https://localhost:8444", "https://sub.localhost:8443", "http://localhost:8443"})
  void wrongOriginsFailRegistrationAndAssertion(String origin) throws Exception {
    String registration = authenticator.registration(registrationOptions(), 0x45, "localhost", c -> c.put("origin", origin));
    assertThrows(WebAuthnService.Rejected.class, () -> service.finishRegistration(session, registration));
    enroll(); String response = authenticator.assertion(options(), 1, 0x05, "localhost", c -> c.put("origin", origin));
    assertThrows(WebAuthnService.Rejected.class, () -> finish(response));
  }
  @ParameterizedTest @ValueSource(strings={"challenge", "type", "crossOrigin", "topOrigin"})
  void invalidClientBindingsFailBothCeremonies(String field) throws Exception {
    java.util.function.Consumer<com.fasterxml.jackson.databind.node.ObjectNode> change = c -> {
      switch (field) {
        case "challenge" -> c.put(field, TestAuthenticator.b64(new byte[32]));
        case "type" -> c.put(field, "invalid.operation");
        case "crossOrigin" -> c.put(field, true);
        case "topOrigin" -> c.put(field, "https://attacker.invalid");
      }
    };
    String registration = authenticator.registration(registrationOptions(), 0x45, "localhost", change);
    assertThrows(WebAuthnService.Rejected.class, () -> service.finishRegistration(session, registration));
    enroll(); String response = authenticator.assertion(options(), 1, 0x05, "localhost", change);
    assertThrows(WebAuthnService.Rejected.class, () -> finish(response));
  }
  @ParameterizedTest @ValueSource(ints={0x00, 0x01, 0x04, 0x15})
  void missingPresenceVerificationOrInvalidBackupFlagsFailBothCeremonies(int flags) throws Exception {
    String registration = authenticator.registration(registrationOptions(), flags | 0x40, "localhost", c -> {});
    assertThrows(WebAuthnService.Rejected.class, () -> service.finishRegistration(session, registration));
    enroll(); String response = authenticator.assertion(options(), 1, flags, "localhost", c -> {});
    assertThrows(WebAuthnService.Rejected.class, () -> finish(response));
  }
  @Test void wrongRpIdHashFailsBothCeremonies() throws Exception {
    String registration = authenticator.registration(registrationOptions(), 0x45, "attacker.invalid", c -> {});
    assertThrows(WebAuthnService.Rejected.class, () -> service.finishRegistration(session, registration));
    enroll(); String response = authenticator.assertion(options(), 1, 0x05, "attacker.invalid", c -> {});
    assertThrows(WebAuthnService.Rejected.class, () -> finish(response));
  }
  @ParameterizedTest @ValueSource(strings={"signature", "userHandle", "id"})
  void corruptedSignatureOrUnboundKeyFails(String field) throws Exception {
    enroll(); var json = (com.fasterxml.jackson.databind.node.ObjectNode) TestAuthenticator.JSON.readTree(authenticator.assertion(options(), 1));
    if (field.equals("id")) { json.put("id", TestAuthenticator.b64(new byte[32])); json.put("rawId", TestAuthenticator.b64(new byte[32])); }
    else ((com.fasterxml.jackson.databind.node.ObjectNode) json.get("response")).put(field, TestAuthenticator.b64(new byte[32]));
    assertThrows(WebAuthnService.Rejected.class, () -> finish(json.toString()));
    assertEquals(0, registry.passkeys().get(ALICE).signatureCount());
  }
  @Test void changedBackupEligibilityFails() throws Exception {
    enroll(); String response = authenticator.assertion(options(), 1, 0x0d, "localhost", c -> {});
    assertThrows(WebAuthnService.Rejected.class, () -> finish(response));
  }
  @Test void wellFormedSignatureFromAnotherPrivateKeyFails() throws Exception {
    enroll(); var other = new TestAuthenticator();
    System.arraycopy(authenticator.id, 0, other.id, 0, authenticator.id.length);
    other.userHandle = authenticator.userHandle;
    String response = other.assertion(options(), 1);
    assertThrows(WebAuthnService.Rejected.class, () -> finish(response));
    assertEquals(0, registry.passkeys().get(ALICE).signatureCount());
  }
  @Test void sameKeyIdentifierCannotBeRegisteredForAnotherIdentity() throws Exception {
    enroll(); String bob = "TEST-CREDENTIAL-bob";
    registry.begin("SYNTHETIC-bob", bob); registry.simulateProofing(bob, "SYNTHETIC-bob");
    registry.activate(bob, now.get().plusSeconds(3600));
    String response = authenticator.registration(service.beginRegistration(session, bob, "acknowledged"));
    assertThrows(WebAuthnService.Rejected.class, () -> service.finishRegistration(session, response));
    assertEquals(1, registry.passkeys().size());
  }
  @Test void syncedCounterlessKeysWorkButRegressedNonzeroCountersFail() throws Exception {
    service.finishRegistration(session, authenticator.registration(registrationOptions(), 0x4d, "localhost", c -> {}));
    assertEquals(ALICE, finish(authenticator.assertion(options(), 0, 0x1d, "localhost", c -> {})));
    assertTrue(registry.passkeys().get(ALICE).backedUp());
    assertEquals(ALICE, finish(authenticator.assertion(options(), 0, 0x1d, "localhost", c -> {})));
    assertEquals(ALICE, finish(authenticator.assertion(options(), 2, 0x1d, "localhost", c -> {})));
    String repeat = authenticator.assertion(options(), 2, 0x1d, "localhost", c -> {});
    assertThrows(WebAuthnService.Rejected.class, () -> finish(repeat));
    String reset = authenticator.assertion(options(), 0, 0x1d, "localhost", c -> {});
    assertThrows(WebAuthnService.Rejected.class, () -> finish(reset));
  }
  @Test void revokeDuringRegistrationPreventsEnrollment() throws Exception {
    String response = authenticator.registration(registrationOptions()); registry.revoke(ALICE);
    assertThrows(IllegalStateException.class, () -> service.finishRegistration(session, response));
    assertTrue(registry.passkeys().isEmpty());
  }
  @Test void revokeDuringAuthenticationPreventsAuthentication() throws Exception {
    enroll(); String response = authenticator.assertion(options(), 1); registry.revoke(ALICE);
    assertThrows(IllegalStateException.class, () -> finish(response));
  }
  @Test void expiredCredentialPreventsAuthentication() throws Exception {
    enroll(); now.set(now.get().plusSeconds(3590)); String response = authenticator.assertion(options(), 1);
    now.set(now.get().plusSeconds(10)); assertThrows(IllegalStateException.class, () -> finish(response));
  }
  @ParameterizedTest @ValueSource(strings={"", "{", "null", "[]"})
  void malformedResponseIsRejectedAndConsumed(String bad) throws Exception {
    enroll(); String good = authenticator.assertion(options(), 1);
    assertThrows(WebAuthnService.Rejected.class, () -> finish(bad));
    assertThrows(WebAuthnService.Rejected.class, () -> finish(good));
  }
  @Test void oversizedResponseIsRejected() throws Exception {
    enroll(); options(); assertThrows(WebAuthnService.Rejected.class, () -> finish("x".repeat(65537)));
  }
  @Test void concurrentConsumptionSucceedsOnce() throws Exception {
    enroll(); String response = authenticator.assertion(options(), 1);
    try (var pool = Executors.newFixedThreadPool(2)) {
      Callable<Boolean> attempt = () -> { try { finish(response); return true; } catch (WebAuthnService.Rejected e) { return false; } };
      var a = pool.submit(attempt); var b = pool.submit(attempt);
      assertNotEquals(a.get(5, TimeUnit.SECONDS), b.get(5, TimeUnit.SECONDS));
    }
  }
}
