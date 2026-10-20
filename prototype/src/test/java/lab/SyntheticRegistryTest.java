package lab;

import java.time.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SyntheticRegistryTest {
  private final Instant now = Instant.parse("2026-10-19T00:00:00Z");
  private final SyntheticRegistry registry = new SyntheticRegistry(Clock.fixed(now, ZoneOffset.UTC));
  private static final String ID = "SYNTHETIC-unit", OLD = "TEST-CREDENTIAL-unit", NEW = "TEST-CREDENTIAL-new";
  void pending() { registry.begin(ID, OLD); }
  void proofed() { pending(); registry.simulateProofing(OLD, ID); }
  void active() { proofed(); registry.activate(OLD, now.plusSeconds(60)); }
  @Test void noRealIdentityInput() { assertThrows(IllegalArgumentException.class, () -> registry.begin("REAL-IDENTITY", OLD)); }
  @Test void noDuplicateCredential() { pending(); assertThrows(IllegalArgumentException.class, this::pending); }
  @Test void noActivationWithoutSimulatedProofing() { pending(); assertThrows(IllegalStateException.class, () -> registry.activate(OLD, now.plusSeconds(60))); }
  @Test void noProofingForDifferentPerson() { pending(); assertThrows(IllegalStateException.class, () -> registry.simulateProofing(OLD, "SYNTHETIC-other")); }
  @Test void noReplayOfProofingDecision() { proofed(); assertThrows(IllegalStateException.class, () -> registry.simulateProofing(OLD, ID)); }
  @Test void noExpiredActivation() { proofed(); assertThrows(IllegalStateException.class, () -> registry.activate(OLD, now)); }
  @Test void cancelledIssuanceLeavesNoUsableCredential() { proofed(); registry.revoke(OLD); assertThrows(IllegalStateException.class, () -> registry.authorize(OLD)); }
  @Test void unknownCredentialIsDenied() { assertThrows(IllegalArgumentException.class, () -> registry.authorize("TEST-CREDENTIAL-unknown")); }
  @Test void revokedCredentialCannotReactivate() { active(); registry.revoke(OLD); assertThrows(IllegalStateException.class, () -> registry.activate(OLD, now.plusSeconds(60))); }
  @Test void replacementNeedsNewProofingAndRevokesOld() {
    active(); registry.begin(ID, NEW);
    assertThrows(IllegalStateException.class, () -> registry.replace(OLD, NEW, now.plusSeconds(60)));
    registry.simulateProofing(NEW, ID); registry.replace(OLD, NEW, now.plusSeconds(60));
    assertThrows(IllegalStateException.class, () -> registry.authorize(OLD));
    assertEquals(OLD, registry.authorize(NEW).replaces());
    assertThrows(IllegalStateException.class, () -> registry.replace(OLD, NEW, now.plusSeconds(60)));
  }
  @Test void wrongPersonCannotReplaceCredential() {
    active(); registry.begin("SYNTHETIC-other", NEW); registry.simulateProofing(NEW, "SYNTHETIC-other");
    assertThrows(IllegalStateException.class, () -> registry.replace(OLD, NEW, now.plusSeconds(60)));
    assertEquals(ID, registry.authorize(OLD).identity());
  }
  @Test void expirationIsEnforcedAtDecisionTime() {
    var instant = new java.util.concurrent.atomic.AtomicReference<>(now);
    Clock clock = new Clock() {
      public ZoneId getZone() { return ZoneOffset.UTC; }
      public Clock withZone(ZoneId z) { return this; }
      public Instant instant() { return instant.get(); }
    };
    var r = new SyntheticRegistry(clock); r.begin(ID, OLD); r.simulateProofing(OLD, ID); r.activate(OLD, now.plusSeconds(1));
    r.authorize(OLD); instant.set(now.plusSeconds(1));
    assertThrows(IllegalStateException.class, () -> r.authorize(OLD));
    assertFalse(r.activeIdentity(ID, r.revocationVersions().get(ID)));
  }
  @Test void revokeAndAuthenticationHaveOneOrdering() throws Exception {
    active();
    try (var executor = Executors.newFixedThreadPool(2)) {
      CountDownLatch checked = new CountDownLatch(1), finish = new CountDownLatch(1), revokeStarted = new CountDownLatch(1);
      Future<?> auth = executor.submit(() -> { synchronized (registry) {
        registry.authorize(OLD); checked.countDown();
        try { if (!finish.await(5, TimeUnit.SECONDS)) throw new AssertionError("test barrier timeout"); }
        catch (InterruptedException e) { throw new AssertionError(e); }
        registry.authorize(OLD); // models the final signer inside the same critical section
      }});
      assertTrue(checked.await(5, TimeUnit.SECONDS));
      Future<?> revoke = executor.submit(() -> { revokeStarted.countDown(); registry.revoke(OLD); });
      assertTrue(revokeStarted.await(5, TimeUnit.SECONDS)); assertFalse(revoke.isDone());
      finish.countDown(); auth.get(5, TimeUnit.SECONDS); revoke.get(5, TimeUnit.SECONDS);
      assertThrows(IllegalStateException.class, () -> registry.authorize(OLD));
    }
  }
}
