package lab;

import java.time.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import lab.signing.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

class SigningCeremonyTest {
  final AtomicLong seconds = new AtomicLong();
  final Clock clock = new Clock() {
    final Instant base = Instant.now();
    public ZoneId getZone() { return ZoneOffset.UTC; }
    public Clock withZone(ZoneId zone) { return this; }
    public Instant instant() { return base.plusSeconds(seconds.get()); }
  };
  SyntheticRegistry registry;
  SigningCeremony ceremony;
  @BeforeEach void setup() throws Exception { registry = SyntheticRegistry.fixtures(); ceremony = new SigningCeremony(registry, clock); }
  SigningCeremony.Transaction begin() throws Exception { return ceremony.begin("TEST-CREDENTIAL-alice"); }
  SigningCeremony.Result finish(SigningCeremony.Transaction tx) throws Exception { return ceremony.finish(tx, tx.credential(), tx.id(), tx.digest()); }
  @Test void alteredDigestOrTransactionConsumesApproval() throws Exception {
    var tx = begin();
    assertThrows(IllegalStateException.class, () -> ceremony.finish(tx, tx.credential(), tx.id(), "0".repeat(64)));
    assertThrows(IllegalStateException.class, () -> finish(tx));
    var other = begin();
    assertThrows(IllegalStateException.class, () -> ceremony.finish(other, other.credential(), tx.id(), other.digest()));
  }
  @Test void wrongSignerConsumesApproval() throws Exception {
    var tx = begin();
    assertThrows(IllegalStateException.class, () -> ceremony.finish(tx, "TEST-CREDENTIAL-bob", tx.id(), tx.digest()));
    assertThrows(IllegalStateException.class, () -> finish(tx));
  }
  @Test void cancelledAndExpiredTransactionsCannotSign() throws Exception {
    var tx = begin(); ceremony.cancel(tx); assertThrows(IllegalStateException.class, () -> finish(tx));
    var expired = begin(); seconds.set(60); assertThrows(IllegalStateException.class, () -> finish(expired));
  }
  @Test void revokedCredentialCannotSignEvenAfterViewing() throws Exception {
    var tx = begin(); registry.revoke(tx.credential()); assertThrows(IllegalStateException.class, () -> finish(tx));
    assertThrows(IllegalStateException.class, this::begin);
  }
  @Test void unavailableRegistryFailsClosed() throws Exception {
    var tx = begin(); registry.close(); assertThrows(IllegalStateException.class, () -> finish(tx));
  }
  @Test void concurrentCompletionCreatesOnlyOneSignature() throws Exception {
    var tx = begin(); var wins = new AtomicInteger();
    try (var pool = Executors.newFixedThreadPool(2)) {
      var gate = new CountDownLatch(1);
      Callable<Void> task = () -> { gate.await(); try { finish(tx); wins.incrementAndGet(); } catch (IllegalStateException expected) {} return null; };
      var a = pool.submit(task); var b = pool.submit(task); gate.countDown(); a.get(); b.get();
    }
    assertEquals(1, wins.get()); assertThrows(IllegalStateException.class, () -> finish(tx));
  }
}
