package lab;

import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class OfflineReportTest {
  static final YearMonth OCTOBER = YearMonth.of(2026, 10);
  OfflineReport.Event event(char id, String time, OfflineReport.Outcome outcome) {
    return new OfflineReport.Event(String.valueOf(id).repeat(64), Instant.parse(time), outcome);
  }
  @Test void testTrafficCannotBecomeAClaim() {
    var r = OfflineReport.reconcile(OCTOBER, List.of(event('a', "2026-10-19T12:00:00Z", OfflineReport.Outcome.SUCCESS)));
    assertEquals(1, r.completedSyntheticLogins()); assertEquals(0, r.compensableTransactions());
    assertEquals("SYNTHETIC_ONLY", r.environment()); assertEquals("INTE SKICKAT", r.submission());
  }
  @Test void cancellationFailureAndDuplicatesAreNotCompletedLogins() {
    var success = event('a', "2026-10-19T12:00:00Z", OfflineReport.Outcome.SUCCESS);
    var r = OfflineReport.reconcile(OCTOBER, List.of(success, success,
        event('b', "2026-10-19T12:00:00Z", OfflineReport.Outcome.CANCELLED),
        event('c', "2026-10-19T12:00:00Z", OfflineReport.Outcome.FAILED)));
    assertEquals(1, r.completedSyntheticLogins()); assertEquals(1, r.duplicateEvents());
    assertEquals(1, r.cancelled()); assertEquals(1, r.failed()); assertEquals(0, r.compensableTransactions());
  }
  @Test void conflictingDuplicateBlocksReconciliation() {
    assertThrows(IllegalArgumentException.class, () -> OfflineReport.reconcile(OCTOBER, List.of(
        event('a', "2026-10-19T12:00:00Z", OfflineReport.Outcome.SUCCESS),
        event('a', "2026-10-19T12:00:00Z", OfflineReport.Outcome.FAILED))));
  }
  @Test void stockholmMonthBoundaryAndYearChangeAreExplicit() {
    var r = OfflineReport.reconcile(YearMonth.of(2027, 1), List.of(
        event('a', "2026-12-31T23:00:00Z", OfflineReport.Outcome.SUCCESS),
        event('b', "2026-12-31T22:59:59Z", OfflineReport.Outcome.SUCCESS)));
    assertEquals(1, r.completedSyntheticLogins()); assertEquals(1, r.outsidePeriod());
  }
  @Test void personalIdentifiersAndUnknownTransactionsAreRejected() {
    assertThrows(IllegalArgumentException.class, () -> new OfflineReport.Event("SYNTHETIC-alice", Instant.now(), OfflineReport.Outcome.SUCCESS));
    assertThrows(IllegalArgumentException.class, () -> new OfflineReport.Event("a".repeat(64), Instant.now(), null));
  }
  @Test void emptyMonthIsOnlyAnInternalReconciliation() {
    var r = OfflineReport.reconcile(OCTOBER, List.of());
    assertEquals(0, r.completedSyntheticLogins()); assertEquals(0, r.compensableTransactions());
    assertEquals("INTE SKICKAT", r.submission());
  }
}
