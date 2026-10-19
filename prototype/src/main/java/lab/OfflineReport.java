package lab;

import java.time.*;
import java.util.*;

/** Internal reconciliation ONLY. No Digg payload, endpoint, API key or compensation claim. */
public final class OfflineReport {
  public enum Outcome { SUCCESS, CANCELLED, FAILED }
  public record Event(String transaction, Instant at, Outcome outcome) {
    public Event {
      if (transaction == null || !transaction.matches("[a-f0-9]{64}") || at == null || outcome == null)
        throw new IllegalArgumentException("An opaque transaction fingerprint and a terminal outcome are required");
    }
  }
  public record Summary(String environment, String submission, String period, String timezone,
      long completedSyntheticLogins, long cancelled, long failed, long duplicateEvents, long outsidePeriod,
      long compensableTransactions) {}

  public static Summary reconcile(YearMonth period, Collection<Event> source) {
    Objects.requireNonNull(period); Objects.requireNonNull(source);
    Map<String, Event> unique = new HashMap<>(); long duplicate = 0, outside = 0, success = 0, cancelled = 0, failed = 0;
    for (var e : source) {
      var prior = unique.putIfAbsent(e.transaction(), e);
      if (prior != null) {
        if (!prior.equals(e)) throw new IllegalArgumentException("Conflicting source events; reconciliation blocked");
        duplicate++; continue;
      }
      if (!YearMonth.from(e.at().atZone(ZoneId.of("Europe/Stockholm"))).equals(period)) { outside++; continue; }
      switch (e.outcome()) { case SUCCESS -> success++; case CANCELLED -> cancelled++; case FAILED -> failed++; }
    }
    return new Summary("SYNTHETIC_ONLY", "INTE SKICKAT", period.toString(), "Europe/Stockholm",
        success, cancelled, failed, duplicate, outside, 0);
  }
  private OfflineReport() {}
}
