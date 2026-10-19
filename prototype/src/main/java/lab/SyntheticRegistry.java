package lab;

import java.time.*;
import java.util.*;

/** Deliberately simulated proofing and credentials. No real person or device is verified. */
public final class SyntheticRegistry {
  public enum State { PENDING, PROOFED, ACTIVE, REVOKED, EXPIRED }
  public record Entry(String identity, String credential, State state, Instant expires, String replaces) {}
  private final Map<String, Entry> entries = new HashMap<>();
  private final Map<String, Long> revocations = new HashMap<>();
  private final Clock clock;
  public SyntheticRegistry(Clock clock) { this.clock = clock; }
  public static SyntheticRegistry fixtures() {
    var r = new SyntheticRegistry(Clock.systemUTC());
    for (String id : List.of("alice", "revoked", "expired")) {
      String c = "TEST-CREDENTIAL-" + id;
      r.begin("SYNTHETIC-" + id, c);
      r.simulateProofing(c, "SYNTHETIC-" + id);
      r.activate(c, Instant.now().plusSeconds(3600));
    }
    r.revoke("TEST-CREDENTIAL-revoked");
    Entry old = r.entries.get("TEST-CREDENTIAL-expired");
    r.entries.put(old.credential(), new Entry(old.identity(), old.credential(), State.EXPIRED, Instant.EPOCH, null));
    return r;
  }
  public synchronized void begin(String identity, String credential) {
    if (!identity.matches("SYNTHETIC-[a-z-]{1,40}") || !credential.matches("TEST-CREDENTIAL-[a-z-]{1,40}") || entries.containsKey(credential))
      throw new IllegalArgumentException("Only new synthetic identifiers are accepted");
    entries.put(credential, new Entry(identity, credential, State.PENDING, Instant.EPOCH, null));
  }
  public synchronized void simulateProofing(String credential, String expectedIdentity) {
    Entry e = require(credential);
    if (e.state() != State.PENDING || !e.identity().equals(expectedIdentity)) throw new IllegalStateException("Invalid simulated proofing");
    entries.put(credential, new Entry(e.identity(), credential, State.PROOFED, e.expires(), e.replaces()));
  }
  public synchronized void activate(String credential, Instant expires) {
    Entry e = require(credential);
    if (e.state() != State.PROOFED || !expires.isAfter(clock.instant())) throw new IllegalStateException("Invalid activation");
    entries.put(credential, new Entry(e.identity(), credential, State.ACTIVE, expires, e.replaces()));
  }
  public synchronized void revoke(String credential) {
    Entry e = require(credential);
    entries.put(credential, new Entry(e.identity(), credential, State.REVOKED, e.expires(), e.replaces()));
    revocations.merge(e.identity(), 1L, Long::sum);
  }
  public synchronized void replace(String oldCredential, String newCredential, Instant expires) {
    Entry old = require(oldCredential), replacement = require(newCredential);
    if (!old.identity().equals(replacement.identity()) || replacement.state() != State.PROOFED || !expires.isAfter(clock.instant()))
      throw new IllegalStateException("Replacement requires new simulated proofing of the same identity");
    revoke(oldCredential);
    entries.put(newCredential, new Entry(old.identity(), newCredential, State.ACTIVE, expires, oldCredential));
  }
  public synchronized Entry authorize(String credential) {
    Entry e = require(credential);
    if (e.state() == State.ACTIVE && !e.expires().isAfter(clock.instant())) {
      e = new Entry(e.identity(), credential, State.EXPIRED, e.expires(), e.replaces()); entries.put(credential, e);
    }
    if (e.state() != State.ACTIVE) throw new IllegalStateException("Credential is not active");
    return e;
  }
  public synchronized Map<String, Long> revocationVersions() {
    Map<String, Long> snapshot = new HashMap<>();
    entries.values().forEach(e -> snapshot.put(e.identity(), revocations.getOrDefault(e.identity(), 0L)));
    return Map.copyOf(snapshot);
  }
  public synchronized boolean activeIdentity(String identity, Long expectedRevocationVersion) {
    return Objects.equals(expectedRevocationVersion, revocations.getOrDefault(identity, 0L)) &&
        entries.values().stream().anyMatch(e -> e.identity().equals(identity) && e.state() == State.ACTIVE && e.expires().isAfter(clock.instant()));
  }
  private Entry require(String credential) {
    Entry e = entries.get(credential);
    if (e == null) throw new IllegalArgumentException("Unknown test credential");
    return e;
  }
}
