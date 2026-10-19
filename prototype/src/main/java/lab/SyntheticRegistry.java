package lab;

import java.nio.file.*;
import java.time.*;
import java.util.*;

/** Deliberately simulated proofing and credentials. No real person or device is verified. */
public final class SyntheticRegistry implements AutoCloseable {
  public enum State { PENDING, PROOFED, ACTIVE, REVOKED, EXPIRED }
  public record Entry(String identity, String credential, State state, Instant expires, String replaces) {}
  private Map<String, Entry> entries = Map.of();
  private Map<String, Long> revocations = Map.of();
  private final Clock clock;
  private final RegistryStore store;
  private final Map<String, OfflineReport.Event> memoryOutcomes = new HashMap<>();
  private boolean closed;

  public SyntheticRegistry(Clock clock) { this.clock = clock; store = null; }
  private SyntheticRegistry(Clock clock, RegistryStore store) {
    this.clock = clock; this.store = store;
    var saved = store.load(); entries = saved.entries(); revocations = saved.versions();
    if (store.uncleanShutdown) revokeAll("UNCLEAN_RECOVERY");
  }
  public static SyntheticRegistry open(Path directory, Clock clock) throws Exception {
    var store = new RegistryStore(directory, false);
    try { return new SyntheticRegistry(clock, store); }
    catch (Exception e) { store.close(); throw e; }
  }
  public static void initialize(Path directory) throws Exception {
    try (var store = new RegistryStore(directory, true); var r = new SyntheticRegistry(Clock.systemUTC(), store)) { seed(r); }
  }
  public static SyntheticRegistry fixtures() {
    var r = new SyntheticRegistry(Clock.systemUTC()); seed(r); return r;
  }
  private static void seed(SyntheticRegistry r) {
    for (String id : List.of("alice", "revoked", "expired")) {
      String c = "TEST-CREDENTIAL-" + id;
      r.begin("SYNTHETIC-" + id, c); r.simulateProofing(c, "SYNTHETIC-" + id);
      r.activate(c, r.clock.instant().plusSeconds(3600));
    }
    r.revoke("TEST-CREDENTIAL-revoked");
    Entry old = r.entries.get("TEST-CREDENTIAL-expired");
    r.update(new Entry(old.identity(), old.credential(), State.EXPIRED, Instant.EPOCH, null), "SIMULATE_EXPIRY");
  }
  static void validateIdentifiers(String identity, String credential) {
    if (identity == null || credential == null || !identity.matches("SYNTHETIC-[a-z-]{1,40}") || !credential.matches("TEST-CREDENTIAL-[a-z-]{1,40}"))
      throw new IllegalArgumentException("Only synthetic identifiers are accepted");
  }
  public synchronized void begin(String identity, String credential) {
    check(); validateIdentifiers(identity, credential);
    if (entries.containsKey(credential)) throw new IllegalArgumentException("Only new synthetic credentials are accepted");
    update(new Entry(identity, credential, State.PENDING, Instant.EPOCH, null), "BEGIN_SIMULATED");
  }
  public synchronized void simulateProofing(String credential, String expectedIdentity) {
    Entry e = require(credential);
    if (e.state() != State.PENDING || !e.identity().equals(expectedIdentity)) throw new IllegalStateException("Invalid simulated proofing");
    update(new Entry(e.identity(), credential, State.PROOFED, e.expires(), e.replaces()), "PROOFING_SIMULATED");
  }
  public synchronized void activate(String credential, Instant expires) {
    Entry e = require(credential);
    if (e.state() != State.PROOFED || !expires.isAfter(clock.instant())) throw new IllegalStateException("Invalid activation");
    update(new Entry(e.identity(), credential, State.ACTIVE, expires, e.replaces()), "ACTIVATE_SIMULATED");
  }
  public synchronized void revoke(String credential) {
    Entry e = require(credential);
    if (e.state() == State.REVOKED) return;
    var next = new HashMap<>(entries); var versions = new HashMap<>(revocations);
    next.put(credential, new Entry(e.identity(), credential, State.REVOKED, e.expires(), e.replaces()));
    versions.merge(e.identity(), 1L, Math::addExact);
    commit(next, versions, "REVOKE", credential);
  }
  public synchronized void replace(String oldCredential, String newCredential, Instant expires) {
    Entry old = require(oldCredential), replacement = require(newCredential);
    if (oldCredential.equals(newCredential) || !old.identity().equals(replacement.identity()) || replacement.state() != State.PROOFED || !expires.isAfter(clock.instant()))
      throw new IllegalStateException("Replacement requires new simulated proofing of the same identity");
    var next = new HashMap<>(entries); var versions = new HashMap<>(revocations);
    next.put(oldCredential, new Entry(old.identity(), oldCredential, State.REVOKED, old.expires(), old.replaces()));
    next.put(newCredential, new Entry(old.identity(), newCredential, State.ACTIVE, expires, oldCredential));
    versions.merge(old.identity(), 1L, Math::addExact);
    commit(next, versions, "REPLACE_SIMULATED", newCredential);
  }
  public synchronized Entry authorize(String credential) {
    Entry e = require(credential);
    if (e.state() == State.ACTIVE && !e.expires().isAfter(clock.instant())) {
      e = new Entry(e.identity(), credential, State.EXPIRED, e.expires(), e.replaces()); update(e, "EXPIRE");
    }
    if (e.state() != State.ACTIVE) throw new IllegalStateException("Credential is not active");
    return e;
  }
  public synchronized Map<String, Long> revocationVersions() {
    check(); Map<String, Long> snapshot = new HashMap<>();
    entries.values().forEach(e -> snapshot.put(e.identity(), revocations.getOrDefault(e.identity(), 0L)));
    return Map.copyOf(snapshot);
  }
  public synchronized boolean activeIdentity(String identity, Long expectedRevocationVersion) {
    check();
    return Objects.equals(expectedRevocationVersion, revocations.getOrDefault(identity, 0L)) &&
        entries.values().stream().anyMatch(e -> e.identity().equals(identity) && e.state() == State.ACTIVE && e.expires().isAfter(clock.instant()));
  }
  public synchronized void recordOutcome(String transaction, OfflineReport.Outcome outcome) {
    check(); var event = new OfflineReport.Event(transaction, clock.instant(), outcome);
    if (store != null) store.outcome(transaction, outcome, event.at());
    else {
      var old = memoryOutcomes.putIfAbsent(transaction, event);
      if (old != null && old.outcome() != outcome) throw new IllegalStateException("Conflicting terminal outcome");
    }
  }
  public synchronized List<OfflineReport.Event> outcomes() { check(); return store != null ? store.outcomes() : List.copyOf(memoryOutcomes.values()); }
  public synchronized boolean ready() {
    try { check(); return true; } catch (IllegalStateException e) { return false; }
  }
  synchronized List<RegistryStore.Audit> audit() { check(); return store == null ? List.of() : store.audit(); }
  public synchronized void backup(Path destination) throws Exception {
    check(); if (store == null) throw new IllegalStateException("Backup requires persistent storage"); store.backup(destination);
  }
  public static void restore(Path backup, Path freshDirectory) throws Exception {
    if (!Files.isRegularFile(backup, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("A regular backup file is required");
    if (Files.exists(freshDirectory, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("Restore requires a new directory");
    TestKeys.initialize(freshDirectory); // Never copy authentication keys or sessions from a backup.
    Files.copy(backup, freshDirectory.resolve("registry.sqlite"));
    // Treat every restore as uncertain: a newer revocation could be absent from this backup.
    Files.writeString(freshDirectory.resolve("registry.running"), "Restored state: revoke all before use\n");
    try (var r = open(freshDirectory, Clock.systemUTC())) { r.revokeAll("RESTORE_REVOKE_ALL"); }
  }
  private synchronized void revokeAll(String reason) {
    var next = new HashMap<String, Entry>(); var versions = new HashMap<>(revocations);
    entries.values().forEach(e -> next.put(e.credential(), new Entry(e.identity(), e.credential(), State.REVOKED, e.expires(), e.replaces())));
    entries.values().stream().map(Entry::identity).distinct().forEach(id -> versions.merge(id, 1L, Math::addExact));
    commit(next, versions, reason, null);
  }
  private void update(Entry e, String action) { var next = new HashMap<>(entries); next.put(e.credential(), e); commit(next, revocations, action, e.credential()); }
  private void commit(Map<String, Entry> next, Map<String, Long> versions, String action, String credential) {
    check();
    if (store != null) store.commit(new RegistryStore.Snapshot(next, versions), action, credential, clock.instant());
    entries = Map.copyOf(next); revocations = Map.copyOf(versions); // Only publish after durable commit.
  }
  private void check() { if (closed) throw new IllegalStateException("Registry is closed"); if (store != null) store.check(); }
  private Entry require(String credential) {
    check(); Entry e = entries.get(credential);
    if (e == null) throw new IllegalArgumentException("Unknown test credential"); return e;
  }
  @Override public synchronized void close() throws Exception { if (!closed) { closed = true; if (store != null) store.close(); } }
}
