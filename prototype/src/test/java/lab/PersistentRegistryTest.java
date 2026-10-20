package lab;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.*;
import java.time.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class PersistentRegistryTest {
  @TempDir Path temporary;
  Path state;
  static final String ALICE = "TEST-CREDENTIAL-alice", ID = "SYNTHETIC-alice";
  @BeforeEach void initialize() throws Exception {
    state = temporary.resolve("state"); Files.createDirectory(state);
    Files.setPosixFilePermissions(state, PosixFilePermissions.fromString("rwx------"));
    SyntheticRegistry.initialize(state);
  }
  SyntheticRegistry open() throws Exception { return SyntheticRegistry.open(state, Clock.systemUTC()); }
  Connection sql() throws Exception { return DriverManager.getConnection("jdbc:sqlite:" + state.resolve("registry.sqlite")); }

  @Test void revocationSurvivesRestartWithoutReseeding() throws Exception {
    long version;
    try (var r = open()) { r.authorize(ALICE); r.revoke(ALICE); version = r.revocationVersions().get(ID); }
    try (var r = open()) {
      assertThrows(IllegalStateException.class, () -> r.authorize(ALICE));
      assertEquals(version, r.revocationVersions().get(ID));
      assertEquals("REVOKE", r.audit().getLast().action());
    }
  }
  @Test void publicKeyAndSignatureCounterSurviveOrderlyRestart() throws Exception {
    var authenticator = new TestAuthenticator(); var session = new org.springframework.mock.web.MockHttpSession();
    Passkey saved;
    try (var r = open()) {
      var web = new lab.idp.WebAuthnService(r, authenticator.origin, Clock.systemUTC(), true);
      web.finishRegistration(session, authenticator.registration(web.beginRegistration(session, ALICE, "acknowledged")));
      web.finishAuthentication(session, "flow", authenticator.assertion(web.beginAuthentication(session, ALICE, "flow"), 1));
      saved = r.passkeys().get(ALICE);
    }
    try (var r = open()) {
      assertEquals(saved, r.passkeys().get(ALICE));
      var web = new lab.idp.WebAuthnService(r, authenticator.origin, Clock.systemUTC(), true);
      assertEquals(ALICE, web.finishAuthentication(session, "flow", authenticator.assertion(web.beginAuthentication(session, ALICE, "flow"), 2)));
      assertEquals(2, r.passkeys().get(ALICE).signatureCount());
    }
  }
  @Test void schemaOneMigratesWithoutLosingRevocations() throws Exception {
    try (var r = open()) { r.revoke(ALICE); }
    try (var c = sql(); var s = c.createStatement()) { s.execute("DROP TABLE passkeys"); s.execute("PRAGMA user_version=1"); }
    try (var r = open(); var c = sql(); var s = c.createStatement()) {
      assertTrue(r.passkeys().isEmpty()); assertThrows(IllegalStateException.class, () -> r.authorize(ALICE));
      try (var rows = s.executeQuery("PRAGMA user_version")) { assertTrue(rows.next()); assertEquals(2, rows.getInt(1)); }
    }
  }
  @Test void enrollmentAndAuditCommitAtomically() throws Exception {
    var authenticator = new TestAuthenticator(); var session = new org.springframework.mock.web.MockHttpSession();
    try (var r = open(); var c = sql(); var s = c.createStatement()) {
      var web = new lab.idp.WebAuthnService(r, authenticator.origin, Clock.systemUTC(), true);
      String response = authenticator.registration(web.beginRegistration(session, ALICE, "acknowledged"));
      s.execute("CREATE TRIGGER inject_audit_failure BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'injected'); END");
      assertThrows(lab.idp.WebAuthnService.Rejected.class, () -> web.finishRegistration(session, response));
      assertFalse(r.ready());
      try (var rows = s.executeQuery("SELECT COUNT(*) FROM passkeys")) { assertTrue(rows.next()); assertEquals(0, rows.getInt(1)); }
      s.execute("DROP TRIGGER inject_audit_failure");
    }
  }
  @Test void restoringAnOldPublicKeyBackupNeverRestoresItsUsability() throws Exception {
    var authenticator = new TestAuthenticator(); var session = new org.springframework.mock.web.MockHttpSession();
    Path backup = state.resolve("keys-backup.sqlite"), restored = temporary.resolve("restored-key");
    try (var r = open()) {
      var web = new lab.idp.WebAuthnService(r, authenticator.origin, Clock.systemUTC(), true);
      web.finishRegistration(session, authenticator.registration(web.beginRegistration(session, ALICE, "acknowledged")));
      r.backup(backup); r.revoke(ALICE);
    }
    SyntheticRegistry.restore(backup, restored);
    try (var r = SyntheticRegistry.open(restored, Clock.systemUTC())) {
      assertTrue(r.passkeys().containsKey(ALICE));
      var web = new lab.idp.WebAuthnService(r, authenticator.origin, Clock.systemUTC(), true);
      assertThrows(IllegalStateException.class, () -> web.beginAuthentication(session, ALICE, "flow"));
    }
  }
  @Test void orderlyRestartKeepsExistingValidityAndDoesNotExtendLifetime() throws Exception {
    Instant expires;
    try (var r = open()) { expires = r.authorize(ALICE).expires(); }
    try (var r = open()) { assertEquals(expires, r.authorize(ALICE).expires()); }
    try (var r = SyntheticRegistry.open(state, Clock.fixed(expires, ZoneOffset.UTC))) {
      assertThrows(IllegalStateException.class, () -> r.authorize(ALICE));
    }
  }
  @Test void aSecondProcessCannotUseStaleInMemoryState() throws Exception {
    try (var r = open()) { assertThrows(Exception.class, this::open); r.authorize(ALICE); }
    try (var r = open()) { r.authorize(ALICE); }
  }
  @Test void missingDatabaseIsNeverRecreatedAtStartup() throws Exception {
    Files.delete(state.resolve("registry.sqlite"));
    assertThrows(IllegalStateException.class, this::open);
    assertFalse(Files.exists(state.resolve("registry.sqlite")));
  }
  @Test void initNeverOverwritesExistingRevocations() throws Exception {
    try (var r = open()) { r.revoke(ALICE); }
    assertThrows(IllegalStateException.class, () -> SyntheticRegistry.initialize(state));
    try (var r = open()) { assertThrows(IllegalStateException.class, () -> r.authorize(ALICE)); }
  }
  @Test void incompatibleSchemaAndCorruptionFailClosed() throws Exception {
    try (var c = sql(); var s = c.createStatement()) { s.execute("PRAGMA user_version=99"); }
    assertThrows(IllegalStateException.class, this::open);
    Files.writeString(state.resolve("registry.sqlite"), "corrupt");
    assertThrows(Exception.class, this::open);
  }
  @Test void productionMarkerIsRejected() throws Exception {
    try (var c = sql(); var s = c.createStatement()) {
      s.execute("PRAGMA ignore_check_constraints=ON"); s.execute("UPDATE configuration SET environment='PRODUCTION'");
    }
    assertThrows(IllegalStateException.class, this::open);
  }
  @Test void auditFailureRollsBackStateAndDisablesAllAuthentication() throws Exception {
    try (var r = open(); var c = sql(); var s = c.createStatement()) {
      s.execute("CREATE TRIGGER inject_audit_failure BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'injected'); END");
      assertThrows(IllegalStateException.class, () -> r.revoke(ALICE));
      assertThrows(IllegalStateException.class, () -> r.authorize(ALICE));
      assertThrows(IllegalStateException.class, () -> r.activeIdentity(ID, 0L));
      assertFalse(r.ready());
      try (var rows = s.executeQuery("SELECT state FROM credentials WHERE credential='TEST-CREDENTIAL-alice'")) {
        assertTrue(rows.next()); assertEquals("ACTIVE", rows.getString(1)); // The entire failed transaction rolled back.
      }
      s.execute("DROP TRIGGER inject_audit_failure");
    }
    assertTrue(Files.exists(state.resolve("registry.running")));
    try (var r = open()) { assertThrows(IllegalStateException.class, () -> r.authorize(ALICE)); }
  }
  @Test void uncleanShutdownRevokesBeforeAnyAuthentication() throws Exception {
    Files.writeString(state.resolve("registry.running"), "crashed");
    try (var r = open()) {
      assertThrows(IllegalStateException.class, () -> r.authorize(ALICE));
      assertEquals("UNCLEAN_RECOVERY", r.audit().getLast().action());
    }
  }
  @Test void concurrentRevocationIsIdempotentAndDurable() throws Exception {
    try (var r = open(); var executor = Executors.newFixedThreadPool(8)) {
      var tasks = new java.util.ArrayList<Future<?>>();
      for (int i=0;i<16;i++) tasks.add(executor.submit(() -> r.revoke(ALICE)));
      for (var t : tasks) t.get(5, TimeUnit.SECONDS);
      assertEquals(1L, r.revocationVersions().get(ID));
    }
    try (var r = open()) { assertEquals(1L, r.revocationVersions().get(ID)); }
  }
  @Test void replacementAndRevocationCommitTogether() throws Exception {
    String next = "TEST-CREDENTIAL-replacement";
    try (var r = open()) {
      r.begin(ID, next); r.simulateProofing(next, ID); r.replace(ALICE, next, Instant.now().plusSeconds(100));
    }
    try (var r = open()) {
      assertThrows(IllegalStateException.class, () -> r.authorize(ALICE));
      assertEquals(ALICE, r.authorize(next).replaces());
      assertEquals(1L, r.revocationVersions().get(ID));
      assertEquals("REPLACE_SIMULATED", r.audit().getLast().action());
    }
  }
  @Test void auditAndOutcomesCannotBeEditedThroughOrdinarySql() throws Exception {
    try (var r = open()) { r.recordOutcome("a".repeat(64), OfflineReport.Outcome.SUCCESS); }
    try (var c = sql(); var s = c.createStatement()) {
      assertThrows(SQLException.class, () -> s.execute("DELETE FROM audit"));
      assertThrows(SQLException.class, () -> s.execute("UPDATE audit SET action='changed'"));
      assertThrows(SQLException.class, () -> s.execute("DELETE FROM outcomes"));
      assertThrows(SQLException.class, () -> s.execute("UPDATE outcomes SET outcome='FAILED'"));
    }
  }
  @Test void terminalEventsAreDurableDeduplicatedAndConflictsAreRejected() throws Exception {
    String id = "b".repeat(64);
    try (var r = open()) {
      r.recordOutcome(id, OfflineReport.Outcome.SUCCESS); r.recordOutcome(id, OfflineReport.Outcome.SUCCESS);
      assertThrows(IllegalStateException.class, () -> r.recordOutcome(id, OfflineReport.Outcome.FAILED));
    }
    try (var r = open()) { assertEquals(1, r.outcomes().size()); }
  }
  @Test void worldReadableStateAndSymlinkDirectoriesAreRejected() throws Exception {
    Files.setPosixFilePermissions(state, PosixFilePermissions.fromString("rwxr-xr-x"));
    assertThrows(IllegalArgumentException.class, this::open);
    Files.setPosixFilePermissions(state, PosixFilePermissions.fromString("rwx------"));
    Path link = temporary.resolve("link"); Files.createSymbolicLink(link, state);
    assertThrows(IllegalArgumentException.class, () -> SyntheticRegistry.open(link, Clock.systemUTC()));
  }
  @Test void oldBackupCannotResurrectARevokedCredential() throws Exception {
    Path backup = state.resolve("backup.sqlite"), restored = temporary.resolve("restored");
    try (var r = open()) { r.backup(backup); r.revoke(ALICE); }
    SyntheticRegistry.restore(backup, restored);
    try (var r = SyntheticRegistry.open(restored, Clock.systemUTC())) {
      assertThrows(IllegalStateException.class, () -> r.authorize(ALICE));
      assertFalse(r.activeIdentity(ID, 0L));
      assertEquals("RESTORE_REVOKE_ALL", r.audit().getLast().action());
    }
    assertThrows(IllegalArgumentException.class, () -> SyntheticRegistry.restore(backup, restored));
  }
  @Test void backupDoesNotOverwriteAndContainsOnlyRegistryAndPublicKeys() throws Exception {
    Path backup = state.resolve("backup.sqlite");
    try (var r = open()) {
      r.backup(backup);
      assertThrows(IllegalArgumentException.class, () -> r.backup(backup));
    }
    try (var c = DriverManager.getConnection("jdbc:sqlite:" + backup); var s = c.createStatement();
        var rows = s.executeQuery("SELECT name FROM sqlite_master WHERE type='table'")) {
      var names = new java.util.HashSet<String>(); while (rows.next()) names.add(rows.getString(1));
      assertEquals(java.util.Set.of("configuration", "credentials", "revocations", "audit", "outcomes", "sqlite_sequence", "passkeys"), names);
    }
  }
}
