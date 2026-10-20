package lab;

import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.*;
import java.time.Instant;
import java.util.*;

/** Single-process synthetic lab storage. SQLite supplies transactions, locking and backup. */
final class RegistryStore implements AutoCloseable {
  record Snapshot(Map<String, SyntheticRegistry.Entry> entries, Map<String, Long> versions, Map<String, Passkey> passkeys) {}
  record Audit(long sequence, String time, String action, String credential) {}
  private final Path directory, database;
  private FileChannel lockChannel;
  private FileLock lock;
  private Connection connection;
  private boolean failed, closed;
  final boolean uncleanShutdown;

  RegistryStore(Path directory, boolean initialize) throws Exception {
    this.directory = directory.toAbsolutePath().normalize();
    database = this.directory.resolve("registry.sqlite");
    requirePrivateDirectory(this.directory);
    if (Files.isSymbolicLink(database) || Files.isSymbolicLink(this.directory.resolve("registry.lock")) ||
        Files.isSymbolicLink(this.directory.resolve("registry.running"))) throw new IllegalArgumentException("Symlink state is not accepted");
    if (initialize == Files.exists(database)) throw new IllegalStateException("Initialize a new registry, or open an existing one explicitly");
    uncleanShutdown = Files.exists(this.directory.resolve("registry.running"));
    try {
      lockChannel = FileChannel.open(this.directory.resolve("registry.lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
      lock = lockChannel.tryLock();
      if (lock == null) throw new IllegalStateException("Registry already in use");
      Class.forName("org.sqlite.JDBC");
      connection = DriverManager.getConnection("jdbc:sqlite:" + database);
      Files.setPosixFilePermissions(database, PosixFilePermissions.fromString("rw-------"));
      execute("PRAGMA foreign_keys=ON");
      execute("PRAGMA busy_timeout=2000");
      execute("PRAGMA journal_mode=WAL");
      execute("PRAGMA synchronous=FULL");
      if (initialize) initializeSchema();
      int version;
      try (var s = connection.createStatement(); var r = s.executeQuery("PRAGMA user_version")) {
        if (!r.next()) throw new IllegalStateException("Unsupported registry schema");
        version = r.getInt(1);
      }
      if (version == 1) migratePasskeys();
      else if (version != 2) throw new IllegalStateException("Unsupported registry schema");
      try (var s = connection.createStatement(); var r = s.executeQuery("PRAGMA integrity_check")) {
        if (!r.next() || !r.getString(1).equals("ok")) throw new IllegalStateException("Registry integrity check failed");
      }
      try (var s = connection.createStatement(); var r = s.executeQuery("SELECT environment FROM configuration")) {
        if (!r.next() || !r.getString(1).equals("SYNTHETIC_ONLY") || r.next()) throw new IllegalStateException("Invalid registry environment");
      }
      Files.writeString(this.directory.resolve("registry.running"), "Unclean restart requires revoking all credentials\n");
      try (var marker = FileChannel.open(this.directory.resolve("registry.running"), StandardOpenOption.WRITE)) { marker.force(true); }
      syncDirectory();
    } catch (Exception e) {
      failed = true; close(); throw e;
    }
  }
  private void migratePasskeys() throws SQLException {
    connection.setAutoCommit(false);
    try {
      execute("CREATE TABLE passkeys (credential TEXT PRIMARY KEY, credential_id TEXT UNIQUE NOT NULL, user_handle TEXT UNIQUE NOT NULL, public_key_cose TEXT NOT NULL, signature_count INTEGER NOT NULL CHECK(signature_count>=0), backup_eligible INTEGER NOT NULL CHECK(backup_eligible IN (0,1)), backed_up INTEGER NOT NULL CHECK(backed_up IN (0,1)))");
      execute("PRAGMA user_version=2");
      connection.commit();
    } catch (SQLException e) { connection.rollback(); throw e; }
    finally { connection.setAutoCommit(true); }
  }

  static void requirePrivateDirectory(Path directory) throws Exception {
    if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(directory) ||
        !directory.toRealPath().equals(directory.toAbsolutePath().normalize()) ||
        !Files.getPosixFilePermissions(directory).equals(PosixFilePermissions.fromString("rwx------")))
      throw new IllegalArgumentException("State requires a real private POSIX directory (0700)");
  }
  private void initializeSchema() throws SQLException {
    connection.setAutoCommit(false);
    try {
      execute("CREATE TABLE configuration (environment TEXT NOT NULL CHECK(environment='SYNTHETIC_ONLY'))");
      execute("INSERT INTO configuration VALUES ('SYNTHETIC_ONLY')");
      execute("CREATE TABLE credentials (credential TEXT PRIMARY KEY, identity TEXT NOT NULL, state TEXT NOT NULL, expires TEXT NOT NULL, replaces TEXT)");
      execute("CREATE TABLE revocations (identity TEXT PRIMARY KEY, version INTEGER NOT NULL CHECK(version>=0))");
      execute("CREATE TABLE audit (sequence INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, action TEXT NOT NULL, credential TEXT)");
      execute("CREATE TABLE outcomes (transaction_id TEXT PRIMARY KEY, time TEXT NOT NULL, outcome TEXT NOT NULL CHECK(outcome IN ('SUCCESS','CANCELLED','FAILED')))");
      for (String table : List.of("audit", "outcomes")) for (String operation : List.of("UPDATE", "DELETE"))
        execute("CREATE TRIGGER immutable_" + table + "_" + operation + " BEFORE " + operation + " ON " + table + " BEGIN SELECT RAISE(ABORT, 'immutable event'); END");
      execute("PRAGMA user_version=1");
      connection.commit();
    } catch (SQLException e) { connection.rollback(); throw e; }
    finally { connection.setAutoCommit(true); }
  }
  Snapshot load() {
    check();
    try {
      Map<String, SyntheticRegistry.Entry> entries = new HashMap<>();
      Map<String, Long> versions = new HashMap<>();
      Map<String, Passkey> passkeys = new HashMap<>();
      try (var s = connection.createStatement(); var r = s.executeQuery("SELECT * FROM credentials")) {
        while (r.next()) {
          var e = new SyntheticRegistry.Entry(r.getString("identity"), r.getString("credential"),
              SyntheticRegistry.State.valueOf(r.getString("state")), Instant.parse(r.getString("expires")), r.getString("replaces"));
          SyntheticRegistry.validateIdentifiers(e.identity(), e.credential());
          entries.put(e.credential(), e);
        }
      }
      try (var s = connection.createStatement(); var r = s.executeQuery("SELECT * FROM revocations")) {
        while (r.next()) {
          if (!r.getString("identity").matches("SYNTHETIC-[a-z-]{1,40}") || r.getLong("version") < 0) throw new IllegalStateException("Invalid revocation state");
          versions.put(r.getString("identity"), r.getLong("version"));
        }
      }
      try (var s = connection.createStatement(); var r = s.executeQuery("SELECT * FROM passkeys")) {
        while (r.next()) {
          String credential = r.getString("credential");
          if (!entries.containsKey(credential)) throw new IllegalStateException("Orphaned passkey");
          passkeys.put(credential, new Passkey(r.getString("credential_id"), r.getString("user_handle"),
              r.getString("public_key_cose"), r.getLong("signature_count"), r.getBoolean("backup_eligible"), r.getBoolean("backed_up")));
        }
      }
      return new Snapshot(Map.copyOf(entries), Map.copyOf(versions), Map.copyOf(passkeys));
    } catch (SQLException | IllegalArgumentException e) { throw unavailable(); }
  }
  void commit(Snapshot next, String action, String credential, Instant now) {
    check();
    try {
      connection.setAutoCommit(false);
      execute("DELETE FROM credentials"); execute("DELETE FROM revocations");
      execute("DELETE FROM passkeys");
      try (var p = connection.prepareStatement("INSERT INTO credentials VALUES (?,?,?,?,?)")) {
        for (var e : next.entries().values()) {
          p.setString(1, e.credential()); p.setString(2, e.identity()); p.setString(3, e.state().name());
          p.setString(4, e.expires().toString()); p.setString(5, e.replaces()); p.addBatch();
        }
        p.executeBatch();
      }
      try (var p = connection.prepareStatement("INSERT INTO revocations VALUES (?,?)")) {
        for (var e : next.versions().entrySet()) { p.setString(1, e.getKey()); p.setLong(2, e.getValue()); p.addBatch(); }
        p.executeBatch();
      }
      try (var p = connection.prepareStatement("INSERT INTO audit(time,action,credential) VALUES (?,?,?)")) {
        p.setString(1, now.toString()); p.setString(2, action); p.setString(3, credential); p.executeUpdate();
      }
      try (var p = connection.prepareStatement("INSERT INTO passkeys VALUES (?,?,?,?,?,?,?)")) {
        for (var e : next.passkeys().entrySet()) {
          Passkey k = e.getValue();
          p.setString(1, e.getKey()); p.setString(2, k.credentialId()); p.setString(3, k.userHandle());
          p.setString(4, k.publicKeyCose()); p.setLong(5, k.signatureCount());
          p.setBoolean(6, k.backupEligible()); p.setBoolean(7, k.backedUp()); p.addBatch();
        }
        p.executeBatch();
      }
      connection.commit(); connection.setAutoCommit(true);
    } catch (SQLException e) {
      try { connection.rollback(); } catch (SQLException ignored) { }
      throw unavailable();
    }
  }
  void outcome(String transaction, OfflineReport.Outcome outcome, Instant now) {
    check();
    try (var p = connection.prepareStatement("INSERT INTO outcomes VALUES (?,?,?) ON CONFLICT(transaction_id) DO NOTHING")) {
      p.setString(1, transaction); p.setString(2, now.toString()); p.setString(3, outcome.name());
      if (p.executeUpdate() == 0) {
        try (var q = connection.prepareStatement("SELECT outcome FROM outcomes WHERE transaction_id=?")) {
          q.setString(1, transaction);
          try (var r = q.executeQuery()) {
            if (!r.next() || !r.getString(1).equals(outcome.name())) throw new IllegalStateException("Conflicting terminal outcome");
          }
        }
      }
    } catch (SQLException e) { throw unavailable(); }
  }
  List<OfflineReport.Event> outcomes() {
    check();
    try (var s = connection.createStatement(); var r = s.executeQuery("SELECT * FROM outcomes ORDER BY transaction_id")) {
      List<OfflineReport.Event> events = new ArrayList<>();
      while (r.next()) events.add(new OfflineReport.Event(r.getString(1), Instant.parse(r.getString(2)), OfflineReport.Outcome.valueOf(r.getString(3))));
      return List.copyOf(events);
    } catch (SQLException e) { throw unavailable(); }
  }
  List<Audit> audit() {
    check();
    try (var s = connection.createStatement(); var r = s.executeQuery("SELECT * FROM audit ORDER BY sequence")) {
      List<Audit> events = new ArrayList<>();
      while (r.next()) events.add(new Audit(r.getLong(1), r.getString(2), r.getString(3), r.getString(4)));
      return List.copyOf(events);
    } catch (SQLException e) { throw unavailable(); }
  }
  void backup(Path destination) throws Exception {
    check();
    requirePrivateDirectory(destination.toAbsolutePath().getParent());
    if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("Backup destination must be new");
    try (var p = connection.prepareStatement("VACUUM INTO ?")) {
      p.setString(1, destination.toAbsolutePath().toString()); p.execute();
      Files.setPosixFilePermissions(destination, PosixFilePermissions.fromString("rw-------"));
    }
  }
  void check() {
    if (failed || closed || connection == null || !Files.isRegularFile(database, LinkOption.NOFOLLOW_LINKS)) throw unavailable();
    try (var s = connection.createStatement()) { s.executeQuery("SELECT 1").close(); }
    catch (SQLException e) { throw unavailable(); }
  }
  private void execute(String sql) throws SQLException { try (var s = connection.createStatement()) { s.execute(sql); } }
  private void syncDirectory() throws java.io.IOException {
    try (var dir = FileChannel.open(directory, StandardOpenOption.READ)) { dir.force(true); }
  }
  private IllegalStateException unavailable() { failed = true; return new IllegalStateException("Registry unavailable; authentication disabled"); }
  @Override public void close() throws Exception {
    if (closed) return;
    closed = true;
    try { if (connection != null) connection.close(); }
    finally {
      try { if (lock != null && lock.isValid()) {
        try { if (!failed) { Files.deleteIfExists(directory.resolve("registry.running")); syncDirectory(); } }
        finally { lock.release(); }
      } }
      finally { if (lockChannel != null) lockChannel.close(); }
    }
  }
}
