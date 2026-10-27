"""Actual SQLite snapshots and adversarial offline archive verification."""
import hashlib
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import audit_archive as archive

REVISION = 'a'*40


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.db = self.root/'wallet.sqlite'
        self.destination = self.root/'archive'
        with closing(sqlite3.connect(self.db)) as db, db:
            db.executescript('''PRAGMA journal_mode=WAL;
                CREATE TABLE credentials(id TEXT PRIMARY KEY,public_key TEXT,state TEXT,created INTEGER,
                    expires INTEGER,decision TEXT,subject TEXT);
                CREATE TABLE profiles(credential TEXT,version TEXT,verified INTEGER,document_expires INTEGER,
                    sealed TEXT,person TEXT);
                CREATE TABLE events(id INTEGER PRIMARY KEY,credential TEXT,kind TEXT,time INTEGER,request TEXT);
                CREATE TABLE security_codes(hash TEXT);
                INSERT INTO credentials VALUES('credential','public-key','ACTIVE',1000,2000,'REVIEW-example','PRIVATE_SUBJECT');
                INSERT INTO profiles VALUES('credential','proof-version',1000,3000,'PRIVATE_SEALED_PROFILE','PRIVATE_PERSON_TAG');
                INSERT INTO events VALUES(1,'credential','ACTIVATED',1000,NULL);
                INSERT INTO security_codes VALUES('PRIVATE_PIN_VERIFIER');''')

    def export(self, **kwargs):
        return archive.export_snapshot(archive.sqlite_snapshot(self.db), self.destination, 'sqlite', REVISION, **kwargs)

    def journal_schema(self, insert=True):
        policy = {'version': 1, 'reference': 'TEST_POLICY_001', 'profileDays': 7,
                  'authenticationRequestDays': 1}
        digest = hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        counts = json.dumps(dict(profiles=1, security_codes=1, requests=2, federation_requests=0))
        row = [1, 2000, policy['reference'], digest, 7, 1, counts]
        with closing(sqlite3.connect(self.db)) as db, db:
            db.executescript('''CREATE TABLE profile_evidence(credential TEXT,version TEXT,
                verified INTEGER,document_expires INTEGER,purged INTEGER);
                CREATE TABLE retention_runs(id INTEGER PRIMARY KEY,time INTEGER,policy_ref TEXT,
                policy_sha256 TEXT,profile_days INTEGER,request_days INTEGER,counts TEXT);''')
            if insert: db.execute('INSERT INTO retention_runs VALUES(?,?,?,?,?,?,?)', row)
        return row

    def test_roundtrip_offline_without_identity_keys_and_minimal_private_data(self):
        receipt = self.export()
        self.db.unlink()  # Verification has no database, application or key dependency.
        result = archive.verify(self.destination, receipt['manifestSha256'])
        self.assertEqual(1, json.loads((self.destination/'manifest.json').read_bytes())['format'])
        self.assertEqual('VERIFIED', result['state']); self.assertEqual(3, result['rows'])
        self.assertEqual(receipt['bytes'], result['bytes'])
        combined = b''.join(p.read_bytes() for p in self.destination.iterdir())
        self.assertNotIn(b'PRIVATE_', combined)
        self.assertIn(b'public-key', combined); self.assertIn(b'REVIEW-example', combined)
        self.assertEqual(0o700, self.destination.stat().st_mode & 0o777)
        for path in self.destination.iterdir():self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_concurrent_revocation_cannot_split_the_snapshot_across_tables(self):
        original = archive.write_table
        def concurrent(*args):
            result = original(*args)
            if args[2] == 'credentials':
                with closing(sqlite3.connect(self.db)) as db, db:
                    db.execute("UPDATE credentials SET state='REVOKED'")
                    db.execute("INSERT INTO events VALUES(2,'credential','REVOKED',1001,NULL)")
            return result
        with patch.object(archive, 'write_table', side_effect=concurrent):receipt = self.export()
        archive.verify(self.destination, receipt['manifestSha256'])
        self.assertIn('ACTIVE', (self.destination/'credentials.jsonl').read_text())
        self.assertNotIn('REVOKED', (self.destination/'events.jsonl').read_text())
        with closing(sqlite3.connect(self.db)) as db, db:self.assertEqual('REVOKED', db.execute('SELECT state FROM credentials').fetchone()[0])

    def test_changed_data_and_rewritten_manifest_do_not_match_external_anchor(self):
        receipt = self.export(); path = self.destination/'events.jsonl'
        path.write_bytes(path.read_bytes().replace(b'ACTIVATED', b'FORGERY!!'))
        with self.assertRaises(ValueError):archive.verify(self.destination, receipt['manifestSha256'])
        manifest = self.destination/'manifest.json'; data = json.loads(manifest.read_bytes())
        data['files']['events.jsonl']['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest.write_bytes(archive.encoded(data))
        with self.assertRaises(ValueError):archive.verify(self.destination, receipt['manifestSha256'])

    def test_missing_extra_symlink_and_public_files_are_rejected(self):
        receipt = self.export(); digest = receipt['manifestSha256']; path = self.destination/'events.jsonl'
        content = path.read_bytes(); path.unlink()
        with self.assertRaises(ValueError):archive.verify(self.destination, digest)
        outside = self.root/'outside'; outside.write_bytes(content); outside.chmod(0o600)
        path.symlink_to(outside)
        with self.assertRaises(OSError):archive.verify(self.destination, digest)
        path.unlink(); path.write_bytes(content); path.chmod(0o644)
        with self.assertRaises(ValueError):archive.verify(self.destination, digest)
        path.chmod(0o600); extra = self.destination/'unexpected'; extra.touch(mode=0o600)
        with self.assertRaises(ValueError):archive.verify(self.destination, digest)
        extra.unlink(); self.destination.chmod(0o755)
        with self.assertRaises(ValueError):archive.verify(self.destination, digest)

    def test_size_and_row_limits_remove_partial_output_and_never_overwrite(self):
        with self.assertRaises(ValueError):self.export(max_bytes=20)
        self.assertFalse(self.destination.exists())
        with patch.object(archive, 'MAX_ROWS', 0):
            with self.assertRaises(ValueError):self.export()
        self.assertFalse(self.destination.exists())
        self.destination.mkdir(); sentinel = self.destination/'keep'; sentinel.write_text('existing')
        with self.assertRaises(FileExistsError):self.export()
        self.assertEqual('existing', sentinel.read_text())

    def test_failed_read_transaction_never_publishes_manifest(self):
        with closing(sqlite3.connect(self.db)) as db, db:db.execute('DROP TABLE events')
        with self.assertRaises(sqlite3.Error):self.export()
        self.assertFalse(self.destination.exists())

    def test_invalid_database_types_do_not_publish_an_unverifiable_archive(self):
        with closing(sqlite3.connect(self.db)) as db, db:db.execute('UPDATE credentials SET created=1.25')
        with self.assertRaises(ValueError):self.export()
        self.assertFalse(self.destination.exists())

    def test_missing_database_is_not_created_and_invalid_revision_is_rejected(self):
        self.db.unlink()
        with self.assertRaises(ValueError):self.export()
        self.assertFalse(self.db.exists()); self.assertFalse(self.destination.exists())
        for revision in ('main', 'a'*39, 'A'*40):
            with self.assertRaises(ValueError):
                archive.export_snapshot(archive.sqlite_snapshot(self.db), self.destination, 'sqlite', revision)

    def test_deadline_and_malformed_anchored_inventory_fail_closed(self):
        with patch.object(archive, 'deadline', side_effect=TimeoutError):
            with self.assertRaises(TimeoutError):self.export()
        self.assertFalse(self.destination.exists()); self.export()
        path = self.destination/'manifest.json'; data = json.loads(path.read_bytes())
        data['files']['../outside'] = data['files'].pop('events.jsonl')
        raw = archive.encoded(data); path.write_bytes(raw)
        with self.assertRaises(ValueError):archive.verify(self.destination, hashlib.sha256(raw).hexdigest())

    def test_verification_rejects_truncation_row_count_and_duplicate_manifest_keys(self):
        self.export(); path = self.destination/'manifest.json'; original = path.read_bytes()
        events = self.destination/'events.jsonl'; saved = events.read_bytes()
        events.write_bytes(saved[:-4])
        with self.assertRaises(ValueError):archive.verify(self.destination, hashlib.sha256(original).hexdigest())
        events.write_bytes(saved)
        data = json.loads(original); data['files']['events.jsonl']['rows'] = 2
        raw = archive.encoded(data); path.write_bytes(raw)
        with self.assertRaises(ValueError):archive.verify(self.destination, hashlib.sha256(raw).hexdigest())
        raw = original.replace(b'"format":1', b'"format":1,"format":1')
        path.write_bytes(raw)
        with self.assertRaises(ValueError):archive.verify(self.destination, hashlib.sha256(raw).hexdigest())

    def test_cli_requires_external_digest_and_does_not_log_sensitive_failure(self):
        receipt = self.export(); command = [sys.executable, str(Path(archive.__file__)), 'verify', '--source', str(self.destination)]
        run = subprocess.run(command+['--manifest-sha256', receipt['manifestSha256']], capture_output=True)
        self.assertEqual(0, run.returncode); self.assertEqual('VERIFIED', json.loads(run.stdout)['state'])
        run = subprocess.run(command, capture_output=True); self.assertNotEqual(0, run.returncode)
        secret = self.root/'PRIVATE-input'; secret.mkdir()
        run = subprocess.run([sys.executable, str(Path(archive.__file__)), 'verify', '--source', str(secret),
                              '--manifest-sha256', 'b'*64], capture_output=True)
        self.assertEqual(2, run.returncode); self.assertEqual(b'', run.stdout)
        self.assertNotIn(b'PRIVATE', run.stderr); self.assertNotIn(b'Traceback', run.stderr)

    def test_retention_journal_v2_offline_roundtrip_and_minimal_fields(self):
        row = self.journal_schema(); receipt = self.export()
        self.db.unlink()
        manifest = json.loads((self.destination/'manifest.json').read_bytes())
        self.assertEqual(2, manifest['format'])
        self.assertEqual(row, json.loads((self.destination/'retention_runs.jsonl').read_bytes()))
        self.assertEqual(4, archive.verify(self.destination, receipt['manifestSha256'])['rows'])
        self.assertNotIn(b'PRIVATE_', b''.join(p.read_bytes() for p in self.destination.iterdir()))
        journal = self.destination/'retention_runs.jsonl'
        self.assertEqual(0o600, journal.stat().st_mode & 0o777)
        journal.write_bytes(journal.read_bytes().replace(b'TEST_POLICY', b'FAKE_POLICY'))
        with self.assertRaises(ValueError): archive.verify(self.destination, receipt['manifestSha256'])

    def test_empty_journal_and_concurrent_insert_share_snapshot(self):
        row = self.journal_schema(insert=False); original = archive.write_table
        def concurrent(*args):
            result = original(*args)
            if args[2] == 'credentials':
                with closing(sqlite3.connect(self.db)) as db, db:
                    db.execute('INSERT INTO retention_runs VALUES(?,?,?,?,?,?,?)', row)
            return result
        with patch.object(archive, 'write_table', side_effect=concurrent): receipt = self.export()
        self.assertEqual(b'', (self.destination/'retention_runs.jsonl').read_bytes())
        self.assertEqual(3, archive.verify(self.destination, receipt['manifestSha256'])['rows'])
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(1, db.execute('SELECT count(*) FROM retention_runs').fetchone()[0])

    def test_partial_retention_schema_cannot_downgrade_export(self):
        self.journal_schema()
        with closing(sqlite3.connect(self.db)) as db, db: db.execute('DROP TABLE retention_runs')
        with self.assertRaisesRegex(ValueError, 'incomplete retention schema'): self.export()
        self.assertFalse(self.destination.exists())
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('DROP TABLE profile_evidence'); db.execute('CREATE TABLE retention_runs(id INTEGER)')
        with self.assertRaisesRegex(ValueError, 'incomplete retention schema'): self.export()
        self.assertFalse(self.destination.exists())
        with closing(sqlite3.connect(self.db)) as db, db:
            db.executescript('''DROP TABLE retention_runs;
                CREATE VIEW retention_runs AS SELECT 1 AS id;
                CREATE VIEW profile_evidence AS SELECT 1 AS credential;''')
        with self.assertRaisesRegex(ValueError, 'incomplete retention schema'): self.export()
        self.assertFalse(self.destination.exists())

    def test_invalid_journal_rejected_at_export_and_even_with_new_trusted_digest(self):
        row = self.journal_schema(); self.export()
        manifest_path = self.destination/'manifest.json'
        manifest = json.loads(manifest_path.read_bytes())
        for column, value in [(0, 0), (1, -1), (2, 'PRIVATE PERSON'), (3, 'a'*64),
                (4, 0), (5, 3651), (6, '{}'), (6, '{"profiles":1,"profiles":2}'),
                (6, json.dumps(dict(profiles=True, security_codes=0, requests=0, federation_requests=0))),
                (6, json.dumps(dict(profiles=1001, security_codes=0, requests=0, federation_requests=0)))]:
            with self.subTest(column=column, value=value):
                changed = row.copy(); changed[column] = value
                with closing(sqlite3.connect(self.db)) as db, db:
                    db.execute('DELETE FROM retention_runs')
                    db.execute('INSERT INTO retention_runs VALUES(?,?,?,?,?,?,?)', changed)
                dest = self.root/'invalid-export'
                with self.assertRaises(ValueError):
                    archive.export_snapshot(archive.sqlite_snapshot(self.db), dest, 'sqlite', REVISION)
                self.assertFalse(dest.exists())
                raw = archive.encoded(changed)
                (self.destination/'retention_runs.jsonl').write_bytes(raw)
                info = manifest['files']['retention_runs.jsonl']
                info.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                raw_manifest = archive.encoded(manifest); manifest_path.write_bytes(raw_manifest)
                with self.assertRaises(ValueError):
                    archive.verify(self.destination, hashlib.sha256(raw_manifest).hexdigest())

    def test_v2_requires_journal_and_rejects_unknown_or_postgres_versions(self):
        self.journal_schema(); receipt = self.export()
        journal = self.destination/'retention_runs.jsonl'; journal.unlink()
        with self.assertRaises(ValueError): archive.verify(self.destination, receipt['manifestSha256'])
        manifest_path = self.destination/'manifest.json'; manifest = json.loads(manifest_path.read_bytes())
        del manifest['files']['retention_runs.jsonl']
        raw = archive.encoded(manifest); manifest_path.write_bytes(raw)
        with self.assertRaises(ValueError): archive.verify(self.destination, hashlib.sha256(raw).hexdigest())
        for version, backend in [(3, 'sqlite'), (True, 'sqlite'), (2, 'postgresql')]:
            manifest.update(format=version, backend=backend)
            raw = archive.encoded(manifest); manifest_path.write_bytes(raw)
            with self.assertRaises(ValueError): archive.verify(self.destination, hashlib.sha256(raw).hexdigest())


if __name__ == '__main__': unittest.main()
