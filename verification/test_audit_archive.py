"""Actual SQLite snapshots and adversarial offline archive verification."""
import hashlib
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
        with sqlite3.connect(self.db) as db:
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

    def test_roundtrip_offline_without_identity_keys_and_minimal_private_data(self):
        receipt = self.export()
        self.db.unlink()  # Verification has no database, application or key dependency.
        result = archive.verify(self.destination, receipt['manifestSha256'])
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
                with sqlite3.connect(self.db) as db:
                    db.execute("UPDATE credentials SET state='REVOKED'")
                    db.execute("INSERT INTO events VALUES(2,'credential','REVOKED',1001,NULL)")
            return result
        with patch.object(archive, 'write_table', side_effect=concurrent):receipt = self.export()
        archive.verify(self.destination, receipt['manifestSha256'])
        self.assertIn('ACTIVE', (self.destination/'credentials.jsonl').read_text())
        self.assertNotIn('REVOKED', (self.destination/'events.jsonl').read_text())
        with sqlite3.connect(self.db) as db:self.assertEqual('REVOKED', db.execute('SELECT state FROM credentials').fetchone()[0])

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
        with sqlite3.connect(self.db) as db:db.execute('DROP TABLE events')
        with self.assertRaises(sqlite3.Error):self.export()
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


if __name__ == '__main__': unittest.main()
