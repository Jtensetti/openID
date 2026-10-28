"""Synthetic SQLite retention: no live database, identity documents or policy decisions."""
import base64
import hashlib
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from identity import VerifiedDocument
import sqlite_retention
from sqlite_retention import maintain, policy, read_policy
from wallet import Wallet

NOW = 2_000_000_000
DAY = 86400
POLICY = {'version': 1, 'reference': 'TEST_POLICY_001', 'profileDays': 7,
          'authenticationRequestDays': 1}


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.path = self.root/'wallet.sqlite'
        self.wallet = Wallet(self.path, 'https://example.invalid', clock=lambda: NOW,
                             crypto=lambda *a, **k: None)
        self.original_key = self.wallet.vault.key(create=True)
        with self.wallet.transaction() as db:
            for ident, state, expires in [('a'*64, 'REVOKED', NOW-8*DAY),
                    ('b'*64, 'ACTIVE', NOW+2*DAY), ('c'*64, 'ACTIVE', NOW-7*DAY),
                    ('d'*64, 'PENDING_REVIEW', None), ('e'*64, 'REVOKED', NOW+DAY)]:
                db.execute('INSERT INTO credentials VALUES(?,?,?,?,?,?,?)',
                    (ident, 'public-'+ident, state, NOW-20*DAY, expires, 'TEST_DECISION', 'subject-'+ident))
                db.execute('INSERT INTO persons VALUES(?,?)', ('person-'+ident, 'tag-'+ident))
                db.execute('INSERT INTO profiles VALUES(?,?,?,?,?,?)',
                    (ident, 'person-'+ident, 'version-'+ident, 'PRIVATE_SEALED', NOW-20*DAY, NOW+30*DAY))
                db.execute('INSERT INTO security_codes VALUES(?,?,?,?,?)', (ident, 'PRIVATE_PIN', 5, 1, NOW-20*DAY))
                db.execute('INSERT INTO document_links VALUES(?,?)', ('tag-'+ident, 'person-'+ident))
                db.execute('INSERT INTO profile_documents VALUES(?,?)', (ident, 'tag-'+ident))
                db.execute('INSERT INTO events(credential,kind,time) VALUES(?,?,?)', (ident, 'CAPTURE_VERIFIED', NOW-20*DAY))
            db.execute('INSERT INTO retired_documents VALUES(?)', ('retired-tag',))
            db.execute('INSERT INTO biometric_failures VALUES(?,?)', ('tag-'+'a'*64, NOW-1))
            for ident, expiry in [('old', NOW-2*DAY), ('edge', NOW-DAY), ('fresh', NOW+DAY)]:
                db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?)',
                    (ident, 'a'*64, 'hash', 'APPROVED', NOW-5*DAY, expiry, '123456'))
            for ident, message in [('auth-old', None), ('sign-old', 'SYNTHETIC SIGNING TEXT')]:
                db.execute('INSERT INTO federation_requests VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                    (ident, 'a'*64, 'hash', 'APPROVED', NOW-5*DAY, NOW-2*DAY, '123456',
                     'binding', 'test-audience', message, 'test-level'))

    def run_retention(self, **kwargs):
        return maintain(self.path, POLICY, clock=lambda: NOW, **kwargs)

    def rows(self, table):
        with closing(sqlite3.connect(self.path)) as db:
            return db.execute('SELECT * FROM '+table+' ORDER BY 1').fetchall()

    def test_preview_is_read_only_bounded_and_contains_no_identifiers(self):
        before = self.path.read_bytes()
        result = self.run_retention(batch=1)
        self.assertEqual(result['mode'], 'plan')
        self.assertEqual(result['selected'], dict(profiles=1, security_codes=1, requests=1, federation_requests=1))
        self.assertTrue(result['moreEligible']['profiles'])
        self.assertNotIn('PRIVATE', json.dumps(result)); self.assertNotIn('a'*64, json.dumps(result))
        self.assertEqual(before, self.path.read_bytes()); self.assertEqual([], self.rows('retention_runs'))

    def test_apply_preserves_boundary_active_ids_signing_and_security_evidence(self):
        protected = ('credentials','events','persons','document_links','retired_documents',
                     'profile_documents','biometric_failures')
        before = {t: self.rows(t) for t in protected}
        marker = self.path.with_suffix('.continuity-required'); marker.write_bytes(b'v1\n')
        with self.wallet.transaction() as db:
            db.execute('INSERT INTO enrollment_quarantine VALUES(1,?)', (NOW+DAY,))
        result = self.run_retention(apply=True)
        self.assertEqual(result['selected'], dict(profiles=2, security_codes=2, requests=1, federation_requests=1))
        self.assertEqual([r[0] for r in self.rows('profiles')], [x*64 for x in 'bce'])
        self.assertEqual([r[0] for r in self.rows('requests')], ['edge','fresh'])
        self.assertEqual([r[0] for r in self.rows('federation_requests')], ['sign-old'])
        self.assertEqual(before, {t: self.rows(t) for t in protected})
        self.assertEqual([(1,NOW+DAY)], self.rows('enrollment_quarantine'))
        self.assertEqual(self.original_key, self.wallet.vault.key())
        self.assertEqual(b'v1\n', marker.read_bytes())
        journal = self.rows('retention_runs'); self.assertEqual(1, len(journal))
        self.assertEqual(result['policySHA256'], journal[0][3])
        self.assertEqual(result['selected'], json.loads(journal[0][6]))
        evidence = self.rows('profile_evidence')
        self.assertEqual([x*64 for x in 'ad'], [row[0] for row in evidence])
        self.assertNotIn('PRIVATE', json.dumps(evidence))
        with self.assertRaises(ValueError): self.wallet.activate('a'*64, 'TEST_DECISION')

    def test_batch_resume_and_repeat_does_not_remove_more_than_selected(self):
        first = self.run_retention(apply=True, batch=1)
        second = self.run_retention(apply=True, batch=1)
        third = self.run_retention(apply=True, batch=1)
        self.assertEqual([1,1,0], [r['selected']['profiles'] for r in (first,second,third)])
        self.assertFalse(any(third['selected'].values()))
        self.assertEqual(3, len(self.rows('retention_runs')))

    def test_trigger_cannot_delete_revocation_and_failure_rolls_back_entire_batch(self):
        with self.wallet.transaction() as db:
            db.execute('''CREATE TRIGGER interfere BEFORE DELETE ON requests BEGIN
                DELETE FROM events; END''')
        before = {t: self.rows(t) for t in ('profiles','security_codes','requests','events','retention_runs','profile_evidence')}
        with self.assertRaises(sqlite3.DatabaseError): self.run_retention(apply=True)
        self.assertEqual(before, {t: self.rows(t) for t in before})

    def test_audit_profile_metadata_survives_gallring_and_conflict_is_rejected(self):
        from audit_archive import export_snapshot, sqlite_snapshot, verify
        first, second = self.root/'before', self.root/'after'
        export_snapshot(sqlite_snapshot(self.path), first, 'sqlite', 'a'*40)
        self.run_retention(apply=True)
        receipt = export_snapshot(sqlite_snapshot(self.path), second, 'sqlite', 'a'*40)
        verify(second, receipt['manifestSha256'])
        self.assertEqual((first/'profiles.jsonl').read_bytes(), (second/'profiles.jsonl').read_bytes())
        self.assertEqual(4, json.loads((second/'manifest.json').read_bytes())['format'])
        self.assertEqual(b'', (first/'retention_runs.jsonl').read_bytes())
        journal = json.loads((second/'retention_runs.jsonl').read_bytes())
        self.assertEqual(list(self.rows('retention_runs')[0]), journal)
        with self.wallet.transaction() as db:
            db.execute('INSERT INTO profile_evidence VALUES(?,?,?,?,?)',
                       ('b'*64, 'conflicting-version', NOW, NOW+DAY, NOW))
        destination = self.root/'conflict'
        with self.assertRaisesRegex(ValueError, 'conflicting profile evidence'):
            export_snapshot(sqlite_snapshot(self.path), destination, 'sqlite', 'a'*40)
        self.assertFalse(destination.exists())

    def test_commit_after_concurrent_extension_keeps_new_validity(self):
        ready = threading.Event(); results = []; errors = []
        original_connect = sqlite3.connect
        def observed_connect(*args, **kwargs):
            db = original_connect(*args, **kwargs)
            db.set_trace_callback(lambda sql: ready.set() if sql == 'BEGIN IMMEDIATE' else None)
            return db
        with closing(sqlite3.connect(self.path, isolation_level=None)) as writer:
            writer.execute('BEGIN IMMEDIATE')
            writer.execute("UPDATE credentials SET expires=? WHERE id=?", (NOW+DAY, 'd'*64))
            def work():
                try: results.append(self.run_retention(apply=True))
                except BaseException as error: errors.append(error)
            with patch('sqlite_retention.sqlite3.connect', side_effect=observed_connect):
                thread = threading.Thread(target=work); thread.start(); self.assertTrue(ready.wait(2))
                writer.execute('COMMIT'); thread.join(5)
        self.assertFalse(thread.is_alive()); self.assertFalse(errors)
        self.assertEqual(1, results[0]['selected']['profiles'])
        self.assertIn('d'*64, [r[0] for r in self.rows('profiles')])

    def test_deadline_rolls_back_deletion_evidence_and_journal(self):
        before = {t: self.rows(t) for t in ('profiles','security_codes','requests','profile_evidence','retention_runs')}
        ticks = iter([0])
        with patch('sqlite_retention.time.monotonic', side_effect=lambda: next(ticks,20)):
            with self.assertRaises((ValueError,sqlite3.DatabaseError)):
                self.run_retention(apply=True)
        self.assertEqual(before, {t: self.rows(t) for t in before})

    def test_backup_restore_after_last_profile_purge_still_requires_original_key(self):
        from recovery import backup_database, bind_backup, restore
        with self.wallet.transaction() as db:
            db.execute("UPDATE credentials SET state='REVOKED',expires=?", (NOW-8*DAY,))
        self.assertEqual(5, self.run_retention(apply=True)['selected']['profiles'])
        backup = backup_database(self.path, self.root/'backup')
        with self.assertRaises(ValueError): restore(backup, self.root/'without-key')
        self.assertFalse((self.root/'without-key').exists())
        binding = self.root/'binding.json'
        anchor = bind_backup(backup, self.wallet.vault.path,
            hashlib.sha256(self.original_key).hexdigest(), binding)
        restored = restore(backup, self.root/'restored', self.wallet.vault.path,
                           binding=binding, binding_sha256=anchor)
        self.assertEqual(self.original_key, restored.with_suffix('.identity-key').read_bytes())
        with closing(sqlite3.connect(restored)) as db:
            self.assertEqual(0, db.execute('SELECT count(*) FROM profiles').fetchone()[0])
            self.assertEqual(5, db.execute('SELECT count(*) FROM profile_evidence').fetchone()[0])
            self.assertEqual(5, db.execute("SELECT count(*) FROM credentials WHERE state='REVOKED'").fetchone()[0])

    def test_invalid_state_or_timestamp_does_not_qualify_for_profile_deletion(self):
        with self.wallet.transaction() as db:
            db.execute("UPDATE credentials SET state='UNKNOWN' WHERE id=?", ('a'*64,))
            db.execute("UPDATE credentials SET state='ACTIVE' WHERE id=?", ('d'*64,))
        self.assertEqual(0, self.run_retention(apply=True)['selected']['profiles'])

    def test_missing_key_after_profiles_are_removed_is_not_recreated(self):
        with self.wallet.transaction() as db:
            db.execute('DELETE FROM profiles'); db.execute('DELETE FROM security_codes')
            db.execute('DELETE FROM biometric_failures')
        self.wallet.vault.path.unlink()
        with self.assertRaises(FileNotFoundError): self.wallet.health()
        doc = VerifiedDocument(b'synthetic', {'documentExpires':'2039-01-01',
            'issuingState':'UTO', 'documentNumber':'TEST123', 'birthDateMrz':'900101'},
            'CHECKED_CRL', NOW+DAY)
        with self.assertRaises(FileNotFoundError): self.wallet.biometric_attempt(doc)
        self.assertEqual([], self.rows('biometric_failures'))
        self.assertFalse(self.wallet.vault.path.exists())
        with self.assertRaises(FileNotFoundError):
            self.wallet.enroll(base64.b64encode(b'new synthetic public key').decode(), doc)
        self.assertFalse(self.wallet.vault.path.exists())
        self.assertEqual(5, len(self.rows('credentials')))

    def test_invalid_policy_missing_database_and_unsafe_files_never_create_data(self):
        for changes in ({'profileDays':True}, {'profileDays':0}, {'authenticationRequestDays':3651},
                        {'reference':'person@example.invalid'}, {'version':2}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):policy(POLICY|changes)
        missing = self.root/'missing.sqlite'
        with self.assertRaises(FileNotFoundError): maintain(missing, POLICY)
        self.assertFalse(missing.exists())
        link = self.root/'link.sqlite'; link.symlink_to(self.path)
        with self.assertRaises(ValueError): maintain(link, POLICY)
        link.unlink(); os.link(self.path, link)
        with self.assertRaises(ValueError): self.run_retention(apply=True)
        link.unlink(); self.path.chmod(0o644)
        with self.assertRaises(ValueError): self.run_retention(apply=True)

    def test_unknown_schema_does_not_initialize_or_modify_database(self):
        with self.wallet.transaction() as db:db.execute('DROP TABLE retention_runs')
        before = self.path.read_bytes()
        with self.assertRaises(ValueError): self.run_retention(apply=True)
        self.assertEqual(before, self.path.read_bytes())

    def test_policy_file_rejects_duplicates_symlink_fifo_and_writable_permissions(self):
        path = self.root/'policy.json'; path.write_text(json.dumps(POLICY));path.chmod(0o600)
        self.assertEqual(POLICY, read_policy(path))
        path.write_text(json.dumps(POLICY)[:-1]+',"profileDays":1}')
        with self.assertRaises(ValueError): read_policy(path)
        path.unlink(); path.symlink_to(self.path)
        with self.assertRaises(OSError): read_policy(path)
        path.unlink();os.mkfifo(path,0o600)
        with self.assertRaises(ValueError): read_policy(path)
        path.unlink();path.write_text(json.dumps(POLICY));path.chmod(0o666)
        with self.assertRaises(ValueError): read_policy(path)

    def test_cli_plan_and_sanitized_error(self):
        path = self.root/'policy.json';path.write_text(json.dumps(POLICY));path.chmod(0o600)
        result = subprocess.run([sys.executable, str(Path(sqlite_retention.__file__)),
            'plan','--db',str(self.path),'--policy',str(path)],capture_output=True,timeout=5)
        self.assertEqual(0,result.returncode); self.assertEqual('plan',json.loads(result.stdout)['mode'])
        path.write_text('PRIVATE invalid policy')
        result = subprocess.run([sys.executable,str(Path(sqlite_retention.__file__)),
            'apply','--db',str(self.path),'--policy',str(path)],capture_output=True,timeout=5)
        self.assertEqual(2,result.returncode);self.assertEqual(b'',result.stdout)
        self.assertEqual(b'Retention failed; no sensitive details logged.\n',result.stderr)


if __name__ == '__main__': unittest.main()
