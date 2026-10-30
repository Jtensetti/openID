"""Synthetic key/backup binding; no real key or profile is used."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch

import recovery
from recovery import backup_database, bind_backup
from test_erasure_helpers import sqlite_restore as restore
import recovery_binding
from recovery_binding import read_binding, snapshot_copy, write_binding
from wallet import Wallet


class RecoveryBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.wallet = Wallet(self.root/'live'/'wallet.sqlite', 'https://example.invalid')
        self.key = self.wallet.vault.key(create=True)
        self.fingerprint = hashlib.sha256(self.key).hexdigest()
        with self.wallet.transaction() as db:
            db.execute('INSERT INTO persons VALUES(?,?)', ('synthetic-person', 'synthetic-document-tag'))
        self.backup = backup_database(self.wallet.path, self.root/'backup')

    def bind(self):
        path = self.root/'binding.json'
        checksum = bind_backup(self.backup, self.wallet.vault.path, self.fingerprint, path)
        return {'binding': path, 'binding_sha256': checksum}

    def test_unbound_restore_cannot_accept_a_different_key_after_profiles_are_gone(self):
        wrong = self.root/'wrong-key'; wrong.write_bytes(b'x'*64); wrong.chmod(0o600)
        with self.assertRaises(ValueError): restore(self.backup, self.root/'restored', wrong)
        self.assertFalse((self.root/'restored').exists())

    def test_keyless_backups_require_anchor_and_cannot_bypass_it_by_dropping_history(self):
        evidence = self.bind()
        with closing(sqlite3.connect(self.backup)) as db, db:
            db.execute('DELETE FROM persons')
        for kwargs in ({}, evidence):
            with self.subTest(bound=bool(kwargs)), self.assertRaises(ValueError):
                restore(self.backup, self.root/'restored', **kwargs)
            self.assertFalse((self.root/'restored').exists())
        binding = self.root/'keyless-binding.json'
        anchor = bind_backup(self.backup, None, None, binding)
        self.assertIsNone(read_binding(binding, anchor)['identityKeySHA256'])
        with self.assertRaises(ValueError):
            restore(self.backup, self.root/'wrong', self.wallet.vault.path,
                    binding=binding, binding_sha256=anchor)
        self.assertFalse((self.root/'wrong').exists())
        target = restore(self.backup, self.root/'restored', binding=binding, binding_sha256=anchor)
        self.assertFalse(target.with_suffix('.identity-key').exists())

    def test_binding_may_not_disclaim_existing_key_history(self):
        evidence = self.bind(); value = read_binding(evidence['binding'], evidence['binding_sha256'])
        value['identityKeySHA256'] = None
        binding = self.root/'false-binding.json'; anchor = write_binding(binding, value)
        with self.assertRaises(ValueError):
            restore(self.backup, self.root/'restored', binding=binding, binding_sha256=anchor)
        self.assertFalse((self.root/'restored').exists())

    def test_executable_database_schema_cannot_be_attested_or_restored(self):
        evidence = self.bind()
        with closing(sqlite3.connect(self.backup)) as db, db:
            db.execute('CREATE VIEW unexpected AS SELECT * FROM persons')
        with self.assertRaises(ValueError):
            bind_backup(self.backup, self.wallet.vault.path, self.fingerprint, self.root/'bad-binding.json')
        value = read_binding(evidence['binding'], evidence['binding_sha256'])
        value.update(backupSHA256=hashlib.sha256(self.backup.read_bytes()).hexdigest(), backupBytes=self.backup.stat().st_size)
        binding = self.root/'bound-unexpected.json'; anchor = write_binding(binding, value)
        with self.assertRaises(ValueError):
            restore(self.backup, self.root/'restored', self.wallet.vault.path, binding=binding, binding_sha256=anchor)
        self.assertFalse((self.root/'restored').exists())

    def test_profile_size_and_deadline_reject_before_crypto(self):
        from unittest.mock import Mock
        with closing(sqlite3.connect(':memory:')) as db:
            db.execute('CREATE TABLE profiles (credential TEXT, person TEXT, sealed TEXT)')
            db.execute('INSERT INTO profiles VALUES(?,?,?)', ('c','p','x'*131073))
            vault = Mock()
            with self.assertRaises(ValueError): recovery.verify_profiles(db, vault)
            vault.crypt.assert_not_called()
            db.execute('DELETE FROM profiles')
            with patch('recovery.time.monotonic', side_effect=[0,121]):
                with self.assertRaises(ValueError): recovery.verify_profiles(db, vault)

    def test_correct_original_key_and_anchor_restore_after_profiles_are_gone(self):
        evidence = self.bind()
        data = read_binding(evidence['binding'], evidence['binding_sha256'])
        self.assertEqual(hashlib.sha256(self.backup.read_bytes()).hexdigest(), data['backupSHA256'])
        self.assertEqual(self.fingerprint, data['identityKeySHA256'])
        self.assertEqual(0o600, evidence['binding'].stat().st_mode & 0o777)
        target = restore(self.backup, self.root/'restored', self.wallet.vault.path, **evidence)
        self.assertEqual(self.key, target.with_suffix('.identity-key').read_bytes())
        with closing(sqlite3.connect(target)) as db:
            self.assertEqual(0, db.execute('SELECT count(*) FROM profiles').fetchone()[0])
            self.assertEqual(1, db.execute('SELECT count(*) FROM persons').fetchone()[0])
            self.assertGreater(db.execute('SELECT until_epoch FROM enrollment_quarantine').fetchone()[0], 0)
        self.assertFalse(self.backup.with_suffix('.identity-key').exists())

    def test_changing_either_key_half_is_rejected_even_without_profiles(self):
        evidence = self.bind()
        for offset in (0, 32):
            key = bytearray(self.key); key[offset] ^= 1
            path = self.root/('wrong-'+str(offset)); path.write_bytes(key); path.chmod(0o600)
            destination = self.root/('restored-'+str(offset))
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                restore(self.backup, destination, path, **evidence)
            self.assertFalse(destination.exists())

    def test_correct_key_still_requires_separate_anchor_and_binding(self):
        evidence = self.bind()
        for kwargs in ({}, {'binding':evidence['binding']}, {'binding_sha256':evidence['binding_sha256']}):
            with self.subTest(kwargs=tuple(kwargs)), self.assertRaises(ValueError):
                restore(self.backup, self.root/'restored', self.wallet.vault.path, **kwargs)
            self.assertFalse((self.root/'restored').exists())

    def test_changed_valid_database_cannot_use_old_binding(self):
        evidence = self.bind()
        with closing(sqlite3.connect(self.backup)) as db, db:
            db.execute("INSERT INTO persons VALUES('other-person','other-tag')")
        with self.assertRaises(ValueError):
            restore(self.backup, self.root/'restored', self.wallet.vault.path, **evidence)
        self.assertFalse((self.root/'restored').exists())

    def test_rewritten_binding_cannot_replace_external_anchor(self):
        evidence = self.bind()
        value = json.loads(evidence['binding'].read_text()); value['identityKeySHA256'] = 'a'*64
        evidence['binding'].write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            restore(self.backup, self.root/'restored', self.wallet.vault.path, **evidence)
        self.assertFalse((self.root/'restored').exists())

    def test_invalid_inventory_does_not_publish_binding(self):
        for fingerprint in ('a'*64, 'A'*64, True, 'a'*63, self.fingerprint+'\n'):
            with self.subTest(fingerprint=fingerprint), self.assertRaises(ValueError):
                bind_backup(self.backup, self.wallet.vault.path, fingerprint, self.root/'binding.json')
            self.assertFalse((self.root/'binding.json').exists())
        self.assertFalse(list(self.root.glob('openid-binding-*')))

    def test_existing_binding_is_never_overwritten(self):
        evidence = self.bind(); before = evidence['binding'].read_bytes()
        with self.assertRaises(ValueError): self.bind()
        self.assertEqual(before, evidence['binding'].read_bytes())

    def test_anchor_preserves_required_continuity_even_if_marker_lost(self):
        marker = self.backup.with_suffix('.continuity-required')
        marker.write_bytes(b'v1\n'); marker.chmod(0o600)
        evidence = self.bind(); marker.unlink()
        target = restore(self.backup, self.root/'restored', self.wallet.vault.path, **evidence)
        self.assertEqual(b'v1\n', target.with_suffix('.continuity-required').read_bytes())
        with self.assertRaises(ValueError): Wallet(target, 'https://example.invalid')

    def test_malformed_binding_rejected_even_with_matching_anchor(self):
        evidence = self.bind(); base = json.loads(evidence['binding'].read_text())
        cases = [json.dumps(base | change) for change in (
            {'format':'unknown'}, {'backupBytes':True}, {'backupBytes':0},
            {'backupSHA256':'a'*63}, {'identityKeySHA256':False},
            {'continuityRequired':1}, {'unknown':1})]
        cases += [json.dumps(base)[:-1]+',"format":"'+base['format']+'"}', '{}', '[]', 'NaN', 'x'*4097]
        for raw in cases:
            evidence['binding'].write_text(raw)
            checksum = hashlib.sha256(raw.encode()).hexdigest()
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                read_binding(evidence['binding'], checksum)

    def test_binding_symlink_hardlink_public_file_and_fifo_are_rejected(self):
        evidence = self.bind(); path = evidence['binding']; alias = self.root/'alias'
        alias.symlink_to(path)
        with self.assertRaises(OSError): read_binding(alias, evidence['binding_sha256'])
        alias.unlink(); os.link(path, alias)
        with self.assertRaises(ValueError): read_binding(alias, evidence['binding_sha256'])
        alias.unlink(); path.chmod(0o644)
        with self.assertRaises(ValueError): read_binding(path, evidence['binding_sha256'])
        path.unlink(); os.mkfifo(path, 0o600)
        with self.assertRaises(ValueError): read_binding(path, evidence['binding_sha256'])

    def test_snapshot_rejects_active_sidecars_aliases_and_oversize_without_output(self):
        target = self.root/'copy.sqlite'
        for suffix in ('-wal','-shm','-journal'):
            sidecar = Path(str(self.backup)+suffix); sidecar.write_bytes(b'')
            with self.assertRaises(ValueError): snapshot_copy(self.backup, target)
            sidecar.unlink(); self.assertFalse(target.exists())
        alias = self.root/'alias'; alias.symlink_to(self.backup)
        with self.assertRaises(OSError): snapshot_copy(alias, target)
        alias.unlink(); os.link(self.backup, alias)
        with self.assertRaises(ValueError): snapshot_copy(alias, target)
        alias.unlink()
        with patch('recovery_binding.MAX_SNAPSHOT_BYTES', 1):
            with self.assertRaises(ValueError): snapshot_copy(self.backup, target)
        self.assertFalse(target.exists())

    def test_snapshot_change_or_deadline_never_leaves_a_partial_copy(self):
        target = self.root/'copy.sqlite'
        original = recovery_binding.no_sqlite_sidecars
        calls = []
        def changed(path):
            original(path); calls.append(path)
            if len(calls) == 2:
                with self.backup.open('ab') as stream: stream.write(b'changed')
        with patch('recovery_binding.no_sqlite_sidecars', side_effect=changed):
            with self.assertRaises(ValueError): snapshot_copy(self.backup, target)
        self.assertFalse(target.exists())
        with patch('recovery_binding.time.monotonic', side_effect=[0,31]):
            with self.assertRaises(ValueError): snapshot_copy(self.backup, target)
        self.assertFalse(target.exists())

    def test_profile_authentication_still_required_before_publishing_binding(self):
        with self.wallet.transaction() as db:
            db.execute('INSERT INTO credentials VALUES(?,?,?,?,?,?,?)',
                ('a'*64, 'synthetic-public', 'ACTIVE', 1, 2, 'TEST', 'subject'))
            sealed = self.wallet.vault.crypt('seal', 'a'*64, 'synthetic-person', {'synthetic':True})
            db.execute('INSERT INTO profiles VALUES(?,?,?,?,?,?)',
                ('a'*64, 'synthetic-person', 'version', json.dumps(sealed), 1, 2))
        self.backup = backup_database(self.wallet.path, self.root/'encrypted-backup')
        evidence = self.bind()
        key = bytearray(self.key); key[0] ^= 1
        self.wallet.vault.path.write_bytes(key)
        with self.assertRaises(ValueError):
            bind_backup(self.backup, self.wallet.vault.path, hashlib.sha256(key).hexdigest(), self.root/'wrong-binding.json')
        self.assertFalse((self.root/'wrong-binding.json').exists())
        self.wallet.vault.path.write_bytes(self.key)
        target = restore(self.backup, self.root/'restored', self.wallet.vault.path, **evidence)
        with closing(sqlite3.connect(target)) as db:
            self.assertEqual('REVOKED', db.execute('SELECT state FROM credentials').fetchone()[0])

    def test_cli_outputs_only_digest_and_sanitizes_binding_failure(self):
        path = self.root/'binding.json'
        command = [sys.executable, str(Path(recovery.__file__)), 'bind', '--backup', str(self.backup),
            '--identity-key', str(self.wallet.vault.path), '--expected-key-sha256', self.fingerprint, '--output', str(path)]
        result = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(0, result.returncode)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest().encode()+b'\n', result.stdout)
        self.assertEqual(b'', result.stderr)
        result = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(2, result.returncode); self.assertEqual(b'', result.stdout)
        self.assertEqual(b'Recovery failed; no sensitive details logged.\n', result.stderr)


if __name__ == '__main__': unittest.main()
