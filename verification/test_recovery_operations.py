"""Operator backup/restore uses synthetic data and must retain fail-closed policy."""
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

import recovery
import notices
from recovery import backup_database, bind_backup, restore
from wallet import Wallet


class RecoveryOperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root/'live'/'wallet.sqlite'
        self.wallet = Wallet(self.source, 'https://example.invalid')
        self.marker = self.source.with_suffix('.continuity-required')

    def mark(self, content=b'v1\n'):
        self.marker.write_bytes(content)
        self.marker.chmod(0o600)

    def cli(self, *args):
        return subprocess.run([sys.executable, str(Path(recovery.__file__)), *map(str, args)],
                              check=True, capture_output=True, text=True, timeout=15)

    def test_cli_backup_does_not_initialize_wallet_or_modify_live_database(self):
        self.mark()
        with self.assertRaises(ValueError): Wallet(self.source, 'https://example.invalid')
        before = hashlib.sha256(self.source.read_bytes()).digest()
        result = self.cli('backup', '--db', self.source, '--destination', self.root/'snapshot')
        target = Path(result.stdout.strip())
        self.assertEqual(before, hashlib.sha256(self.source.read_bytes()).digest())
        self.assertEqual(b'v1\n', target.with_suffix('.continuity-required').read_bytes())
        self.assertEqual(0o600, target.stat().st_mode & 0o777)
        self.assertEqual(0o700, target.parent.stat().st_mode & 0o777)
        self.assertFalse(target.with_suffix('.identity-key').exists())

    def test_snapshot_includes_committed_wal_without_checkpointing_the_source(self):
        with closing(sqlite3.connect(self.source)) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA wal_autocheckpoint=0')
            db.execute('CREATE TABLE operator_probe (value TEXT)')
            db.execute("INSERT INTO operator_probe VALUES ('synthetic')")
            db.commit()
            before = self.source.read_bytes()
            target = backup_database(self.source, self.root/'snapshot')
            self.assertEqual(before, self.source.read_bytes())
            with closing(sqlite3.connect(target)) as snapshot:
                self.assertEqual([('synthetic',)], snapshot.execute('SELECT value FROM operator_probe').fetchall())

    def test_restore_preserves_requirement_and_cannot_start_without_independent_services(self):
        self.mark()
        source = backup_database(self.source, self.root/'snapshot')
        binding = self.root/'binding.json'; anchor = bind_backup(source, None, None, binding)
        target = restore(source, self.root/'restored', binding=binding, binding_sha256=anchor)
        self.assertEqual(b'v1\n', target.with_suffix('.continuity-required').read_bytes())
        self.assertEqual(0o600, target.with_suffix('.continuity-required').stat().st_mode & 0o777)
        with self.assertRaises(ValueError): Wallet(target, 'https://example.invalid')
        with self.assertRaises(ValueError): Wallet(target, 'https://example.invalid', revocation=object())

    def test_cli_requires_continuity_for_older_backup(self):
        source = backup_database(self.source, self.root/'snapshot')
        binding = self.root/'binding.json'; anchor = bind_backup(source, None, None, binding)
        result = self.cli('restore', '--backup', source, '--destination', self.root/'restored',
                         '--binding', binding, '--binding-sha256', anchor, '--require-continuity')
        target = Path(result.stdout.strip())
        with self.assertRaises(ValueError): Wallet(target, 'https://example.invalid')

    def test_restore_requires_key_when_only_sealed_revocation_code_remains(self):
        with self.wallet.transaction() as db:
            notices.install(db)
            db.execute('INSERT INTO credentials VALUES(?,?,?,?,?,?,?)',
                ('a'*64, 'synthetic-public-key', 'REVOKED', 1, 2, 'TEST', 'test-subject'))
            db.execute('INSERT INTO revocation_codes VALUES(?,?,?,?)',
                ('a'*64, 'SYNTHETIC_SEALED_CODE', 'test-contact-reference', 'test-evidence-reference'))
        source = backup_database(self.source, self.root/'snapshot')
        key = self.wallet.vault.key(create=True)
        binding = self.root/'binding.json'
        anchor = bind_backup(source, self.wallet.vault.path, hashlib.sha256(key).hexdigest(), binding)
        self.wallet.vault.path.unlink()
        destination = self.root/'restored'
        with self.assertRaisesRegex(ValueError, 'Separate identity key required'):
            restore(source, destination, binding=binding, binding_sha256=anchor)
        self.assertFalse(destination.exists())
        self.assertFalse(self.wallet.vault.path.exists())

    def test_invalid_marker_and_marker_symlink_reject_without_destination(self):
        binding = self.root/'binding.json'; anchor = bind_backup(self.source, None, None, binding)
        for index, content in enumerate((b'', b'v2\n', b'v1\nextra', b'x'*8192)):
            self.mark(content)
            for operation in (backup_database, restore):
                destination = self.root/(operation.__name__+str(index))
                kwargs = {'binding':binding, 'binding_sha256':anchor} if operation is restore else {}
                with self.assertRaises(ValueError): operation(self.source, destination, **kwargs)
                self.assertFalse(destination.exists())
        self.marker.unlink()
        other = self.root/'other'; other.write_bytes(b'v1\n')
        self.marker.symlink_to(other)
        for operation in (backup_database, restore):
            kwargs = {'binding':binding, 'binding_sha256':anchor} if operation is restore else {}
            with self.assertRaises(OSError): operation(self.source, self.root/operation.__name__, **kwargs)
            self.assertFalse((self.root/operation.__name__).exists())

    def test_marker_named_pipe_rejects_without_waiting(self):
        os.mkfifo(self.marker, 0o600)
        with self.assertRaises(ValueError): backup_database(self.source, self.root/'snapshot')
        self.assertFalse((self.root/'snapshot').exists())

    def test_missing_symlink_or_corrupt_database_never_leaves_snapshot(self):
        missing = self.root/'missing.sqlite'
        link = self.root/'link.sqlite'; link.symlink_to(self.source)
        corrupt = self.root/'corrupt.sqlite'; corrupt.write_bytes(b'not sqlite')
        for source in (missing, link, corrupt):
            destination = self.root/(source.stem+'-snapshot')
            with self.assertRaises((ValueError, sqlite3.DatabaseError)):
                backup_database(source, destination)
            self.assertFalse(destination.exists())
        self.assertFalse(missing.exists())

    def test_snapshot_never_overwrites_existing_directory(self):
        destination = self.root/'existing'; destination.mkdir()
        sentinel = destination/'retain'; sentinel.write_bytes(b'retain')
        with self.assertRaises(ValueError): backup_database(self.source, destination)
        self.assertEqual(b'retain', sentinel.read_bytes())


if __name__ == '__main__': unittest.main()
