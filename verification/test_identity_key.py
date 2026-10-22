"""File-object attacks against the local pilot vault; no real keys used."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from identity import IdentityVault


class IdentityKeyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'key'
        self.vault = IdentityVault(self.path)

    def test_creation_preserves_existing_key(self):
        original = self.vault.key(create=True)
        self.assertEqual(64, len(original))
        self.assertEqual(original, self.vault.key(create=True))
        self.path.chmod(0o400)
        self.assertEqual(original, self.vault.key())

    def test_missing_key_is_not_created_by_read(self):
        with self.assertRaises(FileNotFoundError):
            self.vault.key()
        self.assertFalse(self.path.exists())

    def test_symlink_and_hardlink_rejected(self):
        original = self.vault.key(create=True)
        alias = self.path.with_name('alias')
        alias.symlink_to(self.path)
        with self.assertRaises(OSError):
            IdentityVault(alias).key()
        alias.unlink()
        os.link(self.path, alias)
        for path in (self.path, alias):
            with self.assertRaises(ValueError):
                IdentityVault(path).key()
        alias.unlink()
        self.assertEqual(original, self.vault.key())

    def test_permissions_and_length_rejected(self):
        self.vault.key(create=True)
        for mode in (0o644, 0o640, 0o604, 0o700):
            self.path.chmod(mode)
            with self.assertRaises(ValueError):
                self.vault.key()
        self.path.chmod(0o600)
        for size in (0, 63, 65):
            self.path.write_bytes(b'x' * size)
            with self.assertRaises(ValueError):
                self.vault.key()

    def test_directory_rejected(self):
        self.path.mkdir(mode=0o700)
        with self.assertRaises((ValueError, OSError)):
            self.vault.key()

    def test_fifo_rejected_without_waiting_for_writer(self):
        os.mkfifo(self.path, 0o600)
        script = '''from identity import IdentityVault
import sys
try:
    IdentityVault(sys.argv[1]).key()
except ValueError:
    sys.exit(0)
sys.exit(1)
'''
        result = subprocess.run([sys.executable, '-c', script, str(self.path)],
                                cwd=Path(__file__).parent, timeout=3,
                                capture_output=True)
        self.assertEqual(0, result.returncode)
