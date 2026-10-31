"""Temporary-fixture tests for reversible TestFlight-112 isolation migration."""
import importlib.util
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

import beta112_isolation as m


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/"beta"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        (self.root/"data").mkdir(mode=0o700)
        (self.root/"federation").mkdir(mode=0o700)
        (self.root/"origins.json").write_bytes(b'{"idp":"https://idp.test","sp":"https://sp.test"}')
        (self.root/"federation"/"SYNTHETIC-LAB-ONLY").write_bytes(b"Disposable test keys\n")
        for name in ("tls.p12","idp.p12","sp.p12","tls.crt"):
            (self.root/"federation"/name).write_bytes(b"synthetic-fixture-"+name.encode())
        self.key = os.urandom(64)
        path = self.root/"data"/"wallet.identity-key"
        path.write_bytes(self.key)
        os.chmod(path, 0o600)
        if os.geteuid() == 0:
            os.chown(path, 10001, 10001)
        self.original = m.BETA
        m.BETA = self.root
        self.addCleanup(setattr,m,"BETA",self.original)

    def test_prepare_and_rollback_preserve_original_key_bytes(self):
        if os.geteuid() != 0:
            self.skipTest("root-only permission migration")
        with patch.object(m,"assert_beta_stopped",lambda: None):
            m.prepare()
            self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
            for p, owner in (("federation-idp",10002),("federation-sp",10003)):
                directory=self.root/p
                self.assertEqual(directory.stat().st_uid, owner)
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                for file in ("tls.p12","idp.p12","sp.p12","tls.crt"):
                    self.assertEqual((directory/file).read_bytes(),b"synthetic-fixture-"+file.encode())
                self.assertEqual((directory/"origins.json").read_bytes(),
                                 (self.root/"origins.json").read_bytes())
                self.assertEqual((directory/"origins.json").stat().st_mode & 0o777, 0o600)
            m.activate()
            self.assertFalse((self.root/"data/wallet.identity-key").exists())
            vault_file=self.root/"vault/private/wallet.identity-key"
            self.assertEqual(vault_file.read_bytes(),self.key)
            self.assertEqual(vault_file.stat().st_uid,10005)
            self.assertEqual(vault_file.stat().st_mode & 0o777,0o600)
            m.rollback()
            original=self.root/"data/wallet.identity-key"
            self.assertEqual(original.read_bytes(),self.key)
            self.assertEqual(original.stat().st_uid,10001)
            self.assertEqual(self.root.stat().st_mode & 0o777,0o700)

    def test_failure_on_symlinked_private_paths(self):
        if os.geteuid() != 0:
            self.skipTest("root-only permission migration")
        (self.root/"ipc").symlink_to(self.root/"data",target_is_directory=True)
        with self.assertRaises(RuntimeError):
            m.prepare()


if __name__=="__main__":
    unittest.main()
