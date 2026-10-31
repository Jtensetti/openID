"""Synthetic tests for the beta 112 key and notification IPC contracts."""
import json
import os
from pathlib import Path
import secrets
import socket
import tempfile
import threading
import unittest

from identity import IdentityVault
from ipc_support import LocalService, request
from vault_service import dispatch as vault_dispatch
from notice_ipc import dispatch as notice_dispatch
from wallet import Wallet


class IsolatedSocketTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.directory = Path(self.root.name)
        self.sockdir = self.directory / "ipc"
        self.sockdir.mkdir()
        os.chmod(self.sockdir, 0o2710)
        self.path = self.sockdir / "service.sock"

    def run_server(self, dispatch):
        server = LocalService(self.path, os.getgid(), dispatch)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(lambda: (server.close(), worker.join(timeout=5)))
        return server

    def test_vault_never_returns_key_and_seals_existing_profile(self):
        vault = IdentityVault(self.directory / "wallet.identity-key", remote_socket="")
        vault.key(create=True)
        expected = vault.reference("document-v1", "example")
        self.run_server(lambda body: vault_dispatch(vault, body))
        self.assertEqual(request(self.path, {"operation":"check"}), {"ready":True})
        self.assertEqual(request(self.path, {"operation":"reference", "domain":"document-v1", "value":"example"}), expected)
        payload = {"givenNames":"SYNTHETIC", "portraitJpeg":"not-real"}
        sealed = request(self.path, {"operation":"crypt", "mode":"seal", "credential":"a"*64,
                                   "person":"b"*64, "value":payload})
        self.assertNotIn("givenNames", json.dumps(sealed))
        self.assertEqual(request(self.path, {"operation":"crypt", "mode":"open", "credential":"a"*64,
                                                "person":"b"*64, "value":sealed}), payload)
        with self.assertRaises(ValueError):
            request(self.path, {"operation":"get-key"})
        with self.assertRaises(ValueError):
            request(self.path, {"operation":"crypt", "mode":"open", "credential":"c"*64,
                                "person":"b"*64, "value":sealed})

    def test_no_world_or_other_group_access(self):
        os.chmod(self.sockdir, 0o2770)
        with self.assertRaises(ValueError):
            LocalService(self.path, os.getgid(), lambda _: True)
        os.chmod(self.sockdir, 0o2710)
        self.run_server(lambda _: True)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o660)

    def test_outbox_does_not_expose_identity_fields(self):
        wallet = Wallet(str(self.directory / "wallet.sqlite"), "synthetic")
        with wallet.transaction() as db:
            # Register a purely synthetic credential for the foreign-key constraint.
            db.execute("INSERT INTO credentials(id,public_key,state,created,expires) VALUES(?,?,?,?,?)",
                       ("a"*64, "synthetic", "PENDING_REVIEW", 1, 2000000000))
            db.execute("INSERT INTO notice_outbox(event,credential,contact_version,kind,created) VALUES(?,?,?,?,?)",
                       ("e"*64, "a"*64, "v"*16, "ACTIVATED_V1", 1))
        self.run_server(lambda body: notice_dispatch(wallet, body))
        message = request(self.path, {"operation":"next"})
        self.assertEqual(set(message), {"event","contactVersion","kind","created"})
        self.assertEqual(message["event"], "e"*64)
        self.assertEqual(request(self.path, {"operation":"ack","event":"e"*64,
                                                "receipt":"a"*20}), {"updated":True})
        self.assertIsNone(request(self.path, {"operation":"next"}))
        with self.assertRaises(ValueError):
            request(self.path, {"operation":"get-profile","credential":"a"*64})


if __name__ == "__main__":
    unittest.main()
