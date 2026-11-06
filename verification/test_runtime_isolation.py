"""Synthetic tests for isolated profile keys and notification IPC."""
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from identity import IdentityVault
from federation import FederationServer
from ipc_support import LocalService, request
from vault_service import dispatch as vault_dispatch
from notice_ipc import dispatch as notice_dispatch
from notice_exporter import deliver_once
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

    def test_wallet_enrollment_and_saml_with_remote_key(self):
        from test_identity import document
        from test_wallet import crypt
        key = json.loads(crypt(op="new"))
        vault = IdentityVault(self.directory / "vault-only-key", remote_socket="")
        vault.key(create=True)
        self.run_server(lambda body: vault_dispatch(vault, body))
        with patch.dict(os.environ, {"OPENID_IDENTITY_VAULT_SOCKET": str(self.path)}):
            wallet = Wallet(self.directory / "wallet.sqlite", "https://localhost:8765", clock=lambda:1792454400)
            ident = wallet.enroll(key["publicKey"], document())["id"]
            self.assertFalse((self.directory / "wallet.identity-key").exists())
            wallet.activate(ident, "REVIEW-synthetic-001")
            audience = "https://localhost:8444/sp"
            req = wallet.federation_start("_signed_saml_flow", audience)
            challenge = wallet.challenge({"credentialId":ident, "action":"approve", "requestId":req["id"]})
            signed = crypt(op="sign", key=key["privateKey"], payload=challenge["signingInput"])
            wallet.execute({"challengeId":challenge["id"], "signature":signed})
            reply = wallet.federation_result("consume", request=req["id"], secret=req["secret"],
                                            binding="_signed_saml_flow", audience=audience)
            self.assertEqual(reply["state"], "AUTHENTICATED")
            self.assertEqual(reply["identity"]["displayName"], "ALICE SYNTHETIC")
            self.assertNotIn("documentNumber", reply["identity"])
            wallet.revoke(ident)
            with self.assertRaises(ValueError):
                wallet.federation_check(ident, reply["subject"], reply["version"], audience)
            self.assertFalse((self.directory / "wallet.identity-key").exists())

    def test_no_world_or_other_group_access(self):
        os.chmod(self.sockdir, 0o2770)
        with self.assertRaises(ValueError):
            LocalService(self.path, os.getgid(), lambda _: True)
        os.chmod(self.sockdir, 0o2710)
        self.run_server(lambda _: True)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o660)

    def test_unavailable_remote_vault_never_creates_a_local_key(self):
        path = self.directory / "wallet.identity-key"
        vault = IdentityVault(path, remote_socket=str(self.path))
        for operation in (lambda: vault.key(create=True),
                          lambda: vault.reference("document-v1", "synthetic"),
                          lambda: vault.crypt("seal", "credential", "person", {})):
            with self.assertRaises(FileNotFoundError):
                operation()
            self.assertFalse(path.exists())

    def test_federation_socket_requires_owner_control_and_explicit_group(self):
        wallet = Wallet(str(self.directory / "wallet.sqlite"), "synthetic")
        os.chmod(self.sockdir, 0o2770)
        with self.assertRaises(ValueError):
            FederationServer(self.path, wallet, shared_group=os.getgid())
        os.chmod(self.sockdir, 0o2710)
        server = FederationServer(self.path, wallet, shared_group=os.getgid())
        self.addCleanup(server.close)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o660)
        self.assertEqual(request(self.path, {"operation": "health", "audience": "https://localhost:8444/sp"}),
                         {"state": "READY"})
        with self.assertRaises(ValueError):
            request(self.path, {"operation": "activate", "audience": "https://localhost:8444/sp"})

    def test_malformed_messages_never_reach_the_vault(self):
        dispatch = Mock(return_value=True)
        self.run_server(dispatch)
        for payload in (b'{"operation":"check","operation":"get-key"}\n',
                        b'[]\n', b'{"operation":"check"', b' ' * 131073 + b'\n'):
            with self.subTest(length=len(payload)), socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(5)
                connection.connect(str(self.path))
                connection.sendall(payload)
                connection.shutdown(socket.SHUT_WR)
                self.assertEqual(connection.recv(128), b'{"ok":false}\n')
        dispatch.assert_not_called()

    def test_outbox_does_not_expose_identity_fields(self):
        wallet = Wallet(str(self.directory / "wallet.sqlite"), "synthetic", notifications=True)
        with wallet.transaction() as db:
            # Register a purely synthetic credential for the foreign-key constraint.
            db.execute("INSERT INTO credentials(id,public_key,state,created,expires,subject) VALUES(?,?,?,?,?,?)",
                       ("a"*64, "synthetic", "PENDING_REVIEW", 1, 2000000000, "synthetic-subject"))
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

    def test_export_failure_retains_same_event_and_ack_is_terminal(self):
        wallet = Wallet(str(self.directory / "wallet.sqlite"), "synthetic", notifications=True)
        with wallet.transaction() as db:
            db.execute("INSERT INTO credentials(id,public_key,state,created,expires,subject) VALUES(?,?,?,?,?,?)",
                       ("a"*64, "synthetic", "PENDING_REVIEW", 1, 2000000000, "synthetic-subject"))
            db.execute("INSERT INTO notice_outbox(event,credential,contact_version,kind,created) VALUES(?,?,?,?,?)",
                       ("e"*64, "a"*64, "v"*16, "ACTIVATED_V1", 1))
        self.run_server(lambda body: notice_dispatch(wallet, body))
        sqs = Mock()
        sqs.send_message.side_effect = RuntimeError("synthetic queue outage")
        with self.assertRaises(RuntimeError):
            deliver_once(self.path, sqs, "https://queue.example.invalid")
        first = sqs.send_message.call_args.kwargs["MessageBody"]
        sqs.send_message.side_effect = None
        sqs.send_message.return_value = {"MessageId": "r"*20}
        self.assertTrue(deliver_once(self.path, sqs, "https://queue.example.invalid"))
        self.assertEqual(sqs.send_message.call_args.kwargs["MessageBody"], first)
        self.assertFalse(deliver_once(self.path, sqs, "https://queue.example.invalid"))
        self.assertEqual(request(self.path, {"operation":"ack", "event":"e"*64,
                                           "receipt":"r"*20}), {"updated":False})


if __name__ == "__main__":
    unittest.main()
