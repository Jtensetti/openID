import base64
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from crypto_runtime import CryptoRuntime
from test_wallet import crypt
from test_identity import document
from wallet import Wallet


class CryptoRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.crypto=CryptoRuntime(); self.addCleanup(self.crypto.close)
        self.key=json.loads(crypt(op='new'))

    def test_reuse_keeps_signature_checks_and_rejects_changed_payload(self):
        self.crypto.device('validate',publicKey=self.key['publicKey'])
        pid=self.crypto.signature.process.pid
        payload=base64.b64encode(b'bound transaction').decode()
        signature=crypt(op='sign',key=self.key['privateKey'],payload=payload)
        for _ in range(4):self.crypto.device('verify',publicKey=self.key['publicKey'],payload=payload,signature=signature)
        self.assertEqual(pid,self.crypto.signature.process.pid)
        with self.assertRaises(ValueError):self.crypto.device('verify',publicKey=self.key['publicKey'],payload='YQ==',signature=signature)
        self.crypto.device('verify',publicKey=self.key['publicKey'],payload=payload,signature=signature)

    def test_dead_child_restarts_without_accepting_a_failed_result(self):
        self.crypto.device('validate',publicKey=self.key['publicKey'])
        process=self.crypto.signature.process; process.kill(); process.wait()
        self.crypto.device('validate',publicKey=self.key['publicKey'])
        self.assertNotEqual(process.pid,self.crypto.signature.process.pid)

    def test_stalled_child_is_killed_and_next_request_is_fresh(self):
        self.crypto.device('validate',publicKey=self.key['publicKey'])
        process=self.crypto.signature.process
        self.crypto.signature.timeout=0.3
        os.kill(process.pid,signal.SIGSTOP)
        try:
            with self.assertRaises((ValueError,OSError)):self.crypto.device('validate',publicKey=self.key['publicKey'])
            self.assertIsNotNone(process.poll())
        finally:
            if process.poll() is None:process.kill();process.wait()
        self.crypto.signature.timeout=10
        self.crypto.device('validate',publicKey=self.key['publicKey'])

    def test_profile_aad_tampering_key_loss_and_revocation(self):
        with tempfile.TemporaryDirectory() as temp:
            wallet=Wallet(Path(temp)/'wallet.sqlite','https://localhost:8765',crypto=self.crypto.device,vault_runner=self.crypto.profile)
            ident=wallet.enroll(self.key['publicKey'],document())['id']
            wallet.activate(ident,'TEST-PRIVATE-REVIEW')
            with wallet.transaction() as db:
                row=db.execute('SELECT * FROM profiles').fetchone()
                sealed=json.loads(row['sealed'])
                profile=wallet.vault.crypt('open',ident,row['person'],sealed)
                self.assertEqual('ALICE SYNTHETIC',profile['displayName'])
                with self.assertRaises(ValueError):wallet.vault.crypt('open',ident,'wrong-person',sealed)
                bad=sealed|{'tag':base64.b64encode(b'x'*16).decode()}
                with self.assertRaises(ValueError):wallet.vault.crypt('open',ident,row['person'],bad)
                self.assertEqual(profile,wallet.vault.crypt('open',ident,row['person'],sealed))
            wallet.revoke(ident)
            with wallet.transaction() as db:self.assertIsNone(wallet.snapshot(db,ident)['identity'])
            wallet.vault.path.unlink()
            with self.assertRaises(OSError):wallet.vault.crypt('open',ident,row['person'],sealed)

    def test_oversized_ipc_and_recycling(self):
        with self.assertRaises(ValueError):self.crypto.profile({'value':'x'*100001})
        self.crypto.device('validate',publicKey=self.key['publicKey'])
        pid=self.crypto.signature.process.pid
        self.crypto.signature.calls=1000
        self.crypto.device('validate',publicKey=self.key['publicKey'])
        self.assertNotEqual(pid,self.crypto.signature.process.pid)
