"""Synthetic authority/SQLite boundary tests; no passport or crypto claims."""
import base64
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from revocation import RevocationAuthority, RevocationUnavailable, lambda_authority
from wallet import Wallet


class RevocationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'wallet.sqlite'
        self.states = {}
        self.failed = False
        self.calls = []
        self.authority = RevocationAuthority(self.invoke)
        self.wallet = self.new_wallet(self.path)
        self.ident = self.wallet.enroll(base64.b64encode(b'synthetic-key').decode())['id']

    def invoke(self, payload):
        self.calls.append(payload)
        if self.failed: raise OSError('provider unavailable')
        ident = payload['credential']
        if payload['operation'] == 'revoke': self.states[ident] = 'REVOKED'
        return {'credential': ident, 'state': self.states.get(ident, 'UNKNOWN')}

    def new_wallet(self, path):
        return Wallet(path, 'https://example.invalid', clock=lambda: 1000,
                      crypto=lambda *a, **k: None, revocation=self.authority)

    def activate(self):
        self.states[self.ident] = 'ENABLED'
        self.wallet.activate(self.ident, 'synthetic-review')

    def test_missing_registration_blocks_activation(self):
        with self.assertRaises(ValueError): self.wallet.activate(self.ident, 'synthetic-review')
        with self.wallet.transaction() as db:
            self.assertEqual('PENDING_REVIEW', self.wallet.credential(db, self.ident)['state'])

    def test_no_cached_allow_after_revocation(self):
        self.activate()
        self.wallet.start_request(self.ident)
        self.states[self.ident] = 'REVOKED'
        with self.assertRaises(ValueError): self.wallet.start_request(self.ident)
        with self.wallet.transaction() as db:
            self.assertEqual('REVOKED', self.wallet.state(self.wallet.credential(db, self.ident)))

    def test_unavailable_authority_blocks_access(self):
        self.activate()
        self.failed = True
        with self.assertRaises(RevocationUnavailable): self.wallet.start_request(self.ident)

    def test_restored_active_backup_does_not_restore_permission(self):
        self.activate()
        backup = Path(self.tmp.name) / 'old.sqlite'
        shutil.copyfile(self.path, backup)
        backup.chmod(0o600)
        self.authority.revoke(self.ident)  # Simulates revocation while verifier is stopped.
        restored = self.new_wallet(backup)
        with self.assertRaises(ValueError): restored.start_request(self.ident)

    def test_remote_revocation_survives_local_rollback(self):
        self.activate()
        with self.assertRaises(RuntimeError), self.wallet.transaction() as db:
            self.wallet._revoke(db, self.ident)
            raise RuntimeError('crash before local commit')
        with self.assertRaises(ValueError): self.wallet.start_request(self.ident)
        self.wallet.revoke(self.ident)
        self.wallet.revoke(self.ident)
        with self.wallet.transaction() as db:
            self.assertEqual('REVOKED', self.wallet.credential(db, self.ident)['state'])

    def test_failed_remote_revoke_is_not_reported_as_success(self):
        self.activate()
        self.failed = True
        with self.assertRaises(RevocationUnavailable): self.wallet.revoke(self.ident)

    def test_already_approved_result_cannot_be_consumed_after_night_revocation(self):
        self.activate()
        request = self.wallet.start_request(self.ident)
        with self.wallet.transaction() as db:
            db.execute("UPDATE requests SET state='APPROVED' WHERE id=?", (request['id'],))
        self.authority.revoke(self.ident)
        with self.assertRaises(ValueError): self.wallet.consume_result(request['id'], request['secret'])

    def test_invalid_or_wrong_credential_response_fails_closed(self):
        for response in [None, {}, {'credential': 'b'*64, 'state': 'ENABLED'},
                         {'credential': self.ident, 'state': 'unknown'}]:
            with self.subTest(response=response), self.assertRaises(RevocationUnavailable):
                RevocationAuthority(lambda _: response).assert_allowed(self.ident)

    def test_lambda_errors_are_not_valid_status(self):
        class Client:
            def invoke(self, **kwargs): return {'StatusCode': 200, 'FunctionError': 'Unhandled'}
        with self.assertRaises(RevocationUnavailable):
            lambda_authority(Client(), 'test').assert_allowed(self.ident)


if __name__ == '__main__': unittest.main()
