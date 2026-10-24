"""Security code (6 digits) for services that require more than Face ID: server-verified, counted and locked."""
import base64
import json
import tempfile
import unittest
from pathlib import Path
from federation import FederationServer
import test_identity
from test_identity import AUDIENCE, document
from test_wallet import crypt
from wallet import Wallet, SecurityCodeError, SECURITY_CODE_ATTEMPTS, weak_security_code


class SecurityCodeTests(unittest.TestCase):
    sign = test_identity.IdentityTests.sign
    execute = test_identity.IdentityTests.execute

    @classmethod
    def setUpClass(cls):
        cls.keys = [json.loads(crypt(op='new')) for _ in range(2)]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.time = 1792454400
        self.db = Path(self.tmp.name)/'wallet.sqlite'
        self.wallet = Wallet(self.db, 'https://localhost:8765', clock=lambda: self.time)
        self.ident = self.wallet.enroll(self.keys[0]['publicKey'], document())['id']
        self.wallet.activate(self.ident, 'REVIEW-fixture-001')

    def run_action(self, action, request=None, **extra):
        return self.wallet.execute(self.sign(action, request) | extra)

    def start(self, level='pin', message=None):
        return self.wallet.federation_start('_signed_saml_flow', AUDIENCE, message, level)

    def result(self, request, operation='consume'):
        return self.wallet.federation_result(operation, request['id'], request['secret'], '_signed_saml_flow', AUDIENCE)

    def error(self, action, request=None, **extra):
        with self.assertRaises(SecurityCodeError) as caught: self.run_action(action, request, **extra)
        return caught.exception.code, caught.exception.remaining

    def test_weak_codes_and_birth_date_are_refused(self):
        for code in ('000000', '111111', '123456', '654321', '012345', '121212', '123123', '112112', '900101', '010190', '010190'):
            with self.subTest(code=code): self.assertTrue(weak_security_code(code, '900101'))
        self.assertFalse(weak_security_code('482917', '900101'))
        self.assertEqual(('PIN_WEAK', None), self.error('set-pin', newPin='900101'))  # passport birth date YYMMDD
        self.assertEqual(('PIN_WEAK', None), self.error('set-pin', newPin='123456'))
        for malformed in ('12345', '1234567', 'abcdef', 482917, '４８２９１７'):
            with self.subTest(code=malformed), self.assertRaises(ValueError): self.run_action('set-pin', newPin=malformed)
        self.assertFalse(self.execute()['securityCode']['set'])

    def test_code_level_request_needs_code_and_names_level_in_signed_consent(self):
        request = self.start()
        shown = self.execute('inspect', request['id'])['requests'][0]
        self.assertEqual('pin', shown['verification'])
        challenge = self.wallet.challenge({'credentialId': self.ident, 'action': 'approve', 'requestId': request['id']})
        self.assertEqual('pin', json.loads(base64.b64decode(challenge['signingInput']))['verification'])
        self.assertEqual(('PIN_REQUIRED', None), self.error('approve', request['id'], pin='482917'))  # no code chosen yet
        self.run_action('set-pin', newPin='482917')
        self.assertEqual('PIN_REQUIRED', self.error('approve', request['id'])[0])
        self.assertEqual(('PIN_INCORRECT', SECURITY_CODE_ATTEMPTS-1), self.error('approve', request['id'], pin='482918'))
        self.assertEqual('PENDING', self.result(request, 'poll')['state'])  # a wrong code leaves the request open
        self.run_action('approve', request['id'], pin='482917')
        result = self.result(request)
        self.assertEqual('pin', result['verification'])
        self.assertEqual(SECURITY_CODE_ATTEMPTS, self.execute()['securityCode']['attemptsRemaining'])  # reset on success

    def test_face_id_level_never_takes_a_code_and_rejection_never_needs_one(self):
        self.run_action('set-pin', newPin='482917')
        login = self.start(level=None)
        with self.assertRaises(ValueError): self.run_action('approve', login['id'], pin='482917')
        self.run_action('approve', login['id'])
        self.assertNotIn('verification', self.result(login))
        high = self.start()
        with self.assertRaises(ValueError): self.run_action('reject', high['id'], pin='482917')
        self.run_action('reject', high['id'])
        self.assertEqual('REJECTED', self.result(high, 'poll')['state'])

    def test_five_wrong_codes_lock_for_good_and_persist_over_restart(self):
        self.run_action('set-pin', newPin='482917')
        request = self.start()
        for remaining in range(SECURITY_CODE_ATTEMPTS-1, 0, -1):
            self.assertEqual(('PIN_INCORRECT', remaining), self.error('approve', request['id'], pin='000001'))
        self.assertEqual(('PIN_LOCKED', 0), self.error('approve', request['id'], pin='000001'))
        restarted = Wallet(self.db, 'https://localhost:8765', clock=lambda: self.time)
        self.wallet = restarted
        self.assertEqual(('PIN_LOCKED', 0), self.error('approve', request['id'], pin='482917'))  # also the right code
        self.assertEqual(('PIN_LOCKED', 0), self.error('set-pin', pin='482917', newPin='739154'))  # no reset by the holder
        status = self.execute()['securityCode']
        self.assertTrue(status['locked']); self.assertEqual(0, status['attemptsRemaining'])
        kinds = [e['kind'] for e in self.execute()['events']]
        self.assertIn('SECURITY_CODE_LOCKED', kinds)
        login = self.start(level=None)  # Face ID level still works; the holder can also still revoke
        self.run_action('approve', login['id'])
        self.run_action('revoke')

    def test_change_needs_current_code_and_counts_failures(self):
        self.run_action('set-pin', newPin='482917')
        with self.assertRaises(ValueError): self.run_action('set-pin', newPin='739154')  # current code missing
        self.assertEqual(('PIN_INCORRECT', SECURITY_CODE_ATTEMPTS-1), self.error('set-pin', pin='111112', newPin='739154'))
        self.run_action('set-pin', pin='482917', newPin='739154')
        request = self.start()
        self.assertEqual('PIN_INCORRECT', self.error('approve', request['id'], pin='482917')[0])
        self.run_action('approve', request['id'], pin='739154')

    def test_code_is_not_stored_readably(self):
        self.run_action('set-pin', newPin='482917')
        self.assertNotIn(b'482917', self.db.read_bytes())
        other = Wallet(Path(self.tmp.name)/'other'/'wallet.sqlite', 'https://localhost:8765', clock=lambda: self.time)
        ident = other.enroll(self.keys[1]['publicKey'], document(documentNumber='TEST00002'))['id']
        other.activate(ident, 'REVIEW-fixture-002')
        self.wallet, keep = other, self.wallet
        challenge = other.challenge({'credentialId': ident, 'action': 'set-pin', 'requestId': None})
        other.execute({'challengeId': challenge['id'], 'signature': crypt(op='sign', key=self.keys[1]['privateKey'], payload=challenge['signingInput']), 'newPin': '482917'})
        import sqlite3
        hashes = [sqlite3.connect(db).execute('SELECT hash FROM security_codes').fetchone()[0] for db in (keep.path, other.path)]
        self.assertNotEqual(*hashes)  # per-credential and per-key HMAC: equal codes do not look equal

    def test_bridge_carries_level_and_rejects_unknown_levels(self):
        for level in ('PIN', 'face', ''):
            with self.assertRaises(ValueError): self.start(level=level)
        socket_dir = Path(self.tmp.name)/'sock'; socket_dir.mkdir(mode=0o700)
        bridge = FederationServer(socket_dir/'bridge.sock', self.wallet); self.addCleanup(bridge.close)
        started = bridge.dispatch({'operation': 'start', 'audience': AUDIENCE, 'binding': 'x', 'verification': 'pin'})
        self.assertEqual('pin', started['verification'])
        with self.assertRaises(ValueError): bridge.dispatch({'operation': 'start', 'audience': AUDIENCE, 'binding': 'x', 'extra': 1})


if __name__ == '__main__':
    unittest.main()
