"""Synthetic campaign tests: real signatures/SQLite/encryption, simulated proofing and authority."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from identity import VerifiedDocument
from native import NativeSessions
from recovery import backup, restore
from test_chip_fixture import ChipFixture, capture_ready, fixture_order, pose_matcher, signed
from test_wallet import crypt
from wallet import Wallet, TEST_BETA_END


class Authority:
    def __init__(self): self.states = {}; self.fail = False; self.lock = threading.Lock()
    def request(self, operation, ident):
        if self.fail: raise ValueError('unavailable')
        return self.states.get(ident, 'UNKNOWN')
    def assert_allowed(self, ident):
        if self.request('status', ident) != 'ENABLED': raise ValueError('revoked')
    def register_test(self, ident, digest):
        with self.lock:
            if self.fail or ident in self.states: raise ValueError('registration rejected')
            self.states[ident] = 'ENABLED'
    def revoke(self, ident):
        with self.lock: self.states[ident] = 'REVOKED'


class TestBetaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.keys = [json.loads(crypt(op='new')) for _ in range(3)]
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'wallet.sqlite'
        self.time = TEST_BETA_END - 20*86400
        self.remote = Authority()
        self.wallet = self.open()
        self.document = VerifiedDocument(b'synthetic portrait', dict(givenNames='ALICE', familyName='SYNTHETIC',
            birthDateMrz='900101', nationality='UTO', issuingState='UTO', documentNumber='TEST00001', documentExpires='2030-01-01'))
        # JPEG resizing and passport cryptography have separate tests. No real identity input.
        p = patch.object(VerifiedDocument, 'profile', return_value={'displayName': 'ALICE SYNTHETIC', 'birthDateMrz':'900101', 'portraitJpeg': 'c3ludGhldGlj'})
        p.start(); self.addCleanup(p.stop)
    def open(self, **kw):
        return Wallet(self.path, 'https://api.openid.tensetti.io', clock=lambda:self.time,
            revocation=self.remote, notifications=True, test_beta=True, **kw)
    def enroll(self, key=0): return self.wallet.enroll(self.keys[key]['publicKey'], self.document, activate_test=True)['id']
    def state(self, ident):
        with self.wallet.transaction() as db: return self.wallet.snapshot(db, ident)
    def execute(self, action, ident, request=None, key=0):
        c = self.wallet.challenge({'credentialId':ident, 'action':action, 'requestId':request})
        return self.wallet.execute({'challengeId':c['id'], 'signature':crypt(op='sign', key=self.keys[key]['privateKey'], payload=c['signingInput'])})

    def test_auto_activation_without_email_and_long_validity(self):
        ident = self.enroll(); value = self.state(ident)
        self.assertEqual('ACTIVE', value['state']); self.assertEqual(TEST_BETA_END, value['expiresAt'])
        self.assertFalse(value['legalIdentityIssued']); self.assertEqual('PRIVATE_PILOT', value['environment'])
        self.assertTrue(value['revocationCode'].startswith(ident+'.'))
        self.assertNotIn(value['revocationCode'].split('.')[1].encode(), self.path.read_bytes())
        with self.wallet.transaction() as db:
            self.assertEqual(0, db.execute('SELECT count(*) FROM notice_contacts').fetchone()[0])
            self.assertEqual(0, db.execute('SELECT count(*) FROM notice_outbox').fetchone()[0])
        self.time += 5*86400
        self.assertEqual('ACTIVE', self.state(ident)['state'])

    def test_deadline_blocks_approved_result_existing_session_and_enrollment(self):
        ident = self.enroll(); self.time = TEST_BETA_END - 1
        req = self.wallet.start_request(ident); self.execute('approve', ident, req['id'])
        audience = 'https://sp.example.test'; binding = '_synthetic_test'
        fed = self.wallet.federation_start(binding, audience)
        self.execute('approve', ident, fed['id'])
        session = self.wallet.federation_result('consume', fed['id'], fed['secret'], binding, audience)
        self.assertEqual('ACTIVE', self.wallet.federation_check(ident, session['subject'], session['version'], audience)['state'])
        self.time = TEST_BETA_END
        self.assertEqual('REVOKED', self.state(ident)['state'])
        self.assertIsNone(self.state(ident)['identity'])
        for operation in [lambda:self.wallet.consume_result(req['id'], req['secret']),
                          lambda:self.wallet.start_request(ident),
                          lambda:self.wallet.federation_check(ident, session['subject'], session['version'], audience),
                          lambda:self.enroll(1), self.wallet.enrollment_available]:
            with self.assertRaises(ValueError): operation()

    def test_manual_pending_and_expired_credentials_also_revoked_at_end(self):
        ident = self.wallet.enroll(self.keys[0]['publicKey'], self.document)['id']
        self.assertEqual('PENDING_REVIEW', self.state(ident)['state'])
        self.time = TEST_BETA_END
        self.assertEqual('REVOKED', self.state(ident)['state'])

    def test_remote_failure_rolls_back_registration(self):
        self.remote.fail = True
        with self.assertRaises(ValueError): self.enroll()
        with self.wallet.transaction() as db:
            for table in ('credentials', 'profiles', 'test_beta_revocation_codes', 'events'):
                self.assertEqual(0, db.execute('SELECT count(*) FROM '+table).fetchone()[0])

    def test_replay_and_remote_revocation_cannot_reactivate(self):
        ident = self.enroll()
        with self.assertRaises(ValueError): self.enroll()
        self.remote.revoke(ident)
        self.assertEqual('REVOKED', self.state(ident)['state'])
        with self.assertRaises(ValueError): self.wallet.activate(ident, 'REVIEW-revive-test')
        self.assertEqual(0, self.wallet.extend_active_test_ids())

    def test_explicit_migration_extends_only_still_active_ids(self):
        ident = self.enroll()
        with self.wallet.transaction() as db:
            db.execute('UPDATE credentials SET expires=? WHERE id=?', (self.time+86400, ident))
        self.assertEqual(1, self.wallet.extend_active_test_ids())
        self.assertEqual(TEST_BETA_END, self.state(ident)['expiresAt'])
        self.assertEqual(0, self.wallet.extend_active_test_ids())
        with self.wallet.transaction() as db:
            db.execute('UPDATE credentials SET expires=? WHERE id=?', (self.time, ident))
        self.assertEqual(0, self.wallet.extend_active_test_ids())
        self.assertEqual('EXPIRED', self.state(ident)['state'])

    def test_missing_passport_and_unconfigured_mode_reject_automatic_activation(self):
        with self.assertRaises(ValueError): self.wallet.enroll(self.keys[0]['publicKey'], activate_test=True)
        with self.assertRaises(ValueError): Wallet(self.path, 'operator', revocation=self.remote, notifications=True)
        with self.wallet.transaction() as db: db.execute('UPDATE test_beta_policy SET ends=ends+1')
        with self.assertRaises(ValueError): self.open()

    def test_passport_expiry_is_still_an_upper_bound_and_not_extended(self):
        self.document.identity['documentExpires'] = '2026-11-12'
        ident = self.enroll(); expiry = self.state(ident)['expiresAt']
        self.assertLess(expiry, TEST_BETA_END)
        self.time = expiry
        self.assertEqual('EXPIRED', self.state(ident)['state'])
        self.assertEqual(0, self.wallet.extend_active_test_ids())

    def test_interrupted_local_commit_cannot_issue_credential(self):
        original = self.wallet.event
        def fail(db, ident, kind, request=None):
            if kind == 'ACTIVATED': raise OSError('synthetic failure')
            return original(db, ident, kind, request)
        with patch.object(self.wallet, 'event', side_effect=fail), self.assertRaises(OSError): self.enroll()
        with self.wallet.transaction() as db:
            self.assertEqual(0, db.execute('SELECT count(*) FROM credentials').fetchone()[0])
        # An orphan remote entry grants nothing without a local active credential.
        with self.assertRaises(ValueError): self.enroll()

    def test_old_backup_and_changed_configuration_cannot_reopen_campaign(self):
        ident = self.enroll()
        saved = backup(self.wallet, Path(self.tmp.name)/'backup')
        restored = restore(saved, Path(self.tmp.name)/'restored', self.wallet.vault.path)
        with self.assertRaises(ValueError): Wallet(restored, 'legacy')
        recovered = Wallet(restored, 'test', clock=lambda:TEST_BETA_END,
            revocation=self.remote, notifications=True, test_beta=True)
        with recovered.transaction() as db: self.assertEqual('REVOKED', recovered.snapshot(db, ident)['state'])
        with self.assertRaises(ValueError): recovered.enrollment_available()

    def test_native_gates_biometric_thresholds_pose_and_replay(self):
        attest = Mock(); attest.check.side_effect = lambda op, **kw: {'publicKey':'test'} if op == 'attestation' else {'signCount':kw['signCount']+1}
        matcher = pose_matcher(Mock()); matcher.compare.return_value = .95
        pad = Mock(); pad.score.return_value = .95
        native = NativeSessions(attest, lambda _:self.document, matcher, pad, wallet=self.wallet,
            chip_factory=ChipFixture, pose_order=fixture_order)
        self.addCleanup(native.close)
        def request():
            start = native.start(); registered = native.register({'id':start['id'], 'keyId':'key', 'attestation':'test'})
            payload = capture_ready(native, registered, dict(sod='YQ==', dg1='YQ==', dg2='YQ==', dg14='YQ==', devicePublicKey=self.keys[0]['publicKey']))
            return signed(start['id'], payload)
        for face, liveness in ((.49,.95), (.95,.79)):
            matcher.compare.return_value = face; pad.score.return_value = liveness
            self.assertIsNone(native.finish(request())['credential'])
        matcher.compare.return_value = .95; pad.score.return_value = .95; native.pose_enforced = False
        with self.assertRaises(ValueError): native.finish(request())
        native.pose_enforced = True
        r = request(); result = native.finish(r)
        self.assertEqual('ACTIVE', result['credential']['state']); self.assertFalse(result['issuanceEnabled'])
        self.assertEqual(TEST_BETA_END, result['testBetaEndsAt'])
        with self.assertRaises(ValueError): native.finish(r)


if __name__ == '__main__': unittest.main()
