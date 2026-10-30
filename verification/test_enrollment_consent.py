"""Synthetic enrollment evidence with real device signatures and SQLite transactions.

Apple, passport and biometric checks are doubles here; existing native/CLI tests
cover those boundaries. No result in this module is a legal validity decision.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import secrets
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from enrollment_policy import EnrollmentPolicy
from native import NativeSessions
from test_chip_fixture import ChipFixture, signed, fixture_order
from test_enrollment_policy import fixture_policy, NOW
from test_wallet import crypt
from test_test_beta import Authority
from wallet import Wallet, TEST_BETA_END


def synthetic_document():
    from identity import VerifiedDocument
    return VerifiedDocument(b'synthetic portrait',dict(givenNames='ALICE',familyName='SYNTHETIC',
        birthDateMrz='900101',nationality='UTO',issuingState='UTO',documentNumber='TEST00001',
        documentExpires='2040-01-01'),'CHECKED_CRL',4102444800)


class EnrollmentConsentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = [json.loads(crypt(op='new')) for _ in range(2)]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.now = NOW
        self.wallet = Wallet(self.root/'wallet.sqlite', 'https://localhost:8765', clock=lambda: self.now)
        self.policy = EnrollmentPolicy(fixture_policy(), clock=lambda: self.now)
        self.attest = Mock()
        self.attest.check.side_effect = lambda op, **kw: {'publicKey':'synthetic-app-key'} if op == 'attestation' else {'signCount':kw['signCount']+1}
        self.passport = Mock(); self.biometry = Mock(return_value=([.9]*3,[.9]*3,[0,-.25,.25]))
        self.native = NativeSessions(self.attest,self.passport,None,None,clock=lambda:self.now,
            wall_clock=lambda:self.now,wallet=self.wallet,chip_factory=ChipFixture,
            biometrics=self.biometry,pose_order=fixture_order,enrollment_policy=self.policy)
        self.addCleanup(self.native.close)

    def registered(self):
        start = self.native.start()
        return self.native.register({'id':start['id'],'keyId':'synthetic-key','attestation':'synthetic-attestation'})

    def choice(self, registered):
        return registered | {'devicePublicKey':self.keys[0]['publicKey'],'receipt':secrets.token_hex(32),
            'acceptance':{'policyDigest':self.policy.digest,'termsAccepted':True,'biometricsAccepted':True}}

    def consent(self):
        registered = self.registered(); choice = self.choice(registered)
        return self.native.consent(signed(registered['id'],choice))

    def document(self, consent, key=0):
        return {k:consent[k] for k in ('id','nonce')} | {'devicePublicKey':self.keys[key]['publicKey'],
            'sod':'YQ==','dg1':'YQ==','dg2':'YQ==','dg14':'YQ=='}

    def withdrawal(self, receipt, key=0, **changes):
        data = {'action':'withdraw-enrollment-consent','origin':self.wallet.origin,'receipt':receipt} | changes
        raw = base64.b64encode(json.dumps(data).encode()).decode()
        return {'publicKey':self.keys[key]['publicKey'],'payload':raw,
            'signature':crypt(op='sign',key=self.keys[key]['privateKey'],payload=raw)}

    def test_no_passport_processing_before_current_separate_choices(self):
        registered = self.registered()
        with self.assertRaises(ValueError): self.native.begin_chip(signed(registered['id'],self.document(registered)))
        for choice in ({'termsAccepted':False},{'biometricsAccepted':False},{'policyDigest':'0'*64}):
            registered = self.registered(); data = self.choice(registered); data['acceptance'].update(choice)
            with self.assertRaises(ValueError): self.native.consent(signed(registered['id'],data))
            with self.assertRaises(ValueError): self.native.consent(signed(registered['id'],data))
        self.passport.assert_not_called(); self.biometry.assert_not_called()
        with self.wallet.transaction() as db:
            self.assertEqual(0,db.execute('SELECT count(*) FROM enrollment_consents').fetchone()[0])

    def test_signed_receipt_precedes_identity_and_nonce_changes(self):
        registered=self.registered(); data=self.choice(registered)
        result=self.native.consent(signed(registered['id'],data))
        self.assertEqual(data['receipt'],result['receipt']); self.assertNotEqual(registered['nonce'],result['nonce'])
        with self.wallet.transaction() as db:
            self.assertEqual(0,db.execute('SELECT count(*) FROM credentials').fetchone()[0])
            evidence=db.execute('SELECT proof FROM enrollment_consents').fetchone()[0]
            self.assertEqual(self.policy.archived(),json.loads(db.execute('SELECT record FROM enrollment_policies').fetchone()[0]))
            self.assertNotIn('dg1',evidence)
        with self.assertRaises(ValueError): self.native.consent(signed(registered['id'],data))
        with self.assertRaises(ValueError): self.native.begin_chip(signed(result['id'],self.document(result,key=1)))
        self.passport.assert_not_called()

    def test_bad_assertion_or_persistence_failure_cannot_advance_to_passport(self):
        registered=self.registered(); data=self.choice(registered)
        self.attest.check.side_effect=ValueError('rejected assertion')
        with self.assertRaises(ValueError): self.native.consent(signed(registered['id'],data))
        self.assertNotIn(registered['id'],self.native.pending)
        self.passport.assert_not_called()
        with self.wallet.transaction() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM enrollment_consents').fetchone()[0])
        self.attest.check.side_effect=lambda op,**kw: {'publicKey':'synthetic-app-key'} if op=='attestation' else {'signCount':kw['signCount']+1}
        registered=self.registered();data=self.choice(registered)
        self.wallet.record_acceptance=Mock(side_effect=sqlite3.OperationalError('synthetic disk failure'))
        with self.assertRaises(sqlite3.OperationalError):self.native.consent(signed(registered['id'],data))
        self.assertNotIn(registered['id'],self.native.pending)

    def test_withdrawal_is_authenticated_origin_bound_permanent_and_survives_restart(self):
        consent=self.consent(); receipt=consent['receipt']
        for request in (self.withdrawal(receipt,key=1),self.withdrawal(receipt,origin='https://other.invalid'),
                        self.withdrawal(receipt,action='approve'),self.withdrawal(receipt)|{'signature':'YQ=='}):
            with self.assertRaises(ValueError): self.native.withdraw(request)
        self.wallet.require_acceptance(receipt,self.keys[0]['publicKey'])
        restarted=Wallet(self.wallet.path,self.wallet.origin,clock=lambda:self.now)
        request=self.withdrawal(receipt)
        self.assertTrue(restarted.withdraw_acceptance(request)['withdrawn'])
        self.now+=1;self.assertTrue(restarted.withdraw_acceptance(request)['withdrawn'])
        with restarted.transaction() as db:self.assertEqual(NOW,db.execute('SELECT withdrawn FROM enrollment_consents').fetchone()[0])
        with self.assertRaises(ValueError): self.native.begin_chip(signed(consent['id'],self.document(consent)))
        self.passport.assert_not_called()

    def test_expiry_before_biometrics_and_withdrawal_after_chip_prevent_analysis(self):
        for withdraw in (False,True):
            self.now=NOW; consent=self.consent()
            chip=self.native.begin_chip(signed(consent['id'],self.document(consent)))
            capture=self.native.chip_step({'id':consent['id'],'chipToken':chip['chipToken'],'sequence':0,'response':'kAA='})
            if withdraw:self.wallet.withdraw_acceptance(self.withdrawal(consent['receipt']))
            else:self.now+=300
            with self.assertRaises(ValueError): self.native.finish(signed(consent['id'],
                {'id':consent['id'],'nonce':capture['nonce'],'frames':['YQ==','Yg==','Yw==']}))
        self.biometry.assert_not_called()

    def test_receipt_binding_is_atomic_and_competing_enrollments_cannot_reuse_it(self):
        consent=self.consent()
        def enroll(_):
            try:
                Wallet(self.wallet.path,self.wallet.origin,clock=lambda:self.now).enroll(
                    self.keys[0]['publicKey'],acceptance_receipt=consent['receipt'])
                return True
            except ValueError:return False
        with ThreadPoolExecutor(2) as pool:self.assertEqual(1,sum(pool.map(enroll,range(2))))
        with self.wallet.transaction() as db:
            self.assertEqual(1,db.execute('SELECT count(*) FROM credentials').fetchone()[0])
            self.assertEqual(1,db.execute('SELECT count(*) FROM credential_consents').fetchone()[0])
        self.wallet.withdraw_acceptance(self.withdrawal(consent['receipt']))
        with self.wallet.transaction() as db:
            self.assertEqual('PENDING_REVIEW',db.execute('SELECT state FROM credentials').fetchone()[0])

    def complete_capture(self, consent):
        chip=self.native.begin_chip(signed(consent['id'],self.document(consent)))
        capture=self.native.chip_step({'id':consent['id'],'chipToken':chip['chipToken'],'sequence':0,'response':'kAA='})
        return signed(consent['id'],{'id':consent['id'],'nonce':capture['nonce'],'frames':['YQ==','Yg==','Yw==']})

    def test_success_binds_receipt_profile_and_pending_credential_in_one_transaction(self):
        self.passport.return_value=synthetic_document()
        consent=self.consent()
        # Thumbnail decoding is covered by profile-worker tests; test the real
        # database/profile encryption and receipt transaction with synthetic bytes.
        with patch('profile_worker.thumbnail',return_value=b'synthetic thumbnail'):
            result=self.native.finish(self.complete_capture(consent))
        self.assertTrue(result['checksPassed']);self.assertEqual('PENDING_REVIEW',result['credential']['state'])
        with self.wallet.transaction() as db:
            self.assertEqual(consent['receipt'],db.execute('SELECT receipt FROM credential_consents JOIN profiles '
                'ON credential_consents.credential=profiles.credential').fetchone()[0])

    def configure_test_beta(self, *, notice_seconds=600):
        self.now = TEST_BETA_END - 20*86400
        self.remote = Authority()
        self.wallet = Wallet(self.root/('beta-'+secrets.token_hex(4)+'.sqlite'),
            'https://localhost:8765', clock=lambda: self.now, revocation=self.remote,
            notifications=True, test_beta=True)
        value = fixture_policy()
        value['notice'].update(notBefore=self.now-60, notAfter=self.now+notice_seconds)
        self.policy = EnrollmentPolicy(value, clock=lambda: self.now)
        self.native.wallet = self.wallet
        self.native.enrollment_policy = self.policy
        self.passport.return_value = synthetic_document()

    def test_test_beta_auto_activation_preserves_signed_consent_binding(self):
        self.configure_test_beta()
        consent = self.consent()
        with patch('profile_worker.thumbnail', return_value=b'synthetic thumbnail'):
            result = self.native.finish(self.complete_capture(consent))
        self.assertEqual('ACTIVE', result['credential']['state'])
        self.assertEqual(TEST_BETA_END, result['testBetaEndsAt'])
        with self.wallet.transaction() as db:
            row = db.execute('SELECT c.receipt,p.credential FROM credential_consents c '
                'JOIN profiles p ON c.credential=p.credential').fetchone()
            self.assertEqual((consent['receipt'], result['credential']['id']), tuple(row))
            self.assertEqual(0, db.execute('SELECT count(*) FROM notice_contacts').fetchone()[0])

    def test_test_beta_cannot_commit_consent_or_notice_expired_during_remote_calls(self):
        for operation in ('register_test', 'assert_allowed'):
            for notice_expires in (False, True):
                with self.subTest(operation=operation, notice_expires=notice_expires):
                    self.configure_test_beta(notice_seconds=60 if notice_expires else 600)
                    consent = self.consent()
                    original = getattr(self.remote, operation)
                    def expire(*args):
                        original(*args)
                        self.now += 60 if notice_expires else 300
                    with patch.object(self.remote, operation, side_effect=expire), \
                            patch('profile_worker.thumbnail', return_value=b'synthetic thumbnail'):
                        with self.assertRaises(ValueError):
                            self.native.finish(self.complete_capture(consent))
                    with self.wallet.transaction() as db:
                        for table in ('credentials', 'profiles', 'credential_consents',
                                      'test_beta_revocation_codes', 'events'):
                            self.assertEqual(0, db.execute('SELECT count(*) FROM '+table).fetchone()[0])

    def test_withdrawal_during_inference_prevents_credential_and_profile_commit(self):
        self.passport.return_value=synthetic_document();consent=self.consent()
        def withdraw_then_score(*args):
            self.wallet.withdraw_acceptance(self.withdrawal(consent['receipt']))
            return [.9]*3,[.9]*3,[0,-.25,.25]
        self.biometry.side_effect=withdraw_then_score
        with self.assertRaises(ValueError):self.native.finish(self.complete_capture(consent))
        with self.wallet.transaction() as db:
            self.assertEqual(0,db.execute('SELECT count(*) FROM credentials').fetchone()[0])
            self.assertEqual(0,db.execute('SELECT count(*) FROM profiles').fetchone()[0])

    def test_receipt_expiry_during_profile_write_rolls_back_credential_and_binding(self):
        self.passport.return_value=synthetic_document();consent=self.consent()
        original=self.wallet.vault.crypt
        def encrypt_then_expire(*args,**kwargs):
            value=original(*args,**kwargs);self.now+=300;return value
        with patch.object(self.wallet.vault,'crypt',side_effect=encrypt_then_expire), \
                patch('profile_worker.thumbnail',return_value=b'synthetic thumbnail'):
            with self.assertRaisesRegex(ValueError,'acceptance expired before commit'):
                self.native.finish(self.complete_capture(consent))
        with self.wallet.transaction() as db:
            for table in ('credentials','profiles','credential_consents'):
                self.assertEqual(0,db.execute('SELECT count(*) FROM '+table).fetchone()[0])

    def test_archive_and_backup_preserve_exact_text_signature_and_withdrawal(self):
        from audit_archive import export_snapshot,sqlite_snapshot,verify
        from recovery import backup
        consent=self.consent();self.wallet.withdraw_acceptance(self.withdrawal(consent['receipt']))
        target=self.root/'archive'
        result=export_snapshot(sqlite_snapshot(self.wallet.path),target,'sqlite','a'*40)
        self.assertEqual('VERIFIED',verify(target,result['manifestSha256'])['state'])
        self.assertEqual(5,json.loads((target/'manifest.json').read_text())['format'])
        self.assertIn(consent['receipt'],(target/'enrollment_consents.jsonl').read_text())
        copy=backup(self.wallet,self.root/'backup')
        with sqlite3.connect(copy) as db:
            self.assertEqual((consent['receipt'],NOW),db.execute('SELECT id,withdrawn FROM enrollment_consents').fetchone())
        with self.wallet.transaction() as db:db.execute('DROP TABLE credential_consents')
        with self.assertRaisesRegex(ValueError,'incomplete consent schema'):
            export_snapshot(sqlite_snapshot(self.wallet.path),self.root/'incomplete','sqlite','a'*40)


if __name__=='__main__':unittest.main()
