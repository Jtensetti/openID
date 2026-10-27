"""Revocation evidence must survive the verifier boundary and the whole enrollment.

These application tests use explicit synthetic verifier results, not real passports.
The Java tests and test_verification.CliTests exercise actual signed CRLs.
"""
import base64
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from identity import VerifiedDocument
from native import NativeSessions
from test_chip_fixture import ChipFixture, signed
from wallet import Wallet


def verifier_result(**changes):
    return dict(passiveAuthentication=True, portrait='YQ==', revocation='CHECKED_CRL', revocationValidUntil=1500,
        identity=dict(givenNames='ALICE',familyName='SYNTHETIC',birthDateMrz='900101',nationality='UTO',
                      issuingState='UTO',documentNumber='TEST00001',documentExpires='2030-10-19')) | changes


class RevocationEvidenceTests(unittest.TestCase):
    def test_checked_status_and_exact_expiry_cross_the_boundary(self):
        doc=VerifiedDocument.from_verifier(verifier_result())
        doc.require_current_revocation(1499.999)
        self.assertEqual(('CHECKED_CRL',1500),(doc.revocation,doc.revocation_valid_until))
        for now in (1500,1501):
            with self.assertRaises(ValueError):doc.require_current_revocation(now)

    def test_missing_and_unchecked_result_cannot_authorize_enrollment(self):
        for metadata in ({'revocation':'NOT_CHECKED','revocationValidUntil':0}, {}):
            result=verifier_result();result.pop('revocation');result.pop('revocationValidUntil');result.update(metadata)
            doc=VerifiedDocument.from_verifier(result)
            with self.assertRaises(ValueError):doc.require_current_revocation(1000)

    def test_malformed_or_invented_revocation_result_is_rejected(self):
        for changes in ({'revocation':'GOOD'},{'revocation':True},{'revocation':None},
                        {'revocationValidUntil':True},{'revocationValidUntil':'1500'},
                        {'revocationValidUntil':1500.1},{'revocationValidUntil':0},
                        {'revocation':'NOT_CHECKED','revocationValidUntil':1500}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                VerifiedDocument.from_verifier(verifier_result(**changes))


class EnrollmentRevocationTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.now=1000
        self.crypto=Mock()
        self.wallet=Wallet(Path(self.directory.name)/'wallet.sqlite','https://example.invalid',
            clock=lambda:self.now,crypto=self.crypto)
        self.wallet.vault.runner=lambda _: {'value':'synthetic-sealed-profile'}
        self.key=base64.b64encode(b'synthetic-public-key').decode()
        self.doc=VerifiedDocument.from_verifier(verifier_result())

    def test_profile_worker_failures_roll_back_registration(self):
        from dataclasses import replace
        import subprocess
        from bounded_process import WorkerOutputLimit
        doc=replace(self.doc,portrait=b'\xff\xd8\xffsynthetic')
        failures=[subprocess.TimeoutExpired('worker',15), WorkerOutputLimit('output limit'),
                  subprocess.CompletedProcess([], -9, b''),
                  subprocess.CompletedProcess([], 0, b'\xff\xd8\xfftruncated')]
        for failure in failures:
            kwargs={'side_effect':failure} if isinstance(failure,Exception) else {'return_value':failure}
            with self.subTest(kind=type(failure).__name__), patch('profile_worker.run_bounded',**kwargs) as run:
                with self.assertRaises((ValueError,OSError,subprocess.TimeoutExpired)):
                    self.wallet.enroll(self.key,doc)
                run.assert_called_once()
            with self.wallet.transaction() as db:
                for table in ('credentials','profiles','persons','events'):
                    self.assertEqual(0,db.execute('SELECT count(*) FROM '+table).fetchone()[0])

    def test_unchecked_and_expired_documents_never_write_or_validate_a_key(self):
        for doc in (replace(self.doc,revocation='NOT_CHECKED',revocation_valid_until=0),
                    replace(self.doc,revocation_valid_until=1000)):
            with self.subTest(doc=doc.revocation):
                with self.assertRaises(ValueError):self.wallet.enroll(self.key,doc)
                with self.assertRaises(ValueError):self.wallet.biometric_attempt(doc)
        self.crypto.assert_not_called()
        with self.wallet.transaction() as db:
            for table in ('credentials','profiles','persons','events','biometric_failures'):
                self.assertEqual(0,db.execute('SELECT count(*) FROM '+table).fetchone()[0])

    def test_expiry_during_profile_creation_rolls_back_all_registration_rows(self):
        def expires(_):
            self.now=1500
            return {'displayName':'SYNTHETIC'}
        with patch.object(VerifiedDocument,'profile',expires),self.assertRaises(ValueError):
            self.wallet.enroll(self.key,self.doc)
        with self.wallet.transaction() as db:
            for table in ('credentials','profiles','persons','events'):
                self.assertEqual(0,db.execute('SELECT count(*) FROM '+table).fetchone()[0])

    def test_current_evidence_allows_pending_review_not_activation(self):
        with patch.object(VerifiedDocument,'profile',return_value={'displayName':'SYNTHETIC'}):
            result=self.wallet.enroll(self.key,self.doc)
        self.assertEqual('PENDING_REVIEW',result['state'])


class NativeRevocationTests(unittest.TestCase):
    def setUp(self):
        self.now=1000
        self.doc=VerifiedDocument.from_verifier(verifier_result())
        self.attest=Mock()
        self.attest.check.side_effect=lambda op,**kw: {'publicKey':'synthetic'} if op=='attestation' else {'signCount':kw['signCount']+1}
        self.wallet,self.biometrics,self.chips=Mock(),Mock(),Mock(side_effect=ChipFixture)
        self.native=NativeSessions(self.attest,lambda _:self.doc,None,None,wallet=self.wallet,
            chip_factory=self.chips,biometrics=self.biometrics,wall_clock=lambda:self.now)
        self.addCleanup(self.native.close)

    def begin(self):
        start=self.native.start()
        registration=self.native.register(dict(id=start['id'],keyId='test',attestation='test'))
        return self.native.begin_chip(signed(start['id'],dict(registration,sod='YQ==',dg1='YQ==',dg2='YQ==',dg14='YQ==')))

    def test_missing_revocation_rejected_before_chip_and_camera(self):
        self.doc=replace(self.doc,revocation='NOT_CHECKED',revocation_valid_until=0)
        with self.assertRaises(ValueError):self.begin()
        self.chips.assert_not_called();self.biometrics.assert_not_called();self.wallet.enroll.assert_not_called()
        self.assertFalse(self.native.pending)

    def test_expiry_during_chip_or_camera_consumes_session_before_analysis(self):
        chip=self.begin()
        capture=self.native.chip_step(dict(id=chip['id'],chipToken=chip['chipToken'],sequence=0,response='kAA='))
        self.now=1500
        request=signed(chip['id'],dict(id=chip['id'],nonce=capture['nonce'],frames=['YQ==','Yg==','Yw==']))
        with self.assertRaises(ValueError):self.native.finish(request)
        self.biometrics.assert_not_called();self.wallet.biometric_attempt.assert_not_called();self.wallet.enroll.assert_not_called()
        with self.assertRaises(ValueError):self.native.finish(request)


if __name__=='__main__':unittest.main()
