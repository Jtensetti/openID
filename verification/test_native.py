import base64
import json
from pathlib import Path
import unittest
from unittest.mock import Mock
import numpy as np
from native import NativeSessions, AppAttest
from pad import PresentationAttackDetector

class NativeTests(unittest.TestCase):
    def setUp(self):
        self.time=100
        self.attest=Mock();self.attest.check.side_effect=lambda op,**kw: {'publicKey':'key'} if op=='attestation' else {'signCount':1}
        self.passport=Mock(return_value=b'authenticated portrait')
        self.matcher=Mock();self.matcher.compare.return_value=0.95;self.matcher.decode_face.return_value=('image','face')
        self.pad=Mock();self.pad.score.return_value=0.95
        self.sessions=NativeSessions(self.attest,self.passport,self.matcher,self.pad,lambda:self.time)
    def capture(self):
        started=self.sessions.start();registered=self.sessions.register({'id':started['id'],'keyId':'key','attestation':'data'})
        payload={**registered,'sod':'YQ==','dg1':'YQ==','dg2':'YQ==','chipAuthentication':True,'frames':['YQ==','Yg==','Yw==']}
        payload.pop('frameCount')
        return started['id'],payload
    def request(self,ident,payload):return {'id':ident,'payload':base64.b64encode(json.dumps(payload).encode()).decode(),'assertion':'signed bytes'}
    def test_bound_pipeline_and_one_shot(self):
        ident,payload=self.capture();request=self.request(ident,payload)
        result=self.sessions.finish(request)
        self.assertTrue(result['checksPassed']);self.assertFalse(result['issuanceEnabled'])
        self.assertEqual(3,self.pad.score.call_count)
        with self.assertRaises(ValueError):self.sessions.finish(request)
    def test_expired_capture(self):
        ident,payload=self.capture();self.time+=300
        with self.assertRaises(ValueError):self.sessions.finish(self.request(ident,payload))
        self.passport.assert_not_called()
    def test_other_session_nonce_and_identity_rejected(self):
        for field in ['id','nonce']:
            ident,payload=self.capture();payload[field]='other'
            with self.subTest(field=field),self.assertRaises(ValueError):self.sessions.finish(self.request(ident,payload))
        self.passport.assert_not_called()
    def test_missing_chip_authentication(self):
        ident,payload=self.capture();payload['chipAuthentication']=False
        with self.assertRaises(ValueError):self.sessions.finish(self.request(ident,payload))
    def test_duplicate_frame_and_wrong_count(self):
        for frames in [['YQ==']*3,['YQ==','Yg==']]:
            ident,payload=self.capture();payload['frames']=frames
            with self.assertRaises(ValueError):self.sessions.finish(self.request(ident,payload))
    def test_failed_assertion_consumes_session_before_any_analysis(self):
        ident,payload=self.capture();request=self.request(ident,payload);self.attest.check.side_effect=ValueError('invalid signature')
        with self.assertRaises(ValueError):self.sessions.finish(request)
        with self.assertRaises(ValueError):self.sessions.finish(request)
        self.passport.assert_not_called();self.matcher.compare.assert_not_called()
    def test_failed_attestation_cannot_be_retried(self):
        started=self.sessions.start();self.attest.check.side_effect=ValueError('untrusted app')
        request={'id':started['id'],'keyId':'key','attestation':'data'}
        with self.assertRaises(ValueError):self.sessions.register(request)
        with self.assertRaises(ValueError):self.sessions.register(request)
    def test_low_pad_or_face_score_rejects_checks(self):
        ident,payload=self.capture();self.pad.score.return_value=0.2
        self.assertFalse(self.sessions.finish(self.request(ident,payload))['checksPassed'])
        self.pad.score.return_value=0.95;self.matcher.compare.return_value=0.1
        ident,payload=self.capture();self.assertFalse(self.sessions.finish(self.request(ident,payload))['checksPassed'])
    def test_only_authenticated_portrait_reaches_matcher(self):
        ident,payload=self.capture();self.sessions.finish(self.request(ident,payload))
        for call in self.matcher.compare.call_args_list:self.assertEqual(b'authenticated portrait',call.args[0])
    def test_sessions_are_bounded_and_expiry_frees_capacity(self):
        for _ in range(16):self.sessions.start()
        with self.assertRaises(ValueError):self.sessions.start()
        self.time+=300;self.assertIn('id',self.sessions.start())
    def test_real_app_attest_rejects_invalid_apple_evidence(self):
        verifier=AppAttest('ABCDEFGHIJ','se.openid.PassportCapture')
        with self.assertRaises(ValueError):verifier.check('attestation',attestation='YQ==',keyId='key',challenge='challenge')
    def test_real_pad_models_execute(self):
        detector=PresentationAttackDetector(Path(__file__).parent/'models')
        score=detector.score(np.zeros((320,320,3),dtype=np.uint8),np.array([90,90,100,100]))
        self.assertTrue(np.isfinite(score));self.assertGreaterEqual(score,0);self.assertLessEqual(score,1)

if __name__=='__main__':unittest.main()
