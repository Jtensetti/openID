import base64
import json
from pathlib import Path
import unittest
from unittest.mock import Mock
import numpy as np
from native import NativeSessions, AppAttest
from identity import VerifiedDocument
from pad import PresentationAttackDetector
from test_chip_fixture import ChipFixture, capture_ready

class NativeTests(unittest.TestCase):
    def setUp(self):
        self.time=100
        self.attest=Mock();self.attest.check.side_effect=lambda op,**kw: {'publicKey':'key'} if op=='attestation' else {'signCount':kw['signCount']+1}
        self.passport=Mock(return_value=VerifiedDocument(b'authenticated portrait', {}))
        self.matcher=Mock();self.matcher.compare.return_value=0.95;self.matcher.decode_face.return_value=('image','face')
        self.pad=Mock();self.pad.score.return_value=0.95
        self.sessions=NativeSessions(self.attest,self.passport,self.matcher,self.pad,lambda:self.time,chip_factory=ChipFixture)
        self.addCleanup(self.sessions.close)
    def capture(self):
        started=self.sessions.start();registered=self.sessions.register({'id':started['id'],'keyId':'key','attestation':'data'})
        payload=capture_ready(self.sessions,registered,dict(sod='YQ==',dg1='YQ==',dg2='YQ==',dg14='YQ=='))
        self.passport.reset_mock()
        return started['id'],payload
    def request(self,ident,payload):return {'id':ident,'payload':base64.b64encode(json.dumps(payload).encode()).decode(),'assertion':'signed bytes'}
    def test_bound_pipeline_and_one_shot(self):
        ident,payload=self.capture();request=self.request(ident,payload)
        result=self.sessions.finish(request)
        self.assertTrue(result['checksPassed']);self.assertFalse(result['issuanceEnabled'])
        self.assertEqual('SERVER_VERIFIED_CA',result['chipAuthentication'])
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
    def test_nan_infinite_and_out_of_range_scores_fail_closed(self):
        for model in (self.pad.score, self.matcher.compare):
            for value in (float('nan'), float('inf'), -float('inf'), 1.01):
                model.side_effect=[0.95,value,0.95]
                ident,payload=self.capture()
                with self.assertRaises(ValueError):self.sessions.finish(self.request(ident,payload))
            model.side_effect=None
    def test_client_supplied_identity_fields_are_rejected(self):
        ident,payload=self.capture();payload['identity']={'displayName':'OTHER PERSON'}
        with self.assertRaises(ValueError):self.sessions.finish(self.request(ident,payload))
        self.passport.assert_not_called()
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
    def chip_start(self):
        started=self.sessions.start()
        registered=self.sessions.register({'id':started['id'],'keyId':'key','attestation':'test'})
        payload={**registered,'sod':'YQ==','dg1':'YQ==','dg2':'YQ==','dg14':'YQ=='}
        return self.sessions.begin_chip(self.request(started['id'],payload))
    def test_old_client_boolean_cannot_skip_server_chip(self):
        started=self.sessions.start();registered=self.sessions.register({'id':started['id'],'keyId':'key','attestation':'test'})
        payload={**registered,'sod':'YQ==','dg1':'YQ==','dg2':'YQ==','chipAuthentication':True,'frames':['YQ==','Yg==','Yw==']}
        with self.assertRaises(ValueError):self.sessions.finish(self.request(started['id'],payload))
        self.passport.assert_not_called();self.matcher.compare.assert_not_called()
    def test_chip_token_sequence_and_deadline_fail_closed(self):
        for field,value in [('chipToken','other'),('sequence',1),('sequence',True),('response','bogus')]:
            first=self.chip_start();chip=self.sessions.pending[first['id']]['chip']
            request={'id':first['id'],'chipToken':first['chipToken'],'sequence':0,'response':'kAA=',field:value}
            with self.subTest(field=field),self.assertRaises(ValueError):self.sessions.chip_step(request)
            self.assertTrue(chip.closed);self.assertNotIn(first['id'],self.sessions.pending)
        first=self.chip_start();self.time+=75
        with self.assertRaises(ValueError):self.sessions.chip_step({'id':first['id'],'chipToken':first['chipToken'],'sequence':0,'response':'kAA='})
    def test_cancel_closes_chip_and_cannot_be_reused(self):
        first=self.chip_start();chip=self.sessions.pending[first['id']]['chip']
        request={'id':first['id'],'chipToken':first['chipToken']}
        self.assertTrue(self.sessions.cancel(request)['cancelled']);self.assertTrue(chip.closed)
        with self.assertRaises(ValueError):self.sessions.cancel(request)
    def test_finish_cannot_change_document_or_device_key(self):
        for field,value in [('devicePublicKey','other'),('dg1','Yg=='),('chipAuthentication',True)]:
            ident,payload=self.capture();payload[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.sessions.finish(self.request(ident,payload))
        self.matcher.compare.assert_not_called()
    def test_assertion_counter_must_advance_after_chip_start(self):
        ident,payload=self.capture();self.attest.check.side_effect=lambda *a,**k:{'signCount':1}
        with self.assertRaises(ValueError):self.sessions.finish(self.request(ident,payload))
        self.matcher.compare.assert_not_called()
    def test_no_chip_provider_never_falls_back(self):
        self.sessions.chip_factory=None
        with self.assertRaises(ValueError):self.chip_start()
        self.passport.assert_not_called()
    def test_chip_replay_cannot_advance_capture(self):
        first=self.chip_start()
        request={'id':first['id'],'chipToken':first['chipToken'],'sequence':0,'response':'kAA='}
        self.sessions.chip_step(request)
        with self.assertRaises(ValueError):self.sessions.chip_step(request)
        self.matcher.compare.assert_not_called()

class NativeHTTPTests(unittest.TestCase):
    def setUp(self):
        import threading
        from http.server import HTTPServer
        from server import handler
        self.attest=Mock();self.attest.check.side_effect=lambda op,**kw: {'publicKey':'key'} if op=='attestation' else {'signCount':kw['signCount']+1}
        matcher=Mock();matcher.compare.return_value=0.95;matcher.decode_face.return_value=('image','face')
        pad=Mock();pad.score.return_value=0.95
        self.native=NativeSessions(self.attest,lambda _:VerifiedDocument(b'portrait',{}),matcher,pad,chip_factory=ChipFixture)
        self.http=HTTPServer(('127.0.0.1',0),handler(matcher,[],0))
        self.origin=f'http://localhost:{self.http.server_port}';self.token='x'*43
        self.http.RequestHandlerClass=handler(matcher,[],self.http.server_port,native=self.native,origin=self.origin,token=self.token,browser_enabled=False)
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):
        self.native.close();self.http.shutdown();self.http.server_close();self.thread.join()
    def post(self,path,data,origin=None):
        from urllib.request import Request,urlopen
        from urllib.error import HTTPError
        request=Request(self.origin+path,data=json.dumps(data).encode(),headers={'Content-Type':'application/json',
            'Origin':origin or self.origin,'X-CSRF-Token':self.token})
        try:
            with urlopen(request) as response:return response.status,json.load(response)
        except HTTPError as error:return error.code,json.load(error)
    def begin(self):
        from test_chip_fixture import signed
        code,start=self.post('/native/start',{});self.assertEqual(200,code)
        code,registered=self.post('/native/attest',{'id':start['id'],'keyId':'key','attestation':'test'});self.assertEqual(200,code)
        code,chip=self.post('/native/chip/start',signed(start['id'],{**registered,'sod':'YQ==','dg1':'YQ==','dg2':'YQ==','dg14':'YQ=='}))
        self.assertEqual(200,code)
        return chip
    def test_complete_http_sequence(self):
        from test_chip_fixture import signed
        chip=self.begin()
        code,capture=self.post('/native/chip/step',{'id':chip['id'],'chipToken':chip['chipToken'],'sequence':0,'response':'kAA='})
        self.assertEqual(200,code)
        request=signed(chip['id'],{'id':chip['id'],'nonce':capture['nonce'],'frames':['YQ==','Yg==','Yw==']})
        code,result=self.post('/native/finish',request)
        self.assertEqual(200,code);self.assertEqual('SERVER_VERIFIED_CA',result['chipAuthentication'])
        self.assertEqual(400,self.post('/native/finish',request)[0])
    def test_origin_size_and_cancel_boundaries(self):
        chip=self.begin();request={'id':chip['id'],'chipToken':chip['chipToken'],'sequence':0,'response':'kAA='}
        self.assertEqual(403,self.post('/native/chip/step',request,origin='https://other.invalid')[0])
        self.assertEqual(413,self.post('/native/chip/step',{**request,'response':'a'*17000})[0])
        self.assertEqual(200,self.post('/native/cancel',{'id':chip['id'],'chipToken':chip['chipToken']})[0])
        self.assertEqual(400,self.post('/native/chip/step',request)[0])
    def test_http_finish_before_chip_confirmation_fails(self):
        from test_chip_fixture import signed
        chip=self.begin()
        self.assertEqual(400,self.post('/native/finish',signed(chip['id'],{'id':chip['id'],'nonce':'wrong','frames':['YQ==','Yg==','Yw=='],'chipAuthentication':True}))[0])
        self.assertNotIn(chip['id'],self.native.pending)

if __name__=='__main__':unittest.main()
