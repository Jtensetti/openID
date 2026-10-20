import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock
from wallet import Wallet
from native import NativeSessions

CRYPTO = '''const c=require('node:crypto');let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{const r=JSON.parse(s);if(r.op==='new'){let p=c.generateKeyPairSync('ec',{namedCurve:'prime256v1'});process.stdout.write(JSON.stringify({publicKey:p.publicKey.export({format:'der',type:'spki'}).toString('base64'),privateKey:p.privateKey.export({format:'pem',type:'pkcs8'})}));}else{process.stdout.write(c.sign('sha256',Buffer.from(r.payload,'base64'),r.key).toString('base64'));}});'''
def crypt(**data):
    return subprocess.run(['node','-e',CRYPTO],input=json.dumps(data).encode(),stdout=subprocess.PIPE,check=True).stdout.decode()

class WalletTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key=json.loads(crypt(op='new'));cls.other=json.loads(crypt(op='new'))
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.time=1000;self.db=Path(self.tmp.name)/'wallet.sqlite'
        self.wallet=Wallet(self.db,'https://localhost:8765',clock=lambda:self.time)
        self.id=self.wallet.enroll(self.key['publicKey'])['id']
    def activate(self):self.wallet.activate(self.id,'REVIEW-private-001')
    def challenge(self,action='snapshot',request=None,ident=None):
        return self.wallet.challenge({'credentialId':ident or self.id,'action':action,'requestId':request})
    def signed(self,challenge,key=None,payload=None):
        return {'challengeId':challenge['id'],'signature':crypt(op='sign',key=(key or self.key)['privateKey'],payload=payload or challenge['signingInput'])}
    def execute(self,action='snapshot',request=None):return self.wallet.execute(self.signed(self.challenge(action,request)))
    def test_pending_capture_never_automatically_activates(self):
        self.assertEqual('PENDING_REVIEW',self.execute()['state'])
        with self.assertRaises(ValueError):self.wallet.start_request(self.id)
    def test_actual_signature_authentication_and_one_shot_consumption(self):
        self.activate();r=self.wallet.start_request(self.id)
        self.assertEqual('PENDING',self.wallet.consume_result(r['id'],r['secret'])['state'])
        self.assertEqual(r['code'],self.execute()['requests'][0]['code'])
        self.execute('approve',r['id']);result=self.wallet.consume_result(r['id'],r['secret'])
        self.assertEqual('AUTHENTICATED',result['state']);self.assertEqual('PRIVATE_PILOT',result['assurance'])
        with self.assertRaises(ValueError):self.wallet.consume_result(r['id'],r['secret'])
    def test_wrong_key_and_replay_fail(self):
        challenge=self.challenge()
        with self.assertRaises(ValueError):self.wallet.execute(self.signed(challenge,self.other))
        with self.assertRaises(ValueError):self.wallet.execute(self.signed(challenge))
    def test_changed_action_origin_request_and_details_fail(self):
        self.activate();r=self.wallet.start_request(self.id)
        for field in ['action','origin','requestId','credentialId','code','relyingParty','purpose']:
            c=self.challenge('approve',r['id']);p=json.loads(base64.b64decode(c['signingInput']));p[field]='attacker'
            with self.subTest(field=field),self.assertRaises(ValueError):
                self.wallet.execute(self.signed(c,payload=base64.b64encode(json.dumps(p).encode()).decode()))
    def test_expired_challenge_and_request_fail(self):
        self.activate();r=self.wallet.start_request(self.id);c=self.challenge('approve',r['id']);self.time+=61
        with self.assertRaises(ValueError):self.wallet.execute(self.signed(c))
        self.time+=60
        with self.assertRaises(ValueError):self.challenge('approve',r['id'])
    def test_revocation_between_challenge_and_approval_wins(self):
        self.activate();r=self.wallet.start_request(self.id);c=self.challenge('approve',r['id'])
        Wallet(self.db,'operator',clock=lambda:self.time).revoke(self.id)
        with self.assertRaises(ValueError):self.wallet.execute(self.signed(c))
        self.assertEqual('REVOKED',self.execute()['state'])
    def test_revocation_after_approval_prevents_login_and_reactivation(self):
        self.activate();r=self.wallet.start_request(self.id);self.execute('approve',r['id']);self.execute('revoke')
        with self.assertRaises(ValueError):self.wallet.consume_result(r['id'],r['secret'])
        with self.assertRaises(ValueError):self.wallet.activate(self.id,'REVIEW-revive-001')
    def test_rejection_is_terminal(self):
        self.activate();r=self.wallet.start_request(self.id);self.execute('reject',r['id'])
        with self.assertRaises(ValueError):self.challenge('approve',r['id'])
        with self.assertRaises(ValueError):self.wallet.consume_result(r['id'],r['secret'])
    def test_rp_secret_and_other_credential_cannot_claim_request(self):
        self.activate();r=self.wallet.start_request(self.id)
        other=self.wallet.enroll(self.other['publicKey'])['id'];self.wallet.activate(other,'REVIEW-private-002')
        with self.assertRaises(ValueError):self.challenge('approve',r['id'],ident=other)
        with self.assertRaises(ValueError):self.wallet.consume_result(r['id'],'x'*43)
    def test_concurrent_approvals_and_consumptions_succeed_only_once(self):
        self.activate();r=self.wallet.start_request(self.id)
        signed=[self.signed(self.challenge('approve',r['id'])) for _ in range(2)]
        def approve(value):
            try:self.wallet.execute(value);return True
            except ValueError:return False
        with ThreadPoolExecutor(2) as ex:self.assertEqual(1,sum(ex.map(approve,signed)))
        def consume(_):
            try:Wallet(self.db,'operator',clock=lambda:self.time).consume_result(r['id'],r['secret']);return True
            except ValueError:return False
        with ThreadPoolExecutor(2) as ex:self.assertEqual(1,sum(ex.map(consume,range(2))))
    def test_credential_expiry_and_stale_review_fail(self):
        self.activate();self.time+=86401
        self.assertEqual('EXPIRED',self.execute()['state'])
        with self.assertRaises(ValueError):self.wallet.start_request(self.id)
        other=self.wallet.enroll(self.other['publicKey'])['id'];self.time+=86401
        with self.assertRaises(ValueError):self.wallet.activate(other,'REVIEW-too-old-001')
    def test_restart_preserves_revocation_but_discards_challenges(self):
        c=self.challenge();self.wallet.revoke(self.id);self.wallet=Wallet(self.db,'https://localhost:8765',clock=lambda:self.time)
        with self.assertRaises(ValueError):self.wallet.execute(self.signed(c))
        self.assertEqual('REVOKED',self.execute()['state'])
    def test_duplicate_key_bad_key_and_unsafe_directory_fail(self):
        with self.assertRaises(ValueError):self.wallet.enroll(self.key['publicKey'])
        with self.assertRaises(ValueError):self.wallet.enroll('YQ==')
        public=Path(self.tmp.name)/'public';public.mkdir(mode=0o755)
        with self.assertRaises(ValueError):Wallet(public/'wallet.sqlite','https://localhost')
    def test_bounded_requests_and_challenges(self):
        self.activate()
        for _ in range(5):self.wallet.start_request(self.id)
        with self.assertRaises(ValueError):self.wallet.start_request(self.id)
        for _ in range(128):self.challenge()
        with self.assertRaises(ValueError):self.challenge()
        self.time+=121;self.assertIn('id',self.challenge());self.wallet.start_request(self.id)
    def test_attested_device_key_enrolls_only_after_all_checks(self):
        attest=Mock();attest.check.side_effect=lambda op,**kw: {'publicKey':'attested key'} if op=='attestation' else {'signCount':1}
        matcher=Mock();matcher.compare.return_value=0.95;matcher.decode_face.return_value=('image','face')
        pad=Mock();pad.score.return_value=0.95
        from test_identity import document
        session=NativeSessions(attest,lambda _:document(),matcher,pad,wallet=self.wallet)
        def finish():
            start=session.start();registered=session.register({'id':start['id'],'keyId':'key','attestation':'test'})
            payload={k:v for k,v in registered.items() if k!='frameCount'}
            payload.update(sod='YQ==',dg1='YQ==',dg2='YQ==',frames=['YQ==','Yg==','Yw=='],chipAuthentication=True,devicePublicKey=self.other['publicKey'])
            return session.finish({'id':start['id'],'payload':base64.b64encode(json.dumps(payload).encode()).decode(),'assertion':'test'})
        pad.score.return_value=0.1;self.assertIsNone(finish()['credential'])
        pad.score.return_value=0.95;r=finish()
        self.assertEqual('PENDING_REVIEW',r['credential']['state']);self.assertFalse(r['issuanceEnabled'])
    def test_malformed_and_unknown_actions_rejected(self):
        for r in [{}, {'credentialId':self.id,'action':'activate','requestId':None}, {'credentialId':self.id,'action':'snapshot','requestId':'a'*64}]:
            with self.assertRaises(ValueError):self.wallet.challenge(r)
        c=self.challenge()
        with self.assertRaises(ValueError):self.wallet.execute({'challengeId':c['id'],'signature':'not base64'})
        with self.assertRaises(ValueError):self.wallet.execute(self.signed(c))

class WalletHTTPTests(unittest.TestCase):
    def setUp(self):
        import threading
        from http.server import HTTPServer
        from server import handler
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.http=HTTPServer(('127.0.0.1',0),handler(Mock(),[],0))
        self.port=self.http.server_port;self.origin=f'http://localhost:{self.port}';self.token='t'*43
        self.wallet=Wallet(Path(self.temp.name)/'wallet.sqlite',self.origin)
        self.key=json.loads(crypt(op='new'));self.id=self.wallet.enroll(self.key['publicKey'])['id']
        self.http.RequestHandlerClass=handler(Mock(),[],self.port,origin=self.origin,token=self.token,browser_enabled=False,wallet=self.wallet)
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):self.http.shutdown();self.http.server_close();self.thread.join()
    def call(self,path,body,headers=None,method='POST'):
        import http.client
        c=http.client.HTTPConnection('127.0.0.1',self.port,timeout=3)
        try:
            h={'Host':f'localhost:{self.port}','Origin':self.origin,'X-CSRF-Token':self.token,'Content-Type':'application/json'}
            h.update(headers or {})
            c.request(method,path,body if isinstance(body,str) else json.dumps(body),h)
            r=c.getresponse();return r.status,json.loads(r.read())
        finally:c.close()
    def test_signed_status_over_real_http_and_no_remote_activation(self):
        code,c=self.call('/wallet/challenge',{'credentialId':self.id,'action':'snapshot','requestId':None})
        self.assertEqual(200,code)
        signature=crypt(op='sign',key=self.key['privateKey'],payload=c['signingInput'])
        code,result=self.call('/wallet/execute',{'challengeId':c['id'],'signature':signature})
        self.assertEqual(200,code);self.assertEqual('PENDING_REVIEW',result['state'])
        for path in ['/wallet/activate','/wallet/enroll','/rp/start','/session']:
            self.assertEqual(404,self.call(path,{},method='GET' if path=='/session' else 'POST')[0])
    def test_http_origin_host_pairing_size_duplicate_fields_and_no_unsigned_action(self):
        body={'credentialId':self.id,'action':'snapshot','requestId':None}
        for h in [{'Origin':'https://evil.invalid'},{'Host':'evil.invalid'},{'X-CSRF-Token':'wrong'}]:
            self.assertEqual(403,self.call('/wallet/challenge',body,h)[0])
        self.assertEqual(413,self.call('/wallet/challenge','x'*16385)[0])
        self.assertEqual(400,self.call('/wallet/challenge','{"action":"approve","action":"snapshot"}')[0])
        self.assertEqual(400,self.call('/wallet/execute',{'approved':True})[0])

if __name__=='__main__':unittest.main()
