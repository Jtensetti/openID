"""One-shot native capture binding. App Attest validation is delegated to the pinned library."""
import base64
import json
from pathlib import Path
import secrets
import subprocess
import time

def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate field')
        result[key]=value
    return result

class AppAttest:
    def __init__(self,team,bundle,development=False):
        self.config={'teamIdentifier':team,'bundleIdentifier':bundle,'allowDevelopmentEnvironment':development}
    def check(self,operation,**data):
        result=subprocess.run(['node',str(Path(__file__).parent/'attest.mjs')],
            input=json.dumps({**data,**self.config,'operation':operation}).encode(),
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,check=False)
        if result.returncode!=0:raise ValueError('App Attest rejected')
        return json.loads(result.stdout)

class NativeSessions:
    def __init__(self,attest,passport,matcher,pad,clock=time.monotonic,wallet=None):
        self.attest,self.passport,self.matcher,self.pad,self.clock=attest,passport,matcher,pad,clock
        self.wallet=wallet
        self.pending={}
    def start(self):
        self.pending={k:v for k,v in self.pending.items() if v['expires']>self.clock()}
        if len(self.pending)>=16:raise ValueError('too many sessions')
        ident=secrets.token_urlsafe(32);challenge=secrets.token_urlsafe(32)
        self.pending[ident]={'challenge':challenge,'expires':self.clock()+300,'phase':'attestation'}
        return {'id':ident,'challenge':challenge}
    def current(self,ident,phase):
        value=self.pending.get(ident)
        if value is None or value['expires']<=self.clock() or value['phase']!=phase:
            self.pending.pop(ident,None);raise ValueError('session rejected')
        return value
    def register(self,request):
        if set(request)!={'id','keyId','attestation'}:raise ValueError('fields')
        ident=request['id'];pending=self.current(ident,'attestation')
        self.pending.pop(ident) # Consume on all validation failures.
        if not isinstance(request['attestation'],str) or len(request['attestation'])>50000:raise ValueError('size')
        result=self.attest.check('attestation',attestation=request['attestation'],keyId=request['keyId'],challenge=pending['challenge'])
        pending.update({'phase':'capture','publicKey':result['publicKey'],'nonce':secrets.token_urlsafe(32)})
        self.pending[ident]=pending
        return {'id':ident,'nonce':pending['nonce'],'frameCount':3}
    def finish(self,request):
        if set(request)!={'id','payload','assertion'}:raise ValueError('fields')
        ident=request['id'];pending=self.current(ident,'capture');self.pending.pop(ident)
        raw=base64.b64decode(request['payload'],validate=True)
        if len(raw)>10_000_000 or not isinstance(request['assertion'],str) or len(request['assertion'])>10000:raise ValueError('size')
        # Verify the EXACT bytes before parsing them; no JSON reserialization discrepancy.
        checked=self.attest.check('assertion',assertion=request['assertion'],payload=request['payload'],publicKey=pending['publicKey'],signCount=0)
        if checked['signCount']<=0:raise ValueError('counter')
        data=json.loads(raw,object_pairs_hook=unique_object)
        expected={'id','nonce','sod','dg1','dg2','frames','chipAuthentication'}
        if 'devicePublicKey' in data:
            expected.add('devicePublicKey')
            if self.wallet is None:raise ValueError('wallet not configured')
        if set(data)!=expected or data['id']!=ident or data['nonce']!=pending['nonce']:
            raise ValueError('capture binding')
        if data['chipAuthentication'] is not True:raise ValueError('chip authentication required')
        if not isinstance(data['frames'],list) or len(data['frames'])!=3:raise ValueError('frames')
        for key,limit in [('sod',65536),('dg1',4096),('dg2',2_000_000)]:
            if not 0<len(base64.b64decode(data[key],validate=True))<=limit:raise ValueError('document size')
        frames=[base64.b64decode(frame,validate=True) for frame in data['frames']]
        if any(not 0<len(frame)<=2_000_000 for frame in frames):raise ValueError('frame size')
        if len(set(frames))!=3:raise ValueError('duplicate frames')
        portrait=self.passport(data)
        face_scores=[];pad_scores=[]
        for frame in frames:
            face_scores.append(self.matcher.compare(portrait,frame))
            image,face=self.matcher.decode_face(frame)
            pad_scores.append(self.pad.score(image,face))
        # Technical evaluation thresholds, NOT a calibrated issuance policy.
        passed=min(face_scores)>=0.5 and min(pad_scores)>=0.8
        credential=None
        if passed and 'devicePublicKey' in data:
            credential=self.wallet.enroll(data['devicePublicKey'])
        return {'checksPassed':passed,'passiveAuthentication':True,'appAttest':True,
            'chipAuthentication':'ATTESTED_NATIVE_RESULT','faceScores':face_scores,'padLiveScores':pad_scores,
            'policy':'EXPERIMENTAL_0.5_FACE_0.8_PAD','issuanceEnabled':False,'credential':credential}
