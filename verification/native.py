import base64
import json
import math
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
    def __init__(self,attest,passport,matcher,pad,clock=time.monotonic,wallet=None,chip_factory=None,biometrics=None):
        self.attest,self.passport,self.matcher,self.pad,self.clock=attest,passport,matcher,pad,clock
        self.wallet=wallet
        self.biometrics=biometrics
        self.chip_factory=chip_factory
        self.pending={}
    def start(self):
        for ident in list(self.pending):
            if self.pending[ident]['expires']<=self.clock(): self.discard(ident)
        if len(self.pending)>=16:raise ValueError('too many sessions')
        ident=secrets.token_urlsafe(32);challenge=secrets.token_urlsafe(32)
        self.pending[ident]={'challenge':challenge,'expires':self.clock()+300,'phase':'attestation'}
        return {'id':ident,'challenge':challenge}
    def discard(self,ident):
        value=self.pending.pop(ident,None)
        if value and 'chip' in value:value['chip'].close()
    def close(self):
        for ident in list(self.pending):self.discard(ident)
    def current(self,ident,phase):
        if not isinstance(ident,str):raise ValueError('session rejected')
        value=self.pending.get(ident)
        if value is None or value['expires']<=self.clock() or value['phase']!=phase:
            self.discard(ident);raise ValueError('session rejected')
        return value
    def register(self,request):
        if set(request)!={'id','keyId','attestation'}:raise ValueError('fields')
        ident=request['id'];pending=self.current(ident,'attestation')
        self.pending.pop(ident) # Consume on all validation failures.
        if not isinstance(request['attestation'],str) or len(request['attestation'])>50000:raise ValueError('size')
        result=self.attest.check('attestation',attestation=request['attestation'],keyId=request['keyId'],challenge=pending['challenge'])
        pending.update({'phase':'document','publicKey':result['publicKey'],'nonce':secrets.token_urlsafe(32),'signCount':0})
        self.pending[ident]=pending
        return {'id':ident,'nonce':pending['nonce']}
    def signed(self,request,pending,limit):
        raw=base64.b64decode(request['payload'],validate=True)
        if len(raw)>limit or not isinstance(request['assertion'],str) or len(request['assertion'])>10000:raise ValueError('size')
        checked=self.attest.check('assertion',assertion=request['assertion'],payload=request['payload'],
            publicKey=pending['publicKey'],signCount=pending['signCount'])
        if type(checked['signCount']) is not int or checked['signCount']<=pending['signCount']:raise ValueError('counter')
        pending['signCount']=checked['signCount']
        data=json.loads(raw,object_pairs_hook=unique_object)
        if not isinstance(data,dict) or data.get('id')!=request['id'] or data.get('nonce')!=pending['nonce']:
            raise ValueError('capture binding')
        return data
    def begin_chip(self,request):
        if set(request)!={'id','payload','assertion'}:raise ValueError('fields')
        ident=request['id'];pending=self.current(ident,'document');self.pending.pop(ident)
        if self.chip_factory is None:raise ValueError('server chip authentication required')
        data=self.signed(request,pending,3_000_000)
        expected={'id','nonce','sod','dg1','dg2','dg14'}
        if 'devicePublicKey' in data:
            expected.add('devicePublicKey')
            if self.wallet is None:raise ValueError('wallet not configured')
        if set(data)!=expected:raise ValueError('fields')
        for key,limit in [('sod',65536),('dg1',4096),('dg2',2_000_000),('dg14',16384)]:
            if not 0<len(base64.b64decode(data[key],validate=True))<=limit:raise ValueError('document size')
        document=self.passport(data)
        chip=self.chip_factory(data)
        try:
            result=chip.next()
            if result.get('type')!='command':raise ValueError('chip exchange required')
            pending.update(phase='chip',document=document,devicePublicKey=data.get('devicePublicKey'),
                chip=chip,chipToken=secrets.token_urlsafe(32),chipExpires=self.clock()+75,sequence=result['sequence'])
            self.pending[ident]=pending
            return {**result,'id':ident,'chipToken':pending['chipToken']}
        except BaseException:
            chip.close()
            raise
    def chip_step(self,request):
        if set(request)!={'id','chipToken','sequence','response'}:raise ValueError('fields')
        ident=request['id'];pending=self.current(ident,'chip')
        try:
            if (not isinstance(request['chipToken'],str) or not secrets.compare_digest(request['chipToken'],pending['chipToken'])
                    or pending['chipExpires']<=self.clock() or type(request['sequence']) is not int
                    or request['sequence']!=pending['sequence']):raise ValueError('chip binding')
            if not isinstance(request['response'],str) or len(request['response'])>5464:raise ValueError('chip response')
            result=pending['chip'].next(request['response'],request['sequence'])
            if result.get('type')=='verified':
                pending.pop('chip').close()
                pending.update(phase='capture',nonce=secrets.token_urlsafe(32))
                return {'type':'verified','id':ident,'nonce':pending['nonce'],'frameCount':3}
            pending['sequence']=result['sequence']
            return result
        except BaseException:
            self.discard(ident)
            raise
    def cancel(self,request):
        if set(request)!={'id','chipToken'}:raise ValueError('fields')
        ident=request['id'];pending=self.pending.get(ident) if isinstance(ident,str) else None
        if (pending is None or not isinstance(request['chipToken'],str)
                or not secrets.compare_digest(request['chipToken'],pending.get('chipToken',''))):raise ValueError('chip binding')
        self.discard(ident)
        return {'cancelled':True}
    def finish(self,request):
        if set(request)!={'id','payload','assertion'}:raise ValueError('fields')
        ident=request['id'];pending=self.current(ident,'capture');self.pending.pop(ident)
        data=self.signed(request,pending,10_000_000)
        if set(data)!={'id','nonce','frames'}:raise ValueError('fields')
        if not isinstance(data['frames'],list) or len(data['frames'])!=3:raise ValueError('frames')
        frames=[base64.b64decode(frame,validate=True) for frame in data['frames']]
        if any(not 0<len(frame)<=2_000_000 for frame in frames):raise ValueError('frame size')
        if len(set(frames))!=3:raise ValueError('duplicate frames')
        document=pending['document']
        portrait=document.portrait
        face_scores=[];pad_scores=[]
        if self.biometrics is not None:
            face_scores,pad_scores=self.biometrics(portrait,frames)
            if len(face_scores)!=3 or len(pad_scores)!=3:raise ValueError('model result count')
        else:
            for frame in frames:
                face_scores.append(self.matcher.compare(portrait,frame))
                image,face=self.matcher.decode_face(frame)
                pad_scores.append(self.pad.score(image,face))
        if any(not math.isfinite(score) or not -1 <= score <= 1 for score in face_scores) or any(
            not math.isfinite(score) or not 0 <= score <= 1 for score in pad_scores): raise ValueError('invalid model score')
        # Experimental thresholds; calibration is pending.
        passed=min(face_scores)>=0.5 and min(pad_scores)>=0.8
        credential=None
        if passed and pending['devicePublicKey'] is not None:
            credential=self.wallet.enroll(pending['devicePublicKey'], document)
        return {'checksPassed':passed,'passiveAuthentication':True,'appAttest':True,
            'chipAuthentication':'SERVER_VERIFIED_CA','faceScores':face_scores,'padLiveScores':pad_scores,
            'policy':'EXPERIMENTAL_0.5_FACE_0.8_PAD','issuanceEnabled':False,'credential':credential}
