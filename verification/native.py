import base64
import json
import math
from pathlib import Path
import secrets
import subprocess
import sys
import time

POSES=('front','right','left')
# Experimental pose limits in inter-eye distances (face.pose_ratio); calibration is pending like the score limits.
POSE_FRONT_MAX=0.12
POSE_SIDE_MIN=0.07
POSE_SPREAD_MIN=0.20

def random_pose_order():
    return secrets.SystemRandom().sample(POSES,3)

def check_poses(order,ratios,direction=False):
    """Server-side check of the requested head turns from landmark parallax, independent of the app's guide.

    The frontal frame must be frontal; the two turned frames must be turned clearly and to opposite sides.
    A flat photo or screen cannot produce this parallax. With direction=True the turn direction is also checked
    against the unmirrored-camera convention (right turn = negative ratio); enable after physical calibration.
    """
    if sorted(order)!=sorted(POSES) or len(ratios)!=3:return False
    if any(isinstance(r,bool) or not isinstance(r,(int,float)) or not math.isfinite(r) or abs(r)>2 for r in ratios):return False
    pose=dict(zip(order,ratios));front,right,left=pose['front'],pose['right'],pose['left']
    if abs(front)>POSE_FRONT_MAX:return False
    for side in (right,left):
        if abs(side)<max(POSE_SIDE_MIN,abs(front)+0.05):return False
    if right*left>=0 or abs(right-left)<POSE_SPREAD_MIN:return False
    return not direction or (right<0<left)

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
    def __init__(self,attest,passport,matcher,pad,clock=time.monotonic,wallet=None,chip_factory=None,biometrics=None,
                 pose_order=random_pose_order,pose_direction=False,pose_enforced=True):
        self.attest,self.passport,self.matcher,self.pad,self.clock=attest,passport,matcher,pad,clock
        self.wallet=wallet
        self.pose_order,self.pose_direction,self.pose_enforced=pose_order,pose_direction,pose_enforced
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
                # The app learns the head-turn order only now, after the chip check: frames prepared earlier
                # must match an order chosen by the server for this session.
                order=list(self.pose_order())
                if sorted(order)!=sorted(POSES):raise ValueError('pose order')
                pending.update(phase='capture',nonce=secrets.token_urlsafe(32),poses=order)
                return {'type':'verified','id':ident,'nonce':pending['nonce'],'frameCount':3,'poses':order}
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
        # Persistent per-document limit: a stolen passport cannot be used to tune attacks against the thresholds.
        limiter=getattr(self.wallet,'biometric_attempt',None) if self.wallet is not None else None
        if limiter is not None:limiter(document)
        face_scores=[];pad_scores=[];poses=[]
        if self.biometrics is not None:
            result=self.biometrics(portrait,frames)
            if len(result)!=3:raise ValueError('model result count')
            face_scores,pad_scores,poses=result
            if len(face_scores)!=3 or len(pad_scores)!=3 or len(poses)!=3:raise ValueError('model result count')
        else:
            for frame in frames:
                face_scores.append(self.matcher.compare(portrait,frame))
                image,face=self.matcher.decode_face(frame)
                pad_scores.append(self.pad.score(image,face))
                poses.append(self.matcher.pose_ratio(face))
        if any(not math.isfinite(score) or not -1 <= score <= 1 for score in face_scores) or any(
            not math.isfinite(score) or not 0 <= score <= 1 for score in pad_scores): raise ValueError('invalid model score')
        if any(isinstance(r,bool) or not isinstance(r,(int,float)) or not math.isfinite(r) for r in poses):raise ValueError('invalid pose')
        pose_passed=check_poses(pending['poses'],poses,self.pose_direction)
        if not self.pose_enforced:
            # Calibration mode: only the outcome is logged, never ratios, scores or images.
            print(json.dumps({'event':'pose_check','result':'PASSED' if pose_passed else 'FAILED'}),file=sys.stderr,flush=True)
        # Experimental thresholds; calibration is pending.
        passed=min(face_scores)>=0.5 and min(pad_scores)>=0.8 and (pose_passed or not self.pose_enforced)
        credential=None;remaining=None
        if not passed and limiter is not None:remaining=self.wallet.biometric_failure(document)
        if passed and pending['devicePublicKey'] is not None:
            credential=self.wallet.enroll(pending['devicePublicKey'], document)
        # No raw scores to the client: they would be an oracle for tuning a presentation or morphing attack.
        return {'checksPassed':passed,'passiveAuthentication':True,'appAttest':True,
            'chipAuthentication':'SERVER_VERIFIED_CA','poseCheck':'PASSED' if pose_passed else 'FAILED',
            'policy':'EXPERIMENTAL_0.5_FACE_0.8_PAD_POSE_V1','issuanceEnabled':False,'credential':credential,
            **({'attemptsRemaining':remaining} if remaining is not None else {})}
