"""CI-only device double: real signed passport and ECDSA, mocked camera/App Attest/PAD."""
import base64
import json
import os
from pathlib import Path
import sys
import time
from unittest.mock import Mock
from federation import FederationServer
from native import NativeSessions
from server import verify_document
from test_wallet import crypt
from wallet import Wallet

def main():
    directory = Path(sys.argv[1]); offset = 0
    wallet = Wallet(directory/'wallet.sqlite', 'https://localhost:8765', clock=lambda:time.time()+offset)
    bridge = FederationServer(directory/'bridge.sock', wallet)
    fixture = Path(os.environ['PROOFING_FIXTURES'])
    jar = Path(__file__).resolve().parent.parent/'prototype/target/isolated-eid-lab.jar'
    command = [os.environ['PROOFING_JAVA'], '-jar', str(jar), 'verify-passport', str(fixture/'csca.der')]
    attest = Mock(); attest.check.side_effect = lambda op,**kw: {'publicKey':'test double'} if op == 'attestation' else {'signCount':1}
    matcher = Mock(); matcher.compare.return_value = 0.95; matcher.decode_face.return_value = ('image','face')
    pad = Mock(); pad.score.return_value = 0.95
    native = NativeSessions(attest, lambda data:verify_document(command, data), matcher, pad, wallet=wallet)
    key = ident = None
    print(json.dumps({'ready':True}), flush=True)
    try:
        for line in sys.stdin:
            try:
                data = json.loads(line); op = data['op']
                if op == 'new':
                    key = json.loads(crypt(op='new'))
                    start = native.start(); capture = native.register({'id':start['id'], 'keyId':'fixture', 'attestation':'fixture'})
                    payload = {k:v for k,v in capture.items() if k != 'frameCount'}
                    payload.update({k:base64.b64encode((fixture/(k+'.bin')).read_bytes()).decode() for k in ('sod','dg1','dg2')})
                    payload.update(chipAuthentication=True, frames=['YQ==','Yg==','Yw=='], devicePublicKey=key['publicKey'])
                    result = native.finish({'id':start['id'], 'payload':base64.b64encode(json.dumps(payload).encode()).decode(), 'assertion':'fixture'})
                    ident = result['credential']['id']; wallet.activate(ident, 'TEST-federation-001')
                    result = {'credentialId':ident}
                elif op == 'advance': offset += data['seconds']; result = {'advanced':True}
                elif op == 'stop-bridge': bridge.close(); bridge = None; result = {'stopped':True}
                else:
                    challenge = wallet.challenge({'credentialId':ident, 'action':op, 'requestId':data.get('requestId')})
                    result = wallet.execute({'challengeId':challenge['id'], 'signature':crypt(op='sign', key=key['privateKey'], payload=challenge['signingInput'])})
                print(json.dumps({'result':result}), flush=True)
            except Exception as error: print(json.dumps({'error':type(error).__name__}), flush=True)
    finally:
        if bridge: bridge.close()

if __name__ == '__main__': main()
