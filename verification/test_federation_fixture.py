"""CI-only device double: real signed passport and ECDSA, mocked camera/App Attest/PAD."""
import base64
import json
import os
from pathlib import Path
import sys
import time
import signal
from contextlib import ExitStack
from unittest.mock import Mock
from federation import FederationServer
from native import NativeSessions
from test_chip_fixture import ChipFixture, capture_ready, fixture_order, pose_matcher
from server import verify_document
from test_wallet import crypt
from wallet import Wallet

def main():
    directory = Path(sys.argv[1])
    resources = ExitStack()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        run(directory, resources)
    finally:
        resources.close()


def run(directory, resources):
    offset = 0; shared = None
    if os.environ.get('OPENID_TEST_POSTGRES'):
        from test_federation_postgres import FederationPostgres
        shared = FederationPostgres(directory, 'https://localhost:8765')
        resources.callback(shared.close)
        wallet, enroller, bridge_wallet = shared.wallet, shared.enroller, shared.bridge_wallet
    else:
        wallet = enroller = bridge_wallet = Wallet(directory/'wallet.sqlite', 'https://localhost:8765', clock=lambda:time.time()+offset)
    bridge = FederationServer(directory/'bridge.sock', bridge_wallet)
    def close_bridge():
        nonlocal bridge
        if bridge is not None:
            bridge.close()
            bridge = None
    resources.callback(close_bridge)
    fixture = Path(os.environ['PROOFING_FIXTURES'])
    jar = Path(__file__).resolve().parent.parent/'prototype/target/isolated-eid-lab.jar'
    command = [os.environ['PROOFING_JAVA'], '-jar', str(jar), 'verify-passport', str(fixture/'csca.der')]
    attest = Mock(); attest.check.side_effect = lambda op,**kw: {'publicKey':'test double'} if op == 'attestation' else {'signCount':kw['signCount']+1}
    matcher = pose_matcher(Mock()); matcher.compare.return_value = 0.95
    pad = Mock(); pad.score.return_value = 0.95
    native = NativeSessions(attest, lambda data:verify_document(command, data), matcher, pad, wallet=enroller, chip_factory=ChipFixture, pose_order=fixture_order)
    resources.callback(native.close)
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
                    payload.update(dg14='YQ==', devicePublicKey=key['publicKey'])
                    payload = capture_ready(native, capture, payload)
                    result = native.finish({'id':start['id'], 'payload':base64.b64encode(json.dumps(payload).encode()).decode(), 'assertion':'fixture'})
                    ident = result['credential']['id']
                    if shared: shared.activate(ident)
                    else: wallet.activate(ident, 'TEST-federation-001')
                    result = {'credentialId':ident}
                elif op == 'advance':
                    if shared:
                        if data['seconds'] > 0: shared.expire_pending()
                    else: offset += data['seconds']
                    result = {'advanced':True}
                elif op == 'stop-bridge': close_bridge(); result = {'stopped':True}
                else:
                    challenge = wallet.challenge({'credentialId':ident, 'action':op, 'requestId':data.get('requestId')})
                    result = wallet.execute({'challengeId':challenge['id'], 'signature':crypt(op='sign', key=key['privateKey'], payload=challenge['signingInput'])})
                print(json.dumps({'result':result}), flush=True)
            except Exception as error: print(json.dumps({'error':type(error).__name__}), flush=True)
    finally:
        close_bridge()

if __name__ == '__main__': main()
