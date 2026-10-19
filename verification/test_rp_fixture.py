"""Browser-test subprocess. Control channel is stdin, never an HTTP route.

Creates a disposable private database and OpenSSL test key. It cannot open an
operator database or approve a real enrollment. No passport or biometric input.
"""
from http.server import HTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import time

from relying_party import RelyingParty, handler
from test_wallet import crypt
from wallet import Wallet


def main():
    offset = 0
    clock = lambda: time.time() + offset
    with tempfile.TemporaryDirectory(prefix='openid-rp-test-') as directory:
        wallet = Wallet(Path(directory) / 'wallet.sqlite', 'https://localhost:8765', clock=clock)
        rp = RelyingParty(wallet, clock=clock)
        server = HTTPServer(('127.0.0.1', 0), handler(rp, 0))
        server.RequestHandlerClass = handler(rp, server.server_port)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        print(json.dumps({'origin': f'http://localhost:{server.server_port}'}), flush=True)
        key = ident = None
        try:
            for line in sys.stdin:
                try:
                    command = json.loads(line)
                    if command['op'] == 'new':
                        key = json.loads(crypt(op='new'))
                        ident = wallet.enroll(key['publicKey'])['id']
                        wallet.activate(ident, 'TEST-browser-fixture')
                        result = {'credentialId': ident}
                    elif command['op'] == 'advance':
                        offset += command['seconds']; result = {'advanced': True}
                    else:
                        challenge = wallet.challenge({'credentialId': ident, 'action': command['op'], 'requestId': command.get('requestId')})
                        result = wallet.execute({'challengeId': challenge['id'],
                            'signature': crypt(op='sign', key=key['privateKey'], payload=challenge['signingInput'])})
                    print(json.dumps({'result': result}), flush=True)
                except Exception as error:
                    print(json.dumps({'error': type(error).__name__}), flush=True)
        finally:
            server.shutdown(); server.server_close(); thread.join(2); rp.close()


if __name__ == '__main__': main()
