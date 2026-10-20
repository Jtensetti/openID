"""Real TLS/Gunicorn process checks. Generated certificates, no real identities."""
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent


def main():
    with tempfile.TemporaryDirectory(prefix='openid-runtime-') as directory:
        root = Path(directory)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost',
            '-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        os.chmod(key,0o600)
        pairing = root/'pairing'; pairing.write_text('x'*43); os.chmod(pairing,0o600)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); port = sock.getsockname()[1]
        origin = f'https://localhost:{port}'
        config = {'bind':'127.0.0.1','origin':origin,'team':'ABCDEFGHIJ','bundle':'se.openid.PassportCapture',
            'developmentAttestation':True,'tlsCert':str(cert),'tlsKey':str(key),'csca':str(cert),
            'database':str(root/'data'/'wallet.sqlite'),'pairingFile':str(pairing)}
        path = root/'config.json'; path.write_text(json.dumps(config))
        from wallet import Wallet
        from test_wallet import crypt
        from test_identity import document
        wallet = Wallet(Path(config['database']), origin)
        device = json.loads(crypt(op='new'))
        ident = wallet.enroll(device['publicKey'], document())['id']
        wallet.activate(ident, 'TEST-PRIVATE-REVIEW')
        context = ssl.create_default_context(cafile=str(cert))
        def request(route='/health/ready',method='GET',body=None,headers=None):
            connection = http.client.HTTPSConnection('localhost',port,timeout=5,context=context)
            try:
                connection.request(method,route,body,headers or {})
                response = connection.getresponse()
                return response.status,response.read()
            finally: connection.close()
        with (root/'server.log').open('w+') as log:
            process = subprocess.Popen([sys.executable,str(ROOT/'serve.py'),'--config',str(path)],
                stdout=log,stderr=log,start_new_session=True)
            try:
                deadline=time.monotonic()+60
                while True:
                    if process.poll() is not None: raise AssertionError('Runtime failed to start')
                    try:
                        if request()[0]==200:break
                    except OSError:pass
                    if time.monotonic()>deadline:raise AssertionError('Runtime readiness deadline')
                    time.sleep(0.1)
                assert request('/session')[0]==403
                assert request('/metrics')[0]==403
                assert request('/health/ready?enable=true')[0]==403
                assert request('/health/ready',headers={'Host':'attacker.invalid'})[0]==403
                headers={'Origin':origin,'X-CSRF-Token':'x'*43,'Content-Type':'application/json'}
                assert request('/native/start','POST','{}',headers)[0]==200
                assert request('/native/start','POST','{"x":NaN}',headers)[0]==400
                assert request('/wallet/challenge','POST','{}',headers)[0]==400
                def signed_operation(action, request_id=None):
                    code, raw = request('/wallet/challenge','POST',json.dumps({'credentialId':ident,'action':action,'requestId':request_id}),headers)
                    assert code==200
                    challenge=json.loads(raw)
                    signature=crypt(op='sign',key=device['privateKey'],payload=challenge['signingInput'])
                    message=json.dumps({'challengeId':challenge['id'],'signature':signature})
                    code, raw=request('/wallet/execute','POST',message,headers)
                    assert code==200
                    assert request('/wallet/execute','POST',message,headers)[0]==400
                    return json.loads(raw)
                assert signed_operation('snapshot')['identity']['displayName']=='ALICE SYNTHETIC'
                login=wallet.start_request(ident)
                signed_operation('approve', login['id'])
                assert wallet.consume_result(login['id'],login['secret'])['state']=='AUTHENTICATED'
                assert signed_operation('revoke')['state']=='REVOKED'
                assert signed_operation('snapshot')['identity'] is None
                # A client which stops sending a request body must not monopolize health checks.
                slow=context.wrap_socket(socket.create_connection(('localhost',port)),server_hostname='localhost')
                slow.sendall((f'POST /native/finish HTTP/1.1\r\nHost: localhost:{port}\r\nOrigin: {origin}\r\n'
                    f'X-CSRF-Token: {"x"*43}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{{').encode())
                time.sleep(0.2)
                assert request()[0]==200
                assert request('/native/finish','POST','{}',headers)[0]==503
                slow.close()
                start=time.monotonic()
                with concurrent.futures.ThreadPoolExecutor(16) as pool:
                    results=list(pool.map(lambda _: request('/health/live')[0],range(160)))
                assert all(code==200 for code in results)
                elapsed=time.monotonic()-start
                print(json.dumps({'probe':'tls-health-concurrency','requests':160,'concurrency':16,
                    'seconds':round(elapsed,3),'errors':0}))
                assert request('/metrics',headers={'X-CSRF-Token':'x'*43})[0]==200
                # Existing SQLite files are required; readiness must never recreate one.
                Path(config['database']).unlink()
                assert request()[0]==503
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=65)==0
                log.seek(0); output=log.read()
                assert 'x'*43 not in output
                assert '"x":NaN' not in output
                assert 'ALICE' not in output
                assert ident not in output
                print('PASS: TLS, boundary, bounded admission, health, database loss, private logs and graceful shutdown')
            except BaseException:
                log.seek(0)
                # Only generated data is used in this test process.
                print(log.read(),file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    os.killpg(process.pid,signal.SIGTERM)
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()


if __name__=='__main__':main()
