"""Exercise the actual beta nginx config on loopback with generated TLS and a fake SP.

Requires the operator's nginx and OpenSSL. No pilot keys, account, DNS changes or
live ports are used. The installed nginx version is included in the result.
"""
import base64
import http.client
import http.server
import hashlib
import json
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
NGINX = shutil.which('nginx')
if not NGINX:
    raise SystemExit('nginx must be installed to exercise beta ingress')

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

cases = re.findall(r'new Case\("([a-z0-9-]+)"', (ROOT / 'prototype/src/main/java/lab/TestConsole.java').read_text())
assert 'loa3' in cases and 'sign-encrypted' in cases
with tempfile.TemporaryDirectory(prefix='openid-ingress-') as temporary:
    root = Path(temporary)
    # The nginx worker needs read access to these generated, disposable test files.
    root.chmod(0o755)
    cert, key = root / 'tls.crt', root / 'tls.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=Generated ingress test', '-addext',
        'subjectAltName=DNS:localhost,DNS:openid.tensetti.io,DNS:idp.openid.tensetti.io,DNS:api.openid.tensetti.io',
        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
    password = 'synthetic-ingress-only'
    hashed = subprocess.run(['openssl', 'passwd', '-apr1', '-stdin'], input=password + '\n',
        text=True, check=True, capture_output=True).stdout.strip()
    (root / 'users').write_text('test:' + hashed + '\n')
    (root / 'users').chmod(0o644)
    expected_location = 'https://idp.openid.tensetti.io/saml2/authn?SAMLRequest=' + 'x' * 6000

    class Upstream(http.server.BaseHTTPRequestHandler):
        def end_headers(self):
            # A conflicting backend policy must not create duplicate HSTS fields.
            self.send_header('Strict-Transport-Security', 'max-age=0')
            super().end_headers()
        def log_message(self, *args):
            pass
        def do_POST(self):
            data = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            body = json.dumps({'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                               'authorizationPresent': 'Authorization' in self.headers,
                               'clientAddresses': self.headers.get_all('X-OpenID-Client-IP'),
                               'forwardedPresent': 'Forwarded' in self.headers or 'X-Forwarded-For' in self.headers}).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def do_GET(self):
            if self.path == '/test/run/sign-encrypted':
                self.send_response(303)
                self.send_header('Location', expected_location)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            body = json.dumps({'path': self.path, 'authorizationPresent': 'Authorization' in self.headers}).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    upstream = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    upstream.socket = tls.wrap_socket(upstream.socket, server_side=True)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    public_port, http_port = port(), port()
    config = (ROOT / 'deployment/beta-nginx.conf').read_text()
    for old, new in {
        'listen 443 ssl': f'listen 127.0.0.1:{public_port} ssl',
        'listen 80 default_server': f'listen 127.0.0.1:{http_port} default_server',
        '/etc/letsencrypt/live/openid-beta/fullchain.pem': str(cert),
        '/etc/letsencrypt/live/openid-beta/privkey.pem': str(key),
        '/etc/nginx/openid-saml.crt': str(cert), '/etc/nginx/openid-api.crt': str(cert),
        '/etc/nginx/openid-beta.htpasswd': str(root / 'users'),
        '/var/log/nginx/openid-error.log': str(root / 'error.log'),
        '/var/www/openid-beta': str(root), '/var/www/openid-acme': str(root),
        '127.0.0.1:9444': '127.0.0.1:' + str(upstream.server_port),
        '127.0.0.1:9443': '127.0.0.1:' + str(upstream.server_port),
        '127.0.0.1:8767': '127.0.0.1:' + str(upstream.server_port),
    }.items():
        config = config.replace(old, new)
    configuration = root / 'nginx.conf'
    configuration.write_text('daemon off; master_process off; pid ' + str(root / 'nginx.pid')
        + '; error_log ' + str(root / 'error.log') + '; events {} http { access_log off;\n'
        # nginx -t/start can create/chown its temp directories, even without traffic.
        # Every path must belong to this disposable instance, never the host's nginx.
        + ''.join(f'{kind}_temp_path {root / kind};\n'
                  for kind in ['client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'])
        + config + '\n}')
    command = [NGINX, '-p', str(root), '-c', str(configuration)]
    subprocess.run([*command, '-t'], check=True, capture_output=True)
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    context = ssl.create_default_context(cafile=str(cert))

    def request(path, authenticated=True, body=None, host='openid.tensetti.io', extra_headers=None):
        # Connect only to loopback, while checking the generated certificate and correct SNI.
        connection = http.client.HTTPSConnection(host, public_port, timeout=5, context=context)
        connection.sock = context.wrap_socket(socket.create_connection(('127.0.0.1', public_port), timeout=5),
            server_hostname=host)
        try:
            headers = {'Host': host}
            if authenticated:
                headers['Authorization'] = 'Basic ' + base64.b64encode(('test:' + password).encode()).decode()
            if body is not None:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            headers.update(extra_headers or {})
            connection.request('GET' if body is None else 'POST', path, body=body, headers=headers)
            response = connection.getresponse()
            transport = [value for name, value in response.getheaders() if name.lower() == 'strict-transport-security']
            assert transport == ['max-age=31536000'], (host, path, response.status, transport)
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()
    try:
        for attempt in range(50):
            try:
                assert request('/test', False)[0] == 401
                break
            except ConnectionRefusedError:
                time.sleep(.05)
        else:
            raise AssertionError('nginx did not start')
        for case in cases:
            status, headers, body = request('/test/run/' + case)
            assert status == (303 if case == 'sign-encrypted' else 200), (case, status)
            if case == 'sign-encrypted':
                assert headers['Location'] == expected_location
            else:
                assert json.loads(body)['authorizationPresent'] is False
        for path in ['/test/run/loa3', '/test/run/sign-encrypted', '/oidc/login']:
            assert request(path, False)[0] == 401, path
        for path in ['/wallet', '/lab', '/test/run/UPPER', '/test/run/' + 'a' * 33, '/test/run/loa3/extra']:
            assert request(path)[0] == 404, path
        assert request('/oidc/login')[0] == 200
        assert request('/wallet', host='idp.openid.tensetti.io')[0] == 404
        assert request('/wallet', host='api.openid.tensetti.io')[0] == 404
        assert request('/wallet/challenge', host='api.openid.tensetti.io')[0] == 403
        assert request('/wallet/challenge', body=b'{}', host='api.openid.tensetti.io')[0] == 200
        for route in ('notice','consent','withdraw'):
            assert request('/native/'+route,authenticated=False,body=b'{}',host='api.openid.tensetti.io')[0] == 200
            assert request('/native/'+route+'/extra',authenticated=False,body=b'{}',host='api.openid.tensetti.io')[0] == 404
        # The API's dedicated header must replace attacker input with exactly the
        # actual socket peer. Ordinary Forwarded headers remain stripped.
        for spoof in ({}, {'X-OpenID-Client-IP':'198.51.100.9'},
                      {'X-OpenID-Client-IP':'198.51.100.9','x-openid-client-ip':'192.0.2.8'},
                      {'X-OpenID-Client-IP':'198.51.100.9,192.0.2.8','X-Forwarded-For':'192.0.2.8','Forwarded':'for=192.0.2.8'},
                      {'X_OpenID_Client_IP':'198.51.100.9'}):
            status, _, raw = request('/native/start',authenticated=False,body=b'{}',
                                    host='api.openid.tensetti.io',extra_headers=spoof)
            assert status == 200, status
            response=json.loads(raw)
            assert response['clientAddresses'] == ['127.0.0.1'], response
            assert response['forwardedPresent'] is False
        # Model an unavailable temp-file area: allowed SAML requests must fit in memory.
        body_temp = root / 'client_body'
        body_temp.rmdir()
        body_temp.write_text('No disk spooling in this test')
        for host, path in [('openid.tensetti.io', '/acs'), ('openid.tensetti.io', '/test/acs'),
                           ('openid.tensetti.io', '/sign/acs'), ('idp.openid.tensetti.io', '/phone/complete')]:
            for size in (64 * 1024, 128 * 1024):
                payload = b'SAMLResponse=' + b'x' * (size - len(b'SAMLResponse='))
                status, _, raw = request(path, body=payload, host=host)
                assert status == 200, (path, size, status)
                result = json.loads(raw)
                assert result['bytes'] == size and result['sha256'] == hashlib.sha256(payload).hexdigest()
                assert result['authorizationPresent'] is False
            assert request(path, authenticated=False, body=b'x' * 65536, host=host)[0] == 401
            assert request(path, body=b'x' * (128 * 1024 + 1), host=host)[0] == 413
        print(json.dumps({'status': 'PASS', 'consoleCases': len(cases), 'largeRedirectBytes': len(expected_location),
            'largePostBytes': [65536, 131072], 'postRoutes': 4, 'oversizePostDenied': True,
            'betaAuthEnforced': True, 'credentialsStripped': True, 'unexpectedRoutesDenied': True,
            'hstsAllResponses': True, 'duplicateUpstreamHstsRemoved': True, 'hstsHosts': 3,
            'ingressClientAddressOverwritten': True, 'spoofedClientAddressCases': 5,
            'nginx': subprocess.run([NGINX, '-v'], capture_output=True, text=True, check=True).stderr.strip()}))
    finally:
        process.terminate()
        process.communicate(timeout=10)
        upstream.shutdown()
