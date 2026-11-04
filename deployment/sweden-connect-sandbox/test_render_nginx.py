"""Run Render's nginx template unprivileged, using only generated loopback data."""
import hashlib
import http.client
import http.cookies
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time


def main():
    if os.geteuid() == 0:
        raise SystemExit('Run as an unprivileged user to test runtime permissions')
    nginx = shutil.which('nginx')
    if not nginx:
        raise SystemExit('nginx must be installed')
    template = Path(__file__).with_name('nginx.render.conf').read_text()
    with tempfile.TemporaryDirectory(prefix='tjipp-render-nginx-') as directory:
        root = Path(directory)
        runtime = root / 'runtime'
        runtime.mkdir(mode=0o700)
        cert, key = root / 'tls.crt', root / 'tls.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                        '-nodes', '-days', '1', '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', str(key), '-out', str(cert)],
                       check=True, capture_output=True)

        class Upstream(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header('Set-Cookie', '__Host-lab-idp=synthetic-session; Path=/; Secure; HttpOnly; SameSite=Strict')
                self.send_header('Set-Cookie', '__Host-lab-idp-other=synthetic-other; Path=/; Secure; HttpOnly; SameSite=Strict')
                self.send_header('Content-Length', '0')
                self.end_headers()

            def do_POST(self):
                payload = self.rfile.read(int(self.headers['Content-Length']))
                data = json.dumps({'bytes': len(payload),
                                   'sha256': hashlib.sha256(payload).hexdigest(),
                                   'authorization': self.headers.get('Authorization'),
                                   'forwarded': self.headers.get('Forwarded')}).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        upstream = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        upstream.socket = context.wrap_socket(upstream.socket, server_side=True)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        config = template
        # Only environment paths and listener addresses change; the template's
        # temp-path directives must themselves exist and create the directories.
        for old, new in {
            '0.0.0.0:@PORT@': f'127.0.0.1:{port}',
            '/tmp/tjipp-sandbox-nginx.pid': str(root / 'nginx.pid'),
            '/tmp/tjipp-sandbox/': str(runtime) + '/',
            '/srv/tjipp-sandbox/keys/tls.crt': str(cert),
            '127.0.0.1:9443': f'127.0.0.1:{upstream.server_port}',
            '/dev/stderr': str(root / 'error.log'),
        }.items():
            config = config.replace(old, new)
        config_path = root / 'nginx.conf'
        config_path.write_text(config)
        command = [nginx, '-p', str(root), '-c', str(config_path)]
        process = None

        def request(path, payload=None, with_headers=False):
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            try:
                connection.request('GET' if payload is None else 'POST', path,
                                   body=payload, headers={'Authorization': 'synthetic',
                                                         'Forwarded': 'for=192.0.2.1'})
                response = connection.getresponse()
                data = response.read()
                return (response.status, data, response.getheaders()) if with_headers else (response.status, data)
            finally:
                connection.close()

        try:
            subprocess.run([*command, '-t'], check=True, capture_output=True)
            for kind in ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'):
                assert (runtime / kind).is_dir(), kind
            process = subprocess.Popen([*command, '-g', 'daemon off;'],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            for _ in range(100):
                try:
                    assert request('/healthz')[0] == 200
                    break
                except ConnectionRefusedError:
                    time.sleep(0.05)
            else:
                raise AssertionError('nginx never became ready')
            # Larger than nginx's memory buffer: exercises actual body-temp writes.
            payload = b'SAMLRequest=' + b'x' * 65536
            status, data = request('/saml2/authn', payload)
            assert status == 200, (status, data)
            result = json.loads(data)
            assert result['bytes'] == len(payload)
            assert result['sha256'] == hashlib.sha256(payload).hexdigest()
            assert result['authorization'] is None and result['forwarded'] is None
            assert request('/saml2/authn', b'x' * (128 * 1024 + 1))[0] == 413
            for path in ('/', '/wallet', '/phone', '/actuator', '/lab/revoke'):
                assert request(path)[0] == 404, path
            status, _, headers = request('/lab', with_headers=True)
            assert status == 200
            cookies = http.cookies.SimpleCookie()
            for name, value in headers:
                if name.lower() == 'set-cookie':
                    cookies.load(value)
            session = cookies['__Host-lab-idp']
            assert session['samesite'].lower() == 'lax', 'external navigation needs Lax'
            assert session['secure'] and session['httponly']
            assert session['path'] == '/' and not session['domain']
            assert session.value == 'synthetic-session'
            assert cookies['__Host-lab-idp-other']['samesite'].lower() == 'strict'
            print(json.dumps({'status': 'PASS', 'unprivileged': True,
                              'tempDirectories': 5, 'bufferedPostBytes': len(payload),
                              'oversizedPostDenied': True, 'blockedRoutes': 5,
                              'upstreamTLSVerified': True, 'sensitiveHeadersStripped': True,
                              'idpCookieLaxSecureHttpOnlyHostOnly': True,
                              'unrelatedCookieUnchanged': True,
                              'nginxVersion': subprocess.check_output([nginx, '-v'], stderr=subprocess.STDOUT, text=True).strip(),
                              'configurationSha256': hashlib.sha256(template.encode()).hexdigest()}))
        finally:
            if process:
                process.terminate()
                process.communicate(timeout=10)
            upstream.shutdown()
            upstream.server_close()


if __name__ == '__main__':
    main()
