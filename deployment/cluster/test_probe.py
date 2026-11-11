"""Actual TLS readiness checks; generated keys and loopback traffic only."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cert, self.key = self.certificate('server')
        self.status, self.body = 200, b'{"status":"READY"}'
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != '/health/ready' or self.headers.get('Host') != 'api.example.invalid':
                    self.send_response(404); self.end_headers(); return
                self.send_response(fixture.status); self.end_headers(); self.wfile.write(fixture.body)

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self.close)
        self.config = {'origin': 'https://api.example.invalid', 'bind': '127.0.0.1',
                       'port': self.server.server_port, 'trustedProxy': '127.0.0.1',
                       'tlsCert': str(self.cert)}

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.worker.join(3)

    def certificate(self, name):
        cert, key = self.root / (name + '.pem'), self.root / (name + '.key')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', str(key), '-out', str(cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return cert, key

    def probe(self):
        path = self.root / 'runtime.json'; path.write_text(json.dumps(self.config))
        return subprocess.run([sys.executable, str(Path(__file__).with_name('probe.py')), str(path)],
                              capture_output=True, timeout=8).returncode

    def test_local_ingress_tls_name_keeps_public_host_and_never_resolves_public_dns(self):
        self.assertEqual(0, self.probe())
        del self.config['trustedProxy']
        # The direct mode verifies its public TLS name, which this cert lacks.
        self.assertNotEqual(0, self.probe())

    def test_untrusted_backend_or_unready_response_is_rejected(self):
        other, _ = self.certificate('untrusted')
        self.config['tlsCert'] = str(other)
        self.assertNotEqual(0, self.probe())
        self.config['tlsCert'] = str(self.cert)
        for status, body in [(503, b'{"status":"READY"}'), (200, b'{"status":"SEALED"}'),
                             (200, b'{"status":"READY","extra":true}'), (200, b'x' * 4097)]:
            with self.subTest(status=status, body=body[:50]):
                self.status, self.body = status, body
                self.assertNotEqual(0, self.probe())


if __name__ == '__main__':
    unittest.main()
