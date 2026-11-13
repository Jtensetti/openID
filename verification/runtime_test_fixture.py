"""Disposable protocol-test credentials, never copied into the release image.

Uses the actual runtime entrypoints and role-separated files with synthetic data.
The ingress is a test relay, not the deployed nginx or a federation connection.
"""
import http.client
import http.server
import json
import os
import secrets
import shutil
import ssl
import subprocess
import threading


class RuntimeFixture:
    def __init__(self, root, *, api_host=None):
        self.root = root.resolve()
        self.idp = self.root / 'idp-keys'
        self.sp = self.root / 'sp-keys'
        self.state = self.root / 'metadata-state'
        for path in (self.idp, self.sp, self.state):
            path.mkdir(mode=0o700)
        self.passwords = {}
        for name, alias in (('idp-tls', 'tls'), ('sp-tls', 'tls'), ('idp', 'idp'), ('sp', 'sp'), ('encryption', 'encryption')):
            password = secrets.token_urlsafe(32)
            self.passwords[name] = password
            command = ['keytool', '-genkeypair', '-alias', alias, '-keyalg', 'RSA', '-keysize', '3072',
                       '-sigalg', 'SHA256withRSA', '-validity', '2', '-dname', 'CN=Generated-runtime-protocol-' + name,
                       '-storetype', 'PKCS12', '-keystore', str(self.root / (name + '.p12')),
                       '-storepass:env', 'OPENID_FIXTURE_PASSWORD', '-keypass:env', 'OPENID_FIXTURE_PASSWORD']
            if alias == 'tls': command += ['-ext', 'SAN=DNS:localhost,IP:127.0.0.1', '-ext', 'EKU=serverAuth']
            self.run(command, password=password)
            self.run(['keytool', '-exportcert', '-rfc', '-alias', alias, '-keystore', str(self.root / (name + '.p12')),
                      '-storepass:env', 'OPENID_FIXTURE_PASSWORD', '-file', str(self.root / (name + '.crt'))], password=password)
        for directory, aliases in ((self.idp, ('idp-tls', 'idp', 'encryption')), (self.sp, ('sp-tls', 'sp'))):
            for name in aliases:
                alias = 'tls' if name.endswith('-tls') else name
                shutil.copyfile(self.root / (name + '.p12'), directory / (alias + '.p12'))
                (directory / (alias + '.password')).write_text(self.passwords[name])
        shutil.copyfile(self.root / 'sp.crt', self.idp / 'sp.crt')
        shutil.copyfile(self.root / 'idp.crt', self.sp / 'idp.crt')
        shutil.copyfile(self.root / 'encryption.crt', self.sp / 'idp-encryption.crt')
        (self.idp / 'subject-secret').write_text(secrets.token_urlsafe(32))
        for directory in (self.idp, self.sp):
            for path in directory.iterdir(): path.chmod(0o600)
        self.origins = self.root / 'origins.json'
        self.origins.write_text(json.dumps({'idp': 'https://idp.example.test', 'sp': 'https://sp.example.test'}))
        self.federation = self.root / 'federation.json'
        self.federation.write_text(json.dumps({'version': 1, 'profile': 'private'}))
        self.origins.chmod(0o644)
        self.federation.chmod(0o644)
        self.run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '1', '-subj', '/CN=idp.example.test',
                  '-addext', 'subjectAltName=DNS:idp.example.test,DNS:sp.example.test'+('' if api_host is None else ',DNS:'+api_host),
                  '-keyout', str(self.root / 'ingress.key'), '-out', str(self.root / 'ingress.crt')])
        self.trust_password = secrets.token_urlsafe(32)
        self.run(['keytool', '-importcert', '-noprompt', '-alias', 'ingress', '-file', str(self.root / 'ingress.crt'),
                  '-keystore', str(self.root / 'trust.p12'), '-storetype', 'PKCS12',
                  '-storepass:env', 'OPENID_FIXTURE_PASSWORD'], password=self.trust_password)
        self.upstream_tls = {host: ssl.create_default_context(cafile=str(self.root / (role + '-tls.crt')))
                             for host, role in (('idp.example.test', 'idp'), ('sp.example.test', 'sp'))}
        self.public_tls = ssl.create_default_context(cafile=str(self.root / 'ingress.crt'))

    @staticmethod
    def run(command, *, password=None):
        # keytool's launcher consumes any -J argument before parsing keytool
        # options, including a randomly generated password passed as a value.
        # Keep the password out of argv and supply it to this child only.
        env = None if password is None else dict(os.environ, OPENID_FIXTURE_PASSWORD=password)
        try:
            result = subprocess.run(command, capture_output=True, timeout=60, env=env)
        except subprocess.TimeoutExpired:
            raise RuntimeError('Fixture tool timed out: ' + command[0]) from None
        if result.returncode:
            raise RuntimeError('Fixture tool failed: ' + command[0] + ' (exit ' + str(result.returncode) + ')')

    def command(self, role, jar, socket):
        command = ['java', '-Xmx256m', '-Djavax.net.ssl.trustStore=' + str(self.root / 'trust.p12'),
                   '-Djavax.net.ssl.trustStorePassword=' + self.trust_password, '-jar', jar, 'runtime-' + role,
                   str(self.idp if role == 'idp' else self.sp), str(socket), str(self.origins), str(self.federation)]
        if role == 'idp': command.append(str(self.state))
        return command

    def private_pem(self, alias):
        path = self.root / (alias + '.pem')
        self.run(['openssl', 'pkcs12', '-in', str(self.root / (alias + '.p12')), '-passin', 'pass:' + self.passwords[alias],
                  '-nodes', '-nocerts', '-out', str(path)])
        path.chmod(0o600)
        return path

    def ingress(self, handler=None):
        fixture = self
        if handler is None:
            class Relay(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_): pass
                def do_GET(self): self.forward()
                def do_POST(self): self.forward()
                def forward(self):
                    host = self.headers.get('Host')
                    port = {'idp.example.test': 9443, 'sp.example.test': 9444}.get(host)
                    if port is None:
                        self.send_error(400)
                        return
                    connection = http.client.HTTPSConnection('127.0.0.1', port, context=fixture.upstream_tls[host], timeout=20)
                    body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                    headers = {key: value for key, value in self.headers.items() if key.lower() not in ('connection', 'accept-encoding')}
                    try:
                        connection.request(self.command, self.path, body=body, headers=headers)
                        response = connection.getresponse()
                        data = response.read()
                        self.send_response(response.status)
                        for key, value in response.getheaders():
                            if key.lower() not in ('transfer-encoding', 'connection', 'content-length'): self.send_header(key, value)
                        self.send_header('Content-Length', str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                    except ConnectionRefusedError: self.send_error(503)
                    finally: connection.close()
            handler = Relay
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 443), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.root / 'ingress.crt', self.root / 'ingress.key')
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server
