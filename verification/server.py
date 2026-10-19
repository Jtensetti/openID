import argparse
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
import ssl
import ipaddress
from urllib.parse import urlsplit
import subprocess
import sqlite3
from face import FaceMatcher, FaceRejected

ROOT = Path(__file__).parent
MAX_BODY = 6_000_000

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result

def verify_document(command, request):
    payload = {key: request[key] for key in ('sod', 'dg1', 'dg2')}
    # Fixed executable/JAR/trust store chosen by the operator; never taken from an HTTP request.
    result = subprocess.run(command, input=json.dumps(payload).encode(), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=20, check=False)
    if result.returncode != 0:
        raise ValueError('passport verification failed')
    document = json.loads(result.stdout)
    if document.get('passiveAuthentication') is not True:
        raise ValueError('passport verification failed')
    return base64.b64decode(document['portrait'], validate=True)

def handler(matcher, command, port, native=None, origin=None, token=None, browser_enabled=True, pad=None, wallet=None):
    origin = origin or f'http://localhost:{port}'
    token = token or secrets.token_urlsafe(32)
    authority = urlsplit(origin).netloc
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, code, content, mime='application/json'):
            data = content if isinstance(content, bytes) else json.dumps(content).encode()
            self.send_response(code)
            for key, value in {
                'Content-Type': mime, 'Content-Length': str(len(data)), 'Cache-Control': 'no-store',
                'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' blob:; media-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
                'Permissions-Policy': 'camera=(self), microphone=(), geolocation=()',
                'Cross-Origin-Resource-Policy': 'same-origin',
            }.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)

        def boundary(self):
            return (self.headers.get('Host') == authority and
                    not self.headers.get('Forwarded') and not self.headers.get('X-Forwarded-Host'))

        def do_GET(self):
            if not self.boundary():
                return self.respond(403, {'error': 'DENIED'})
            if not browser_enabled:
                return self.respond(404, {'error': 'NOT_FOUND'})
            if self.path == '/session':
                return self.respond(200, {'token': token, 'issuanceEnabled': False})
            files = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript'), '/style.css': ('style.css', 'text/css')}
            if self.path not in files:
                return self.respond(404, {'error': 'NOT_FOUND'})
            name, mime = files[self.path]
            self.respond(200, (ROOT / 'web' / name).read_bytes(), mime)

        def do_POST(self):
            if (not self.boundary() or self.headers.get('Origin') != origin or
                    not secrets.compare_digest(self.headers.get('X-CSRF-Token', ''), token)):
                return self.respond(403, {'error': 'DENIED'})
            native_route = self.path in {'/native/start', '/native/attest', '/native/finish'}
            wallet_route = self.path in {'/wallet/challenge', '/wallet/execute'}
            if self.path != '/verify' and not (native_route and native is not None) and not (wallet_route and wallet is not None):
                return self.respond(404, {'error': 'NOT_FOUND'})
            if self.headers.get('Content-Type') != 'application/json' or self.headers.get('Transfer-Encoding'):
                return self.respond(415, {'error': 'CONTENT_TYPE'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= (16384 if wallet_route else 14_000_000 if native_route else MAX_BODY):
                    return self.respond(413, {'error': 'SIZE_LIMIT'})
                self.connection.settimeout(15)
                data = self.rfile.read(length)
                request = json.loads(data, object_pairs_hook=unique_object)
                if wallet_route:
                    result = wallet.challenge(request) if self.path == '/wallet/challenge' else wallet.execute(request)
                    return self.respond(200, result)
                if native_route:
                    if not isinstance(request, dict):raise ValueError('fields')
                    if self.path == '/native/start':
                        if request:raise ValueError('fields')
                        result = native.start()
                    elif self.path == '/native/attest': result = native.register(request)
                    else: result = native.finish(request)
                    return self.respond(200, result)
                if not browser_enabled: return self.respond(404, {'error':'NOT_FOUND'})
                if not isinstance(request, dict) or set(request) != {'sod', 'dg1', 'dg2', 'camera'}:
                    raise ValueError('invalid fields')
                for field, limit in [('sod',65536),('dg1',4096),('dg2',2_000_000),('camera',2_000_000)]:
                    value = base64.b64decode(request[field], validate=True)
                    if not 0 < len(value) <= limit:
                        raise ValueError('invalid input')
                portrait = verify_document(command, request)
                score = matcher.compare(portrait, base64.b64decode(request['camera'], validate=True))
                pad_score = None
                if pad is not None:
                    image, face = matcher.decode_face(base64.b64decode(request['camera'], validate=True))
                    pad_score = pad.score(image,face)
                return self.respond(200, {'passiveAuthentication': True, 'faceCosineSimilarity': score, 'padLiveScore':pad_score,
                    'faceDecision': 'NOT_CALIBRATED', 'liveness': 'RGB_PAD_SCORE_ONLY' if pad is not None else 'NOT_PERFORMED',
                    'chipAuthentication': 'NOT_PERFORMED', 'revocation': 'NOT_CHECKED',
                    'identityVerified': False, 'issuanceEnabled': False})
            except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError, sqlite3.Error, FaceRejected):
                return self.respond(400, {'error': 'Kontrollen kunde inte slutföras. Kontrollera chipfiler, tillitsankare och att båda bilderna innehåller exakt ett tydligt ansikte.'})
    return Handler

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--csca', required=True, type=Path, help='Operator-provisioned trusted CSCA PEM bundle')
    parser.add_argument('--java', default='java')
    parser.add_argument('--jar', type=Path, default=ROOT.parent / 'prototype/target/isolated-eid-lab.jar')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--team')
    parser.add_argument('--bundle', default='se.openid.PassportCapture')
    parser.add_argument('--development-attestation', action='store_true')
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--origin')
    parser.add_argument('--tls-cert', type=Path)
    parser.add_argument('--tls-key', type=Path)
    parser.add_argument('--wallet-db', type=Path, help='Enable private pilot credentials in a private 0700 directory')
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535 or not args.csca.is_file() or not args.jar.is_file():
        parser.error('A valid trust bundle, built JAR and unprivileged port are required')
    matcher = FaceMatcher(ROOT / 'models')
    command = [args.java, '-Xmx128m', '-jar', str(args.jar.resolve()), 'verify-passport', str(args.csca.resolve())]
    from pad import PresentationAttackDetector
    pad=PresentationAttackDetector(ROOT/'models')
    origin=args.origin or f'http://localhost:{args.port}'
    wallet=None
    if args.wallet_db:
        if not args.native:parser.error('--wallet-db requires --native')
        from wallet import Wallet
        wallet=Wallet(args.wallet_db,origin)
    native = None
    if args.native:
        if not args.team or len(args.team)!=10:parser.error('--team requires an Apple Team ID')
        from native import AppAttest, NativeSessions
        from pad import PresentationAttackDetector
        native=NativeSessions(AppAttest(args.team,args.bundle,args.development_attestation),
            lambda data: verify_document(command,data),matcher,pad,wallet=wallet)
    address=ipaddress.ip_address(args.bind)
    remote=not address.is_loopback
    if address.is_unspecified or not address.is_private:parser.error('Only explicit private-network or loopback addresses are allowed')
    if remote and (not args.native or not args.origin or not args.tls_cert or not args.tls_key):
        parser.error('Private-network native mode requires --native, --origin, --tls-cert and --tls-key')
    origin=args.origin or f'http://localhost:{args.port}'
    if args.origin and (urlsplit(origin).scheme!='https' or urlsplit(origin).path not in ('','/') or not args.tls_cert or not args.tls_key):
        parser.error('An explicit origin requires HTTPS and a TLS certificate/key')
    pairing=secrets.token_urlsafe(32)
    # OpenCV's stateful detector requires serial requests.
    with HTTPServer((args.bind, args.port), handler(matcher, command, args.port,native,origin,pairing,not remote,pad,wallet)) as server:
        if args.tls_cert:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(args.tls_cert,args.tls_key);server.socket=context.wrap_socket(server.socket,server_side=True)
        print(f'Verification workbench: {origin} — issuance disabled', flush=True)
        if args.native:print('One-process pairing code (keep private): '+pairing,flush=True)
        server.serve_forever()

if __name__ == '__main__':
    main()
