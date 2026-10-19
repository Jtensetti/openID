"""Local browser test service. Uses the pilot wallet; no identity issuance or federation.

Browser sessions and RP consumption secrets remain in this process. Only the
opaque request ID crosses the QR boundary. Local HTTP is restricted to loopback.
"""
import argparse
from dataclasses import dataclass, field
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time

import qrcode
from qrcode.image.svg import SvgPathImage
from wallet import Wallet, RP_NAME, PURPOSE, identifier

ROOT = Path(__file__).parent
COOKIE = 'openid_local_rp'
SESSION_SECONDS = 600
MAX_SESSIONS = 64


@dataclass
class BrowserSession:
    csrf: str
    expires: float
    state: str = 'READY'
    credential: str | None = None
    request: dict | None = None
    subject: str | None = None
    starts: list = field(default_factory=list)


class Rejected(ValueError):
    pass


class RelyingParty:
    def __init__(self, wallet, clock=time.time):
        self.wallet, self.clock = wallet, clock
        self.sessions = {}
        self.lock = threading.RLock()

    def _cancel(self, session):
        if session.request:
            try: self.wallet.cancel_request(session.request['id'], session.request['secret'])
            except (ValueError, OSError, sqlite3.Error): pass
        # Even if the database is unavailable, forgetting the RP secret prevents consumption.
        session.request = None
        session.subject = None
        session.credential = None

    def _prune(self):
        for sid, session in list(self.sessions.items()):
            if session.expires <= self.clock():
                self._cancel(session)
                del self.sessions[sid]

    def _new(self):
        if len(self.sessions) >= MAX_SESSIONS: raise Rejected('capacity')
        sid = secrets.token_hex(32)
        session = BrowserSession(secrets.token_hex(32), self.clock() + SESSION_SECONDS)
        self.sessions[sid] = session
        return sid, session

    def bootstrap(self, sid):
        with self.lock:
            self._prune()
            if sid not in self.sessions: sid, session = self._new()
            else: session = self.sessions[sid]
            return sid, {'csrf': session.csrf}

    def _session(self, sid, csrf):
        self._prune()
        session = self.sessions.get(sid)
        if (session is None or not isinstance(csrf, str) or
                not re.fullmatch('[a-f0-9]{64}', csrf) or not secrets.compare_digest(session.csrf, csrf)):
            raise Rejected('session')
        return session

    def _view(self, session):
        result = {'state': session.state, 'csrf': session.csrf, 'serverTime': self.clock(),
                  'expiresAt': session.expires, 'relyingParty': RP_NAME, 'purpose': PURPOSE}
        if session.state == 'PENDING':
            request = session.request
            result['request'] = {'id': request['id'], 'code': request['code'],
                                 'expiresAt': request['expiresAt'], 'link': 'openid://request/' + request['id']}
        if session.state == 'AUTHENTICATED':
            result.update(subject=session.subject, audience='openid-local-demo', assurance='PRIVATE_PILOT')
        return result

    def start(self, sid, csrf, credential):
        with self.lock:
            session = self._session(sid, csrf)
            if session.state not in ('READY', 'UNAVAILABLE'): raise Rejected('pending or authenticated')
            session.starts = [at for at in session.starts if at > self.clock() - 60]
            if len(session.starts) >= 3: raise Rejected('rate')
            session.starts.append(self.clock())
            credential = identifier(credential)
            request = self.wallet.start_request(credential)
            session.credential, session.request, session.state = credential, request, 'PENDING'
            return sid, self._view(session)

    def poll(self, sid, csrf):
        with self.lock:
            session = self._session(sid, csrf)
            try:
                if session.state == 'PENDING':
                    request = session.request
                    result = self.wallet.consume_result(request['id'], request['secret'])
                    if result['state'] == 'AUTHENTICATED':
                        # Drop the pre-login session and CSRF token before exposing a result.
                        del self.sessions[sid]
                        sid = secrets.token_hex(32)
                        session.csrf = secrets.token_hex(32)
                        session.state, session.subject, session.request = 'AUTHENTICATED', result['subject'], None
                        self.sessions[sid] = session
                if session.state == 'AUTHENTICATED':
                    # Includes the first authenticated response and bounds the UI timer.
                    expiry = self.wallet.check_session(session.credential, session.subject)
                    session.expires = min(session.expires, expiry)
            except (ValueError, OSError, sqlite3.Error):
                self._cancel(session)
                session.state = 'UNAVAILABLE'
            return sid, self._view(session)

    def logout(self, sid, csrf):
        with self.lock:
            session = self._session(sid, csrf)
            self._cancel(session)
            del self.sessions[sid]
            sid, session = self._new()
            return sid, self._view(session)

    def qr(self, sid):
        with self.lock:
            self._prune()
            session = self.sessions.get(sid)
            if session is None or session.state != 'PENDING' or session.request['expiresAt'] <= self.clock():
                raise Rejected('no live request')
            link = 'openid://request/' + session.request['id']
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=4)
            qr.add_data(link)
            qr.make(fit=True)
            return qr.make_image(image_factory=SvgPathImage).to_string()

    def close(self):
        with self.lock:
            for session in self.sessions.values(): self._cancel(session)
            self.sessions.clear()


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise Rejected('duplicate field')
        result[key] = value
    return result


def handler(rp, port):
    authority = f'localhost:{port}'
    origin = 'http://' + authority
    class Handler(BaseHTTPRequestHandler):
        server_version = 'openID-local-test'
        sys_version = ''

        def log_message(self, *args): pass

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def respond(self, status, value, mime='application/json', sid=None):
            data = value if isinstance(value, bytes) else json.dumps(value).encode()
            self.send_response(status)
            headers = {'Content-Type': mime, 'Content-Length': str(len(data)), 'Cache-Control': 'no-store',
                'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
                'Cross-Origin-Resource-Policy': 'same-origin', 'Cross-Origin-Opener-Policy': 'same-origin',
                'Permissions-Policy': 'camera=(), microphone=(), geolocation=()', 'Connection': 'close'}
            if sid: headers['Set-Cookie'] = f'{COOKIE}={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}'
            for key, value in headers.items(): self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)

        def boundary(self):
            return (self.client_address[0] == '127.0.0.1' and self.headers.get_all('Host') == [authority] and
                    self.headers.get('Sec-Fetch-Site') in (None, 'same-origin', 'none') and
                    all(name not in self.headers for name in ('Forwarded', 'X-Forwarded-Host', 'X-Forwarded-For', 'X-Forwarded-Proto')))

        def sid(self):
            values = self.headers.get_all('Cookie') or []
            if not values: return None
            if len(values) != 1 or len(values[0]) > 4096: raise Rejected('cookie')
            if sum(part.strip().split('=', 1)[0] == COOKIE for part in values[0].split(';')) > 1: raise Rejected('cookie')
            cookie = SimpleCookie(); cookie.load(values[0])
            value = cookie[COOKIE].value if COOKIE in cookie else None
            return value if value and re.fullmatch('[a-f0-9]{64}', value) else None

        def do_GET(self):
            if not self.boundary(): return self.respond(403, {'error': 'DENIED'})
            try:
                if self.path == '/session':
                    sid, data = rp.bootstrap(self.sid())
                    return self.respond(200, data, sid=sid)
                if self.path == '/qr.svg': return self.respond(200, rp.qr(self.sid()), 'image/svg+xml')
                files = {'/': ('index.html', 'text/html; charset=utf-8'),
                         '/rp.js': ('rp.js', 'text/javascript; charset=utf-8'), '/rp.css': ('rp.css', 'text/css; charset=utf-8')}
                if self.path not in files: return self.respond(404, {'error': 'NOT_FOUND'})
                filename, mime = files[self.path]
                return self.respond(200, (ROOT / 'rp_web' / filename).read_bytes(), mime)
            except (ValueError, CookieError, OSError, sqlite3.Error): return self.respond(403, {'error': 'DENIED'})

        def do_POST(self):
            if not self.boundary() or self.headers.get_all('Origin') != [origin]:
                return self.respond(403, {'error': 'DENIED'})
            if self.path not in ('/login', '/poll', '/logout'): return self.respond(404, {'error': 'NOT_FOUND'})
            if (self.headers.get_all('Content-Type') != ['application/json'] or 'Transfer-Encoding' in self.headers or
                    len(self.headers.get_all('Content-Length') or []) != 1):
                return self.respond(415, {'error': 'CONTENT_TYPE'})
            try:
                length = int(self.headers['Content-Length'])
                if not 0 < length <= 1024: return self.respond(413, {'error': 'SIZE_LIMIT'})
                raw = self.rfile.read(length)
                if len(raw) != length: raise Rejected('length')
                data = json.loads(raw, object_pairs_hook=unique_fields)
                if not isinstance(data, dict) or set(data) != ({'credentialId'} if self.path == '/login' else set()):
                    raise Rejected('fields')
                csrf = self.headers.get_all('X-CSRF-Token') or []
                if len(csrf) != 1: raise Rejected('csrf')
                sid = self.sid()
                if self.path == '/login': result_sid, result = rp.start(sid, csrf[0], data['credentialId'])
                elif self.path == '/logout': result_sid, result = rp.logout(sid, csrf[0])
                else: result_sid, result = rp.poll(sid, csrf[0])
                return self.respond(200, result, sid=result_sid if result_sid != sid else None)
            except (ValueError, TypeError, CookieError, OSError, sqlite3.Error):
                return self.respond(400, {'error': 'Inloggningen kunde inte slutföras. Kontrollera registreringsreferens och aktuell status i appen.'})
    return Handler


def main():
    parser = argparse.ArgumentParser(description='openID local browser test service; loopback only')
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--port', type=int, default=8766)
    args = parser.parse_args()
    if not args.db.is_file() or not 1024 <= args.port <= 65535: parser.error('Existing wallet database and unprivileged port required')
    rp = RelyingParty(Wallet(args.db, 'local-relying-party'))
    try:
        with HTTPServer(('127.0.0.1', args.port), handler(rp, args.port)) as server:
            print(f'openID local test service: http://localhost:{args.port}', flush=True)
            server.serve_forever()
    except KeyboardInterrupt: pass
    finally: rp.close()


if __name__ == '__main__': main()
