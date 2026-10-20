from concurrent.futures import ThreadPoolExecutor
import http.client
from http.server import HTTPServer
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from relying_party import COOKIE, MAX_SESSIONS, RelyingParty, Rejected, handler
from test_wallet import crypt
from wallet import Wallet


class RPFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = json.loads(crypt(op='new'))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.time = 1000
        self.wallet = Wallet(Path(self.tmp.name) / 'wallet.sqlite', 'https://localhost:8765', clock=lambda: self.time)
        self.credential = self.wallet.enroll(self.key['publicKey'])['id']
        self.wallet.activate(self.credential, 'TEST-review-001')
        self.rp = RelyingParty(self.wallet, clock=lambda: self.time)
        self.sid, data = self.rp.bootstrap(None); self.csrf = data['csrf']
        self.addCleanup(self.rp.close)

    def start(self):
        return self.rp.start(self.sid, self.csrf, self.credential)[1]['request']

    def device(self, action, request=None):
        challenge = self.wallet.challenge({'credentialId': self.credential, 'action': action, 'requestId': request})
        return self.wallet.execute({'challengeId': challenge['id'],
            'signature': crypt(op='sign', key=self.key['privateKey'], payload=challenge['signingInput'])})

    def authenticate(self):
        request = self.start(); self.device('approve', request['id'])
        self.sid, data = self.rp.poll(self.sid, self.csrf); self.csrf = data['csrf']
        self.assertEqual('AUTHENTICATED', data['state'])
        return data


class RelyingPartyTests(RPFixture):
    def test_signed_login_rotates_session_and_consumes_once(self):
        old_sid, old_csrf = self.sid, self.csrf
        request = self.start(); private = dict(self.rp.sessions[self.sid].request)
        self.assertEqual('PENDING', self.rp.poll(self.sid, self.csrf)[1]['state'])
        self.assertEqual(request['code'], self.device('snapshot')['requests'][0]['code'])
        self.device('approve', request['id'])
        sid, result = self.rp.poll(self.sid, self.csrf)
        self.assertNotEqual(old_sid, sid); self.assertNotEqual(old_csrf, result['csrf'])
        self.assertEqual('openid-local-demo', result['audience']); self.assertEqual('PRIVATE_PILOT', result['assurance'])
        self.assertEqual(result['subject'], self.rp.poll(sid, result['csrf'])[1]['subject'])
        with self.assertRaises(Rejected): self.rp.poll(old_sid, old_csrf)
        with self.assertRaises(ValueError): self.wallet.consume_result(private['id'], private['secret'])

    def test_other_browser_and_csrf_cannot_claim_result(self):
        request = self.start(); self.device('approve', request['id'])
        other, data = self.rp.bootstrap(None)
        self.assertEqual('READY', self.rp.poll(other, data['csrf'])[1]['state'])
        for sid, csrf in [(self.sid, data['csrf']), (other, self.csrf), (None, self.csrf), (self.sid, '')]:
            with self.subTest(sid=sid), self.assertRaises(Rejected): self.rp.poll(sid, csrf)
        with self.assertRaises(ValueError): self.wallet.consume_result(request['id'], request['id'])
        self.assertEqual('AUTHENTICATED', self.rp.poll(self.sid, self.csrf)[1]['state'])

    def test_qr_and_public_response_never_disclose_rp_secret(self):
        request = self.start(); secret = self.rp.sessions[self.sid].request['secret']
        response = json.dumps(self.rp.poll(self.sid, self.csrf)[1])
        self.assertNotIn(secret, response); self.assertNotIn('secret', response)
        self.assertEqual('openid://request/' + request['id'], request['link'])
        self.assertIn(b'<svg', self.rp.qr(self.sid)); self.assertNotIn(secret.encode(), self.rp.qr(self.sid))
        other, _ = self.rp.bootstrap(None)
        with self.assertRaises(Rejected): self.rp.qr(other)

    def test_logout_cancels_pending_request_and_old_challenge(self):
        request = self.start()
        challenge = self.wallet.challenge({'credentialId': self.credential, 'action': 'approve', 'requestId': request['id']})
        sid, data = self.rp.logout(self.sid, self.csrf)
        self.assertEqual('READY', data['state']); self.assertNotEqual(sid, self.sid)
        with self.assertRaises(ValueError): self.wallet.execute({'challengeId': challenge['id'],
            'signature': crypt(op='sign', key=self.key['privateKey'], payload=challenge['signingInput'])})
        with self.assertRaises(Rejected): self.rp.poll(self.sid, self.csrf)

    def test_logout_cancels_approved_unconsumed_request(self):
        request = self.start(); private = dict(self.rp.sessions[self.sid].request)
        self.device('approve', request['id']); self.rp.logout(self.sid, self.csrf)
        with self.assertRaises(ValueError): self.wallet.consume_result(private['id'], private['secret'])

    def test_cancel_requires_secret_and_is_idempotent(self):
        request = self.start(); private = dict(self.rp.sessions[self.sid].request)
        with self.assertRaises(ValueError): self.wallet.cancel_request(request['id'], 'x' * 43)
        self.wallet.cancel_request(request['id'], private['secret'])
        self.wallet.cancel_request(request['id'], private['secret'])
        events = self.device('snapshot')['events']
        self.assertEqual(1, sum(e['kind'] == 'CANCELLED' for e in events))
        self.assertEqual('UNAVAILABLE', self.rp.poll(self.sid, self.csrf)[1]['state'])

    def test_cancel_does_not_rewrite_consumed_request(self):
        self.start(); private = dict(self.rp.sessions[self.sid].request)
        self.device('approve', private['id']); self.rp.poll(self.sid, self.csrf)
        self.wallet.cancel_request(private['id'], private['secret'])
        with self.wallet.transaction() as db:
            self.assertEqual('CONSUMED', db.execute('SELECT state FROM requests WHERE id=?', (private['id'],)).fetchone()[0])

    def test_rejection_and_expired_requests_remove_result_and_qr(self):
        request = self.start(); self.device('reject', request['id'])
        self.assertEqual('UNAVAILABLE', self.rp.poll(self.sid, self.csrf)[1]['state'])
        with self.assertRaises(Rejected): self.rp.qr(self.sid)
        self.start(); self.time += 121
        with self.assertRaises(Rejected): self.rp.qr(self.sid)
        self.assertEqual('UNAVAILABLE', self.rp.poll(self.sid, self.csrf)[1]['state'])

    def test_revocation_before_consumption_blocks_login(self):
        request = self.start(); self.device('approve', request['id']); self.device('revoke')
        data = self.rp.poll(self.sid, self.csrf)[1]
        self.assertEqual('UNAVAILABLE', data['state']); self.assertNotIn('subject', data)

    def test_revocation_after_login_invalidates_next_protected_read(self):
        self.authenticate()
        # Revoke through another connection to detect stale in-memory state.
        Wallet(self.wallet.path, 'operator', clock=lambda: self.time).revoke(self.credential)
        data = self.rp.poll(self.sid, self.csrf)[1]
        self.assertEqual('UNAVAILABLE', data['state']); self.assertNotIn('subject', data)
        self.assertIsNone(self.rp.sessions[self.sid].credential)

    def test_credential_expiry_bounds_session(self):
        self.time += 86380
        self.sid, session = self.rp.bootstrap(None); self.csrf = session['csrf']
        data = self.authenticate()
        self.assertEqual(87400, data['expiresAt'])
        self.time += 21
        with self.assertRaises(Rejected): self.rp.poll(self.sid, self.csrf)

    def test_subject_binding_and_database_failure_fail_closed(self):
        self.authenticate(); self.rp.sessions[self.sid].subject = '0' * 64
        self.assertEqual('UNAVAILABLE', self.rp.poll(self.sid, self.csrf)[1]['state'])
        self.sid, data = self.rp.logout(self.sid, self.csrf); self.csrf = data['csrf']
        self.authenticate()
        with patch.object(self.wallet, 'check_session', side_effect=sqlite3.OperationalError('offline')):
            data = self.rp.poll(self.sid, self.csrf)[1]
        self.assertEqual('UNAVAILABLE', data['state']); self.assertNotIn('subject', data)

    def test_restart_and_absolute_session_expiry_forget_authority(self):
        self.authenticate(); fresh = RelyingParty(self.wallet, clock=lambda: self.time)
        with self.assertRaises(Rejected): fresh.poll(self.sid, self.csrf)
        self.time += 601
        with self.assertRaises(Rejected): self.rp.poll(self.sid, self.csrf)
        sid, _ = self.rp.bootstrap(self.sid); self.assertNotEqual(self.sid, sid)

    def test_concurrent_polls_only_one_can_rotate_old_session(self):
        request = self.start(); self.device('approve', request['id'])
        def attempt(_):
            try: return self.rp.poll(self.sid, self.csrf)[1]['state'] == 'AUTHENTICATED'
            except Rejected: return False
        with ThreadPoolExecutor(2) as pool: self.assertEqual(1, sum(pool.map(attempt, range(2))))

    def test_rate_capacity_and_fixed_browser_request(self):
        for _ in range(3):
            with self.assertRaises(ValueError): self.rp.start(self.sid, self.csrf, '0' * 64)
        with self.assertRaises(Rejected): self.start()
        self.time += 61; self.start()
        with self.assertRaises(Rejected): self.start()
        for _ in range(MAX_SESSIONS - 1): self.rp.bootstrap(None)
        with self.assertRaises(Rejected): self.rp.bootstrap(None)
        self.time += 601
        self.assertIsNotNone(self.rp.bootstrap(None)[0])


class HTTPTests(RPFixture):
    def setUp(self):
        super().setUp()
        self.server = HTTPServer(('127.0.0.1', 0), handler(self.rp, 0))
        self.port = self.server.server_port; self.origin = f'http://localhost:{self.port}'
        self.server.RequestHandlerClass = handler(self.rp, self.port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.addCleanup(self.shutdown)

    def shutdown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(2)

    def http(self, path, method='GET', body=None, override=None, extra=()):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode() if body is not None else b''
        headers = {'Host': f'localhost:{self.port}', 'Cookie': f'{COOKIE}={self.sid}',
            'Origin': self.origin, 'Content-Type': 'application/json', 'Content-Length': str(len(raw)), 'X-CSRF-Token': self.csrf}
        if override: headers.update(override)
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for key, value in [*headers.items(), *extra]:
            if value is not None: connection.putheader(key, value)
        connection.endheaders(raw)
        response = connection.getresponse(); result = response.status, dict(response.getheaders()), response.read()
        connection.close(); return result

    def test_http_login_and_security_headers(self):
        status, headers, raw = self.http('/session')
        self.assertEqual(200, status); self.assertEqual({'csrf'}, set(json.loads(raw)))
        for flag in ['HttpOnly', 'SameSite=Strict', 'Path=/', 'Max-Age=600']: self.assertIn(flag, headers['Set-Cookie'])
        self.assertEqual('no-store', headers['Cache-Control']); self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        status, _, raw = self.http('/login', 'POST', {'credentialId': self.credential})
        self.assertEqual(200, status); request = json.loads(raw)['request']
        self.device('approve', request['id'])
        status, headers, raw = self.http('/poll', 'POST', {})
        self.assertEqual(200, status); self.assertEqual('AUTHENTICATED', json.loads(raw)['state'])
        self.assertNotIn(self.sid, headers['Set-Cookie'])

    def test_wrong_host_origin_fetch_site_and_proxy_headers_rejected(self):
        for headers in [{'Host':'attacker.example'}, {'Host':f'127.0.0.1:{self.port}'}, {'Origin':'https://attacker.example'},
                {'Origin':None}, {'Origin':'null'}, {'Sec-Fetch-Site':'cross-site'}, {'Sec-Fetch-Site':'same-site'},
                {'Forwarded':''}, {'X-Forwarded-For':'127.0.0.1'}, {'X-Forwarded-Host':'localhost'}, {'X-Forwarded-Proto':'https'}]:
            with self.subTest(headers=headers): self.assertEqual(403, self.http('/poll', 'POST', {}, headers)[0])
        for field, value in [('Host',f'localhost:{self.port}'), ('Origin',self.origin)]:
            self.assertEqual(403, self.http('/poll', 'POST', {}, extra=[(field,value)])[0])

    def test_duplicate_headers_cookies_wrong_csrf_and_content_type(self):
        for extra in [[('X-CSRF-Token',self.csrf)], [('Cookie',f'{COOKIE}={self.sid}')]]:
            self.assertEqual(400, self.http('/poll', 'POST', {}, extra=extra)[0])
        for override in [{'X-CSRF-Token':'bad'}, {'X-CSRF-Token':None}, {'Cookie':f'{COOKIE}={self.sid}; {COOKIE}={self.sid}'}, {'Cookie':None}]:
            self.assertEqual(400, self.http('/poll', 'POST', {}, override)[0])
        for extra in [[('Content-Length','2')], [('Content-Type','application/json')], [('Transfer-Encoding','chunked')]]:
            self.assertEqual(415, self.http('/poll', 'POST', {}, extra=extra)[0])
        self.assertEqual(415, self.http('/poll', 'POST', {}, {'Content-Type':'text/plain'})[0])
        self.assertEqual(413, self.http('/poll', 'POST', {}, {'Content-Length':'1025'})[0])

    def test_route_and_input_allowlist_no_activation_or_arbitrary_callback(self):
        for path in ['/login','/activate','/admin','/../wallet.sqlite','/qr.svg?request=attacker','/?callback=https://attacker.example']:
            self.assertEqual(404, self.http(path)[0])
        for body in [{'credentialId':self.credential,'callback':'https://attacker.example'}, [], None, {'credentialId':None}]:
            self.assertIn(self.http('/login', 'POST', body)[0], (400,413))
        self.assertEqual(400, self.http('/poll', 'POST', {'requestId':'0'*64})[0])

    def test_duplicate_json_and_malformed_encoding_rejected(self):
        duplicate = ('{"credentialId":"' + self.credential + '","credentialId":"' + self.credential + '"}').encode()
        for raw in [duplicate, b'{', b'\xff', b'null', b'[]']:
            with self.subTest(raw=raw[:20]): self.assertEqual(400, self.http('/login', 'POST', raw)[0])


if __name__ == '__main__': unittest.main()
