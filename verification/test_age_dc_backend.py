import concurrent.futures
import io
import json
from pathlib import Path
import secrets
import subprocess
import threading
import unittest

from age_dc_backend import MdocDcBackend
from age_gateway import AgeError, AgeGateway, Sites
from age_http import AgeApplication
from test_age_gateway import KEY_A, KEY_B, site


def holder(value):
    # Only synthetic credentials cross this private test pipe.
    result = subprocess.run(['node', str(Path(__file__).with_name('age_wallet') / 'interop-fixture.mjs')],
                            input=json.dumps(value).encode(), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=10, check=True)
    return json.loads(result.stdout)


class MdocIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adult = holder({'operation': 'fixture', 'ageOver18': True})
        cls.minor = holder({'operation': 'fixture', 'ageOver18': False})

    def setUp(self):
        self.backend = MdocDcBackend(self.adult['pem'])
        self.gateway = AgeGateway(Sites([site('a', KEY_A), site('b', KEY_B)]), self.backend)
        self.app = AgeApplication(self.gateway, 'age.internal')

    def http(self, path, value, key=KEY_A):
        body = json.dumps(value).encode()
        env = {'REQUEST_METHOD': 'POST', 'PATH_INFO': path, 'QUERY_STRING': '',
               'HTTP_HOST': 'age.internal', 'wsgi.url_scheme': 'https', 'CONTENT_TYPE': 'application/json',
               'CONTENT_LENGTH': str(len(body)), 'HTTP_AUTHORIZATION': 'Bearer ' + key, 'wsgi.input': io.BytesIO(body)}
        status = []
        data = b''.join(self.app(env, lambda code, headers: status.append(code)))
        return status[0], json.loads(data)

    def start(self, ident='a', key=KEY_A):
        status, session = self.http('/age/start', {'siteId': ident, 'origin': f'https://{ident}.example', 'method': 'dc_api'}, key)
        self.assertEqual(status, '200 OK')
        self.assertEqual(set(session['presentation']), {'method', 'requests'})
        return session, {'siteId': ident, 'id': session['id'], 'binding': session['binding']}

    def present(self, session, origin='https://a.example', fixture=None):
        return holder({'operation': 'present', **(fixture or self.adult),
                       'request': session['presentation']['requests'][0]['data'],
                       'browserOrigin': origin, 'approvedOrigin': origin})

    def test_http_real_crypto_two_sites_and_one_use(self):
        for ident, key in [('a', KEY_A), ('b', KEY_B)]:
            session, args = self.start(ident, key)
            proof = self.present(session, f'https://{ident}.example')
            self.assertEqual(('200 OK', {'state': 'VERIFIED'}), self.http('/age/complete', args | {'credential': proof}, key))
            other = 'b' if ident == 'a' else 'a'
            self.assertEqual('400 Bad Request', self.http('/age/consume', args | {'siteId': other}, KEY_B if other == 'b' else KEY_A)[0])
            self.assertEqual(('200 OK', {'age_over_18': True}), self.http('/age/consume', args, key))
            self.assertEqual('400 Bad Request', self.http('/age/consume', args, key)[0])
            self.assertEqual('400 Bad Request', self.http('/age/complete', args | {'credential': proof}, key)[0])

    def test_wrong_browser_origin_session_and_fake_verdict_fail_closed(self):
        first, _ = self.start()
        other_session_proof = self.present(first)
        for proof_factory in [lambda s: self.present(s, 'https://b.example'),
                              lambda s: other_session_proof, lambda s: {'age_over_18': True}]:
            session, args = self.start()
            self.assertEqual(('200 OK', {'state': 'FAILED'}), self.http('/age/complete', args | {'credential': proof_factory(session)}))
            self.assertEqual('400 Bad Request', self.http('/age/consume', args)[0])

    def test_signed_false_is_denied_and_unknown_signer_fails(self):
        for trust_minor, expected in [(False, 'FAILED'), (True, 'DENIED')]:
            if trust_minor:
                self.backend = MdocDcBackend(self.minor['pem'])
                self.gateway.backend = self.backend
            session, args = self.start()
            self.assertEqual(('200 OK', {'state': expected}), self.http('/age/complete', args | {'credential': self.present(session, fixture=self.minor)}))
            self.assertEqual('400 Bad Request', self.http('/age/consume', args)[0])

    def test_concurrent_crypto_completion_runs_once(self):
        nonce = secrets.token_urlsafe(32)
        tx = self.backend.dc_begin('https://a.example', nonce)
        proof = self.present({'presentation': {'requests': tx['requests']}})
        barrier = threading.Barrier(2)

        def complete():
            barrier.wait()
            try:
                return self.backend.dc_complete(tx['backend_id'], nonce, proof)
            except AgeError:
                return False
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            self.assertEqual([False, True], sorted(pool.map(lambda _: complete(), range(2))))

    def test_expiry_invalid_nonce_and_capacity(self):
        clock = [0]
        backend = MdocDcBackend(self.adult['pem'], clock=lambda: clock[0])
        backend.MAX_SESSIONS = 1
        nonce = secrets.token_urlsafe(32)
        tx = backend.dc_begin('https://a.example', nonce)
        with self.assertRaises(AgeError):
            backend.dc_begin('https://a.example', nonce)
        with self.assertRaises(AgeError):
            backend.dc_complete(tx['backend_id'], secrets.token_urlsafe(32), {})
        self.assertIn(tx['backend_id'], backend.transactions)
        clock[0] = backend.TTL
        with self.assertRaises(AgeError):
            backend.dc_complete(tx['backend_id'], nonce, {})
        backend.dc_begin('https://a.example', secrets.token_urlsafe(32))
        self.assertNotIn(tx['backend_id'], backend.transactions)

    def test_failed_worker_consumes_transaction(self):
        nonce = secrets.token_urlsafe(32)
        tx = self.backend.dc_begin('https://a.example', nonce)
        with self.assertRaises(AgeError):
            self.backend.dc_complete(tx['backend_id'], nonce, {'age_over_18': True})
        self.assertNotIn(tx['backend_id'], self.backend.transactions)


if __name__ == '__main__':
    unittest.main()
