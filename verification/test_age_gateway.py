import concurrent.futures
import hashlib
import threading
import unittest

from age_gateway import AgeError, AgeGateway, Site, Sites, site_origin


KEY_A, KEY_B, KEY_C = 'a' * 43, 'b' * 43, 'c' * 43


def site(ident, key, customer='example-group'):
    return Site(customer, ident, 'https://' + ident + '.example', hashlib.sha256(key.encode()).hexdigest())


class Backend:
    """Explicit fake: these tests exercise the gateway, never mdoc cryptography."""
    supports_dc_api = True

    def __init__(self):
        self.calls = []
        self.result = None

    def begin(self, origin, nonce):
        self.calls.append((origin, nonce))
        return {'backend_id': 'opaque-transaction',
                'authorization_request': 'openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest'}

    def poll(self, ident, nonce):
        self.calls.append((ident, nonce))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    def dc_begin(self, origin, nonce):
        self.calls.append((origin, nonce))
        return {'backend_id': 'dc-transaction',
                'requests': [{'protocol': 'org-iso-mdoc', 'data': {'synthetic': True}}]}

    def dc_complete(self, ident, nonce, credential):
        self.calls.append((ident, nonce, credential))
        return self.result


class AgeGatewayTest(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.backend = Backend()
        self.sites = Sites([site('a', KEY_A), site('b', KEY_B), site('c', KEY_C, 'other-group')])
        self.gateway = AgeGateway(self.sites, self.backend, clock=lambda: self.now)

    def start(self, method='openid4vp'):
        return self.gateway.start('a', KEY_A, 'https://a.example', method)

    def args(self, session):
        return 'a', KEY_A, session['id'], session['binding']

    def test_minimal_result_once_after_backend_verification(self):
        session = self.start()
        self.assertEqual({'id', 'binding', 'expiresIn', 'presentation'}, set(session))
        with self.assertRaises(AgeError):
            self.gateway.consume(*self.args(session))
        self.assertEqual({'state': 'PENDING'}, self.gateway.poll(*self.args(session)))
        self.backend.result = True
        self.assertEqual({'state': 'VERIFIED'}, self.gateway.poll(*self.args(session)))
        self.assertEqual({'age_over_18': True}, self.gateway.consume(*self.args(session)))
        with self.assertRaises(AgeError):
            self.gateway.consume(*self.args(session))

    def test_same_customer_does_not_share_authorization(self):
        session = self.start()
        self.backend.result = True
        self.gateway.poll(*self.args(session))
        for ident, key in [('b', KEY_B), ('c', KEY_C), ('a', KEY_B)]:
            with self.subTest(site=ident, key=key), self.assertRaises(AgeError):
                self.gateway.consume(ident, key, session['id'], session['binding'])
        self.assertEqual({'age_over_18': True}, self.gateway.consume(*self.args(session)))

    def test_origin_is_exact_and_nonce_is_fresh(self):
        for origin in ['https://b.example', 'https://a.example/', 'http://a.example', 'https://a.example.evil.test']:
            with self.subTest(origin=origin), self.assertRaises(AgeError):
                self.gateway.start('a', KEY_A, origin, 'openid4vp')
        one, two = self.start(), self.start()
        self.assertNotEqual(one['binding'], two['binding'])
        self.assertNotEqual(one['id'], two['id'])
        self.assertNotEqual(self.backend.calls[0][1], self.backend.calls[1][1])
        self.assertEqual('https://a.example', self.backend.calls[0][0])

    def test_wrong_browser_binding_cannot_poll_cancel_or_consume(self):
        one, two = self.start(), self.start()
        for operation in [self.gateway.poll, self.gateway.cancel, self.gateway.consume]:
            with self.subTest(operation=operation.__name__), self.assertRaises(AgeError):
                operation('a', KEY_A, one['id'], two['binding'])

    def test_false_and_nonboolean_results_never_authorize(self):
        for result in [False, 1, 'true', {'age_over_18': True}, RuntimeError('sensitive details')]:
            with self.subTest(result=result):
                session = self.start()
                self.backend.result = result
                response = self.gateway.poll(*self.args(session))
                self.assertEqual({'state': 'DENIED' if result is False else 'FAILED'}, response)
                with self.assertRaises(AgeError):
                    self.gateway.consume(*self.args(session))

    def test_expiry_and_restart_fail_closed(self):
        session = self.start()
        self.backend.result = True
        self.gateway.poll(*self.args(session))
        self.now += 120
        self.assertEqual({'state': 'EXPIRED'}, self.gateway.poll(*self.args(session)))
        with self.assertRaises(AgeError):
            self.gateway.consume(*self.args(session))
        restarted = AgeGateway(self.sites, self.backend)
        with self.assertRaises(AgeError):
            restarted.consume(*self.args(session))

    def test_cancelled_success_cannot_be_consumed(self):
        session = self.start()
        self.backend.result = True
        self.gateway.poll(*self.args(session))
        self.assertEqual({'state': 'CANCELLED'}, self.gateway.cancel(*self.args(session)))
        self.assertEqual({'state': 'CANCELLED'}, self.gateway.poll(*self.args(session)))
        with self.assertRaises(AgeError):
            self.gateway.consume(*self.args(session))

    def test_parallel_consumption_only_one_wins(self):
        session = self.start()
        self.backend.result = True
        self.gateway.poll(*self.args(session))
        def consume(_):
            try:
                return self.gateway.consume(*self.args(session))
            except AgeError:
                return None
        with concurrent.futures.ThreadPoolExecutor(8) as executor:
            results = list(executor.map(consume, range(8)))
        self.assertEqual(1, results.count({'age_over_18': True}))

    def test_cancel_and_expiry_win_over_inflight_backend_result(self):
        for expire in [False, True]:
            with self.subTest(expire=expire):
                entered, release = threading.Event(), threading.Event()
                def blocking_poll(*_):
                    entered.set()
                    self.assertTrue(release.wait(5))
                    return True
                self.backend.poll = blocking_poll
                session = self.start()
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(self.gateway.poll, *self.args(session))
                    self.assertTrue(entered.wait(5))
                    self.assertEqual({'state': 'VERIFYING'}, self.gateway.poll(*self.args(session)))
                    if expire:
                        self.now += 120
                    else:
                        self.gateway.cancel(*self.args(session))
                    release.set()
                    self.assertEqual({'state': 'EXPIRED' if expire else 'CANCELLED'}, future.result())
                with self.assertRaises(AgeError):
                    self.gateway.consume(*self.args(session))

    def test_dc_api_payload_is_only_sent_to_verifier(self):
        session = self.start('dc_api')
        self.assertEqual({'state': 'PENDING'}, self.gateway.poll(*self.args(session)))
        self.backend.result = False
        self.assertEqual({'state': 'DENIED'}, self.gateway.complete(*self.args(session), {'age_over_18': True}))
        with self.assertRaises(AgeError):
            self.gateway.complete(*self.args(session), {'age_over_18': True})
        with self.assertRaises(AgeError):
            self.gateway.consume(*self.args(session))

    def test_dc_api_disabled_without_compatible_engine(self):
        self.backend.supports_dc_api = False
        with self.assertRaises(AgeError):
            self.start('dc_api')
        self.assertEqual({}, self.gateway.sessions)

    def test_capacity_is_bounded_and_expired_state_is_evicted(self):
        self.gateway.MAX_PER_SITE = 2
        self.start(); self.start()
        with self.assertRaises(AgeError):
            self.start()
        self.now += 120
        self.start()
        self.assertEqual(1, len(self.gateway.sessions))

    def test_failed_start_does_not_consume_unreachable_capacity(self):
        self.gateway.MAX_PER_SITE = 1
        original = self.backend.begin
        def failing(*_):
            raise RuntimeError('temporary outage')
        self.backend.begin = failing
        with self.assertRaises(AgeError):
            self.start()
        self.assertEqual({}, self.gateway.sessions)
        self.backend.begin = original
        self.start()

    def test_start_reports_remaining_lifetime_after_backend_delay(self):
        original = self.backend.begin
        def delayed(*arguments):
            self.now += 110
            return original(*arguments)
        self.backend.begin = delayed
        self.assertEqual(10, self.start()['expiresIn'])

    def test_registry_rejects_shared_keys_ids_and_origins(self):
        for entries in [[site('a', KEY_A), site('a', KEY_B)],
                        [site('a', KEY_A), site('b', KEY_A)],
                        [site('a', KEY_A), Site('group', 'b', 'https://a.example', hashlib.sha256(KEY_B.encode()).hexdigest())]]:
            with self.subTest(entries=entries), self.assertRaises(AgeError):
                Sites(entries)

    def test_origin_parser_rejects_noncanonical_or_ambiguous_values(self):
        for origin in ['http://a.example', 'https://a.example/', 'https://a.example:443',
                       'https://a.example:0', 'https://a.example:99999', 'https://A.example',
                       'https://a.example?', 'https://a.example#', 'https://a.example/?x=1',
                       'https://a.example\n', 'https://a..example', 'https://-a.example',
                       'https://127.1', 'https://2130706433', 'https://0x7f000001',
                       'https://127.0.0.1', 'https://localhost',
                       'https://u:p@a.example', 'https://a.example.evil.test/path']:
            with self.subTest(origin=origin), self.assertRaises(AgeError):
                site_origin(origin)
        self.assertEqual('https://a.example:8443', site_origin('https://a.example:8443'))


if __name__ == '__main__':
    unittest.main()
