"""API-contract/negative tests with an explicit fake verifier, not crypto tests."""
import json
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode

from age_backend import AGE_DOCTYPE, QUERY_ID, EuAgeVerifierBackend
from age_gateway import AgeError


# Generated synthetic CA; no private key is retained. It is never a runtime
# default or a production issuer trust anchor.
TEST_CA = '''-----BEGIN CERTIFICATE-----
MIIBUzCB+6ADAgECAgEBMAoGCCqGSM49BAMCMCgxJjAkBgNVBAMMHVN5bnRoZXRp
YyBhZ2UgYWRhcHRlciB0ZXN0IENBMB4XDTI2MDEwMTAwMDAwMFoXDTM1MTIzMDAw
MDAwMFowKDEmMCQGA1UEAwwdU3ludGhldGljIGFnZSBhZGFwdGVyIHRlc3QgQ0Ew
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ9ZDgnxhqFjz9eIM84K51CDLpWyI8a
iEPAn2EZNBaNAbCdh31L2pCQRjDFoKWYXNnlNc/iQCHTgovOJY0e01a4oxYwFDAS
BgNVHRMBAf8ECDAGAQH/AgEAMAoGCCqGSM49BAMCA0cAMEQCIFjalwofHRJwN01Y
ts7Bl3q20Leh7ndSRTQiMjSaY7lvAiBZy9OhvUfT/AvWo3yqomgD3iuZpcxkaU97
3px6vz6stA==
-----END CERTIFICATE-----
'''
BASE = 'https://verifier.example'
IDENT = 'synthetic_transaction_1234567890'
NONCE = 'n' * 43
PROOF = 'c3ludGhldGljX25vdF9hX3JlYWxfbWRvYw'


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


def init_result():
    uri = BASE + '/wallet/request.jwt/synthetic_request_1234567890'
    parameters = {'client_id': 'x509_san_dns:verifier.example', 'request_uri': uri,
                  'request_uri_method': 'get'}
    return {'transaction_id': IDENT, 'request': None, **parameters,
            'authorization_request_uri': 'openid4vp://?' + urlencode(parameters)}


def documents(value=True):
    return [{'docType': AGE_DOCTYPE, 'attributes': {AGE_DOCTYPE: {'age_over_18': value}}}]


class Transport:
    def __init__(self):
        self.responses = []
        self.calls = []

    def __call__(self, method, path, body, content_type):
        self.calls.append((method, path, body, content_type))
        if not self.responses:
            raise AssertionError('unexpected network call')
        return self.responses.pop(0)


class AgeBackendTest(unittest.TestCase):
    def setUp(self):
        self.transport = Transport()
        self.now = 1000
        self.backend = EuAgeVerifierBackend(BASE, TEST_CA, transport=self.transport,
                                            clock=lambda: self.now)

    def begin(self, data=None):
        self.transport.responses.append((200, encoded(init_result() if data is None else data)))
        return self.backend.begin('https://rp.example', NONCE)

    def response(self, wallet=None, attrs=None):
        self.transport.responses.extend([
            (200, encoded({'vp_token': {QUERY_ID: [PROOF]}} if wallet is None else wallet)),
            (200, encoded(documents() if attrs is None else attrs)),
        ])

    def test_request_is_age_only_and_pins_trust_before_issuance(self):
        result = self.begin()
        self.assertEqual({'backend_id': IDENT,
                          'authorization_request': init_result()['authorization_request_uri']}, result)
        method, path, raw, content_type = self.transport.calls[0]
        self.assertEqual(('POST', '/ui/presentations/v2', 'application/json'), (method, path, content_type))
        request = json.loads(raw)
        self.assertEqual(TEST_CA, request['issuer_chain'])
        self.assertEqual(NONCE, request['nonce'])
        self.assertEqual('direct_post.jwt', request['response_mode'])
        self.assertEqual('by_reference', request['jar_mode'])
        self.assertEqual('openid4vp', request['profile'])
        self.assertEqual({'credentials': [{'id': QUERY_ID, 'format': 'mso_mdoc',
                         'meta': {'doctype_value': AGE_DOCTYPE},
                         'claims': [{'path': [AGE_DOCTYPE, 'age_over_18']}]}]}, request['dcql_query'])
        self.assertNotIn('expected_origins', request)
        self.assertNotIn('wallet_response_redirect_uri_template', request)

    def test_only_session_verified_proof_is_extracted_with_same_anchors(self):
        self.begin()
        self.response()
        self.assertIs(True, self.backend.poll(IDENT, NONCE))
        self.assertEqual(('GET', '/ui/presentations/' + IDENT, None, None), self.transport.calls[1])
        method, path, raw, content_type = self.transport.calls[2]
        self.assertEqual(('POST', '/utilities/validations/msoMdoc/deviceResponse',
                          'application/x-www-form-urlencoded'), (method, path, content_type))
        self.assertEqual({'device_response': [PROOF], 'issuer_chain': [TEST_CA]}, parse_qs(raw.decode()))
        with self.assertRaises(AgeError):
            self.backend.poll(IDENT, NONCE)

    def test_false_is_exact_boolean_denial(self):
        self.begin()
        self.response(attrs=documents(False))
        self.assertIs(False, self.backend.poll(IDENT, NONCE))

    def test_empty_400_is_pending_and_never_calls_extraction(self):
        self.begin()
        self.transport.responses.append((400, b''))
        self.assertIsNone(self.backend.poll(IDENT, NONCE))
        self.assertEqual(2, len(self.transport.calls))
        self.response()
        self.assertIs(True, self.backend.poll(IDENT, NONCE))

    def test_always_accept_reports_never_authorize_even_when_trusted(self):
        for report in [{'trusted': True, 'documents': []}, {'trusted': False}, {}, False, 'trusted']:
            with self.subTest(report=report):
                self.setUp()
                self.begin()
                self.response(wallet={'vp_token': {QUERY_ID: [PROOF]}, 'trust_info': report})
                with self.assertRaises(AgeError):
                    self.backend.poll(IDENT, NONCE)
                self.assertEqual(2, len(self.transport.calls))

    def test_errors_wrong_queries_and_multiple_proofs_fail_before_extraction(self):
        for value in [{'age_over_18': True}, {'vp_token': PROOF},
                      {'vp_token': {QUERY_ID: []}}, {'vp_token': {QUERY_ID: [PROOF, PROOF]}},
                      {'vp_token': {'other': [PROOF]}},
                      {'vp_token': {QUERY_ID: [PROOF], 'other': [PROOF]}},
                      {'vp_token': {QUERY_ID: [1]}}, {'vp_token': {QUERY_ID: ['not base64!']}},
                      {'vp_token': {QUERY_ID: [PROOF]}, 'error': 'access_denied'},
                      {'vp_token': {QUERY_ID: [PROOF]}, 'error_description': 'failed'}]:
            with self.subTest(value=value):
                self.setUp()
                self.begin()
                self.response(wallet=value)
                with self.assertRaises(AgeError):
                    self.backend.poll(IDENT, NONCE)
                self.assertEqual(2, len(self.transport.calls))
                with self.assertRaises(AgeError):
                    self.backend.poll(IDENT, NONCE)

    def test_extra_identity_wrong_doc_types_and_nonboolean_age_fail(self):
        cases = [[], documents() * 2, {'age_over_18': True},
                 [{'docType': 'other', 'attributes': {AGE_DOCTYPE: {'age_over_18': True}}}],
                 [{'docType': AGE_DOCTYPE, 'attributes': {'other': {'age_over_18': True}}}],
                 [{'docType': AGE_DOCTYPE, 'attributes': {AGE_DOCTYPE: {'age_over_18': True, 'name': 'Synthetic'}}}],
                 [{'docType': AGE_DOCTYPE, 'attributes': {AGE_DOCTYPE: {}}}]]
        cases += [documents(value) for value in [1, 0, 'true', None, [], {}]]
        for value in cases:
            with self.subTest(value=value):
                self.setUp()
                self.begin()
                self.response(attrs=value)
                with self.assertRaises(AgeError):
                    self.backend.poll(IDENT, NONCE)

    def test_wrong_nonce_unknown_transaction_and_expiry_precede_network(self):
        self.begin()
        for ident, nonce in [(IDENT, 'x' * 43), ('unknown_transaction_123456', NONCE),
                             (IDENT + '/events', NONCE)]:
            with self.subTest(ident=ident), self.assertRaises(AgeError):
                self.backend.poll(ident, nonce)
        self.assertEqual(1, len(self.transport.calls))
        self.now += 120
        with self.assertRaises(AgeError):
            self.backend.poll(IDENT, NONCE)
        self.assertEqual(1, len(self.transport.calls))

    def test_capacity_duplicate_transaction_and_expired_creation_fail(self):
        self.begin()
        with self.assertRaises(AgeError):
            self.begin()
        self.backend.MAX_SESSIONS = 1
        with self.assertRaises(AgeError):
            self.backend.begin('https://rp.example', NONCE)
        self.setUp()
        def delayed(*args):
            self.now += 120
            return 200, encoded(init_result())
        self.backend.transport = delayed
        with self.assertRaises(AgeError):
            self.backend.begin('https://rp.example', NONCE)

    def test_no_external_request_uri_or_authorization_injection(self):
        changes = [{'request_uri': 'https://evil.example/wallet/request.jwt/' + IDENT},
                   {'request_uri': BASE + '/wallet/request.jwt/../other'},
                   {'request_uri_method': 'post'}, {'request': 'signed.but.unexpected'},
                   {'authorization_request_uri': 'https://evil.example/?x=1'},
                   {'authorization_request_uri': init_result()['authorization_request_uri'] + '&request_uri=evil'},
                   {'authorization_request_uri': init_result()['authorization_request_uri'] + '#fragment'},
                   {'transaction_id': '../../events'}, {'new_unexpected_field': True}]
        for change in changes:
            with self.subTest(change=change):
                self.setUp()
                value = init_result()
                value.update(change)
                with self.assertRaises(AgeError):
                    self.begin(value)

    def test_http_redirect_error_malformed_duplicate_and_oversized_json_fail(self):
        cases = [(302, b''), (404, b''), (500, b'private details'), (400, b'{"error":"failed"}'),
                 (200, b'not JSON'), (200, b'{"vp_token":{},"vp_token":{}}'),
                 (200, b'{"vp_token":NaN}'), (200, b' ' * (self.backend.MAX_RESPONSE + 1))]
        for response in cases:
            with self.subTest(status=response[0], size=len(response[1])):
                self.setUp()
                self.begin()
                self.transport.responses.append(response)
                with self.assertRaises(AgeError) as error:
                    self.backend.poll(IDENT, NONCE)
                self.assertNotIn('private details', str(error.exception))
                self.assertEqual(2, len(self.transport.calls))

    def test_utility_failure_cannot_be_retried_as_success(self):
        self.begin()
        self.transport.responses.extend([(200, encoded({'vp_token': {QUERY_ID: [PROOF]}})),
                                         (400, b'{"error":"invalid signature"}')])
        with self.assertRaises(AgeError):
            self.backend.poll(IDENT, NONCE)
        with self.assertRaises(AgeError):
            self.backend.poll(IDENT, NONCE)

    def test_config_requires_https_and_explicit_parsable_issuer_pem(self):
        for url in ['http://verifier.example', 'https://user:pass@verifier.example',
                    'https://verifier.example?x=1', 'https://verifier.example?',
                    'https://verifier.example#', 'https://verifier.example/a/../b',
                    'https://verifier.example/%2e%2e', 'https://verifier.example\n']:
            with self.subTest(url=url), self.assertRaises(AgeError):
                EuAgeVerifierBackend(url, TEST_CA, transport=self.transport)
        for pem in ['', None, 'arbitrary trust', TEST_CA + '-----BEGIN PRIVATE KEY-----',
                    '-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----']:
            with self.subTest(pem=pem), self.assertRaises(AgeError):
                EuAgeVerifierBackend(BASE, pem, transport=self.transport)

    def test_dc_api_has_no_success_route(self):
        self.assertFalse(self.backend.supports_dc_api)
        with self.assertRaises(AgeError):
            self.backend.dc_begin('https://rp.example', NONCE)
        with self.assertRaises(AgeError):
            self.backend.dc_complete(IDENT, NONCE, {'age_over_18': True})
        self.assertEqual([], self.transport.calls)

    def test_real_transport_uses_tls_checks_and_closes_without_following_redirect(self):
        with patch('age_backend.HTTPSConnection') as factory:
            connection = factory.return_value
            response = connection.getresponse.return_value
            response.status = 302
            response.length = 0
            response.getheader.side_effect = lambda key, default=None: default
            response.read.return_value = b''
            backend = EuAgeVerifierBackend(BASE, TEST_CA)
            with self.assertRaises(AgeError):
                backend.begin('https://rp.example', NONCE)
            self.assertEqual(1, connection.request.call_count)
            connection.close.assert_called_once()
            context = factory.call_args.kwargs['context']
            self.assertTrue(context.check_hostname)
            self.assertEqual('verifier.example', factory.call_args.args[0])

    def test_real_transport_rejects_truncated_json_even_if_prefix_is_valid(self):
        with patch('age_backend.HTTPSConnection') as factory:
            connection = factory.return_value
            response = connection.getresponse.return_value
            response.status = 200
            response.length = 10  # Declared bytes still missing after read.
            response.getheader.side_effect = lambda key, default=None: (
                'application/json' if key == 'Content-Type' else default)
            response.read.return_value = encoded(init_result())
            backend = EuAgeVerifierBackend(BASE, TEST_CA)
            with self.assertRaises(AgeError):
                backend.begin('https://rp.example', NONCE)
            connection.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
