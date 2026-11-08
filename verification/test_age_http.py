import io
import json
import unittest

from age_http import AgeApplication
from age_gateway import AgeGateway, Sites
from test_age_gateway import Backend, KEY_A, site
from age_backend import EuAgeVerifierBackend, QUERY_ID, AGE_DOCTYPE
from test_age_backend import Transport, TEST_CA, BASE, PROOF, encoded, init_result, documents


class AgeHTTPTest(unittest.TestCase):
    def setUp(self):
        self.backend = Backend()
        self.app = AgeApplication(AgeGateway(Sites([site('a', KEY_A)]), self.backend), 'age.internal')

    def request(self, path='/age/start', data=None, raw=None, **headers):
        if raw is None:
            raw = json.dumps(data if data is not None else {'siteId': 'a', 'origin': 'https://a.example', 'method': 'openid4vp'}).encode()
        environ = {'REQUEST_METHOD': 'POST', 'PATH_INFO': path, 'QUERY_STRING': '',
                   'HTTP_HOST': 'age.internal', 'wsgi.url_scheme': 'https', 'CONTENT_TYPE': 'application/json',
                   'CONTENT_LENGTH': str(len(raw)), 'HTTP_AUTHORIZATION': 'Bearer ' + KEY_A,
                   'wsgi.input': io.BytesIO(raw)} | headers
        response = []
        body = b''.join(self.app(environ, lambda status, values: response.extend([status, dict(values)])))
        self.assertEqual('no-store', response[1]['Cache-Control'])
        self.assertNotIn('Access-Control-Allow-Origin', response[1])
        return response[0], json.loads(body)

    def test_private_round_trip_and_one_use(self):
        status, session = self.request()
        self.assertEqual('200 OK', status)
        arguments = {'siteId': 'a', 'id': session['id'], 'binding': session['binding']}
        self.backend.result = True
        self.assertEqual(('200 OK', {'state': 'VERIFIED'}), self.request('/age/poll', arguments))
        self.assertEqual(('200 OK', {'age_over_18': True}), self.request('/age/consume', arguments))
        self.assertEqual('400 Bad Request', self.request('/age/consume', arguments)[0])

    def test_browser_credentials_cross_site_origins_and_framing_rejected(self):
        cases = [{'HTTP_ORIGIN': 'https://a.example'}, {'HTTP_AUTHORIZATION': ''},
                 {'HTTP_AUTHORIZATION': 'Bearer ' + 'z' * 43}, {'HTTP_HOST': 'evil.example'},
                 {'wsgi.url_scheme': 'http'}, {'HTTP_X_FORWARDED_PROTO': 'https'},
                 {'HTTP_TRANSFER_ENCODING': 'chunked'}, {'QUERY_STRING': 'key=secret'},
                 {'CONTENT_LENGTH': '999999'}, {'CONTENT_LENGTH': '0'},
                 {'CONTENT_LENGTH': '2,2'}, {'CONTENT_LENGTH': '999'},
                 {'CONTENT_TYPE': 'text/plain'}, {'REQUEST_METHOD': 'GET'}]
        for case in cases:
            with self.subTest(case=case):
                self.assertEqual(('400 Bad Request', {'error': 'request_rejected'}), self.request(**case))

    def test_json_and_unknown_fields_rejected_without_echo(self):
        cases = [b'{"siteId":"a","siteId":"b"}', b'[]', b'{"x":NaN}', b'not-json', b'\xff',
                 b'{"siteId":"a","origin":"https://a.example","method":"openid4vp","age_over_18":true}']
        for raw in cases:
            with self.subTest(raw=raw):
                self.assertEqual(('400 Bad Request', {'error': 'request_rejected'}), self.request(raw=raw))

    def test_no_client_verdict_route(self):
        self.assertEqual('400 Bad Request', self.request('/age/approve', {'age_over_18': True})[0])

    def test_http_gateway_and_real_adapter_contract_together(self):
        # Only the HTTP verifier responses are fake; exercise the actual local
        # HTTP -> gateway -> adapter -> gateway -> one-use consume integration.
        for extra_identity in (False, True):
            with self.subTest(extra_identity=extra_identity):
                transport = Transport()
                backend = EuAgeVerifierBackend(BASE, TEST_CA, transport=transport)
                self.app = AgeApplication(AgeGateway(Sites([site('a', KEY_A)]), backend), 'age.internal')
                attrs = documents()
                if extra_identity:
                    attrs[0]['attributes'][AGE_DOCTYPE]['name'] = 'Synthetic'
                transport.responses = [(200, encoded(init_result())),
                                       (200, encoded({'vp_token': {QUERY_ID: [PROOF]}})),
                                       (200, encoded(attrs))]
                status, session = self.request()
                self.assertEqual('200 OK', status)
                arguments = {'siteId': 'a', 'id': session['id'], 'binding': session['binding']}
                state = 'FAILED' if extra_identity else 'VERIFIED'
                self.assertEqual(('200 OK', {'state': state}), self.request('/age/poll', arguments))
                result = self.request('/age/consume', arguments)
                if extra_identity:
                    self.assertEqual('400 Bad Request', result[0])
                else:
                    self.assertEqual(('200 OK', {'age_over_18': True}), result)
                self.assertEqual('400 Bad Request', self.request('/age/consume', arguments)[0])


if __name__ == '__main__':
    unittest.main()
