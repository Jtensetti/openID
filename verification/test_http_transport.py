import http.client
import io
import ssl
import unittest
from unittest.mock import patch

from http_transport import configured_url, HTTPConnection, HTTPSConnection, StrictResponse


class Wire:
    def __init__(self, data):
        self.data = data

    def makefile(self, *args):
        return io.BytesIO(self.data)


def response(headers, body=b'hello'):
    value = StrictResponse(Wire(b'HTTP/1.1 200 OK\r\n' + headers + b'\r\n\r\n' + body))
    value.begin()
    return value


class TransportTests(unittest.TestCase):
    def test_ordinary_length_chunked_and_close_delimited_responses(self):
        self.assertEqual(response(b'Content-Length: 5').read(), b'hello')
        self.assertEqual(response(b'Connection: close').read(), b'hello')
        for size in (b'5', b'05', b'5;extension=value'):
            self.assertEqual(response(b'Transfer-Encoding: chunked', size+b'\r\nhello\r\n0\r\n\r\n').read(), b'hello')
        self.assertEqual(response(b'Transfer-Encoding: chunked', b'A\r\n0123456789\r\n0\r\n\r\n').read(), b'0123456789')

    def test_malformed_and_ambiguous_lengths_rejected_before_body(self):
        for length in (b'+5', b'-5', b'5_0', b'0x5', b'\xb2', b'5, 5', b''):
            with self.subTest(length=length), self.assertRaises(http.client.HTTPException):
                response(b'Content-Length: '+length)
        for headers in (b'Content-Length: 5\r\nContent-Length: 5',
                        b'Content-Length: 5\r\nTransfer-Encoding: chunked',
                        b'Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked',
                        b'Transfer-Encoding: gzip, chunked'):
            with self.subTest(headers=headers), self.assertRaises(http.client.HTTPException):
                response(headers)

    def test_chunk_grammar_and_size_limit(self):
        for size in (b'+5', b'-5', b'5_0', b'0x5', b' 5', b'5 ', b'', b'\xb2', b'g'):
            with self.subTest(size=size), self.assertRaises(http.client.IncompleteRead):
                response(b'Transfer-Encoding: chunked', size+b'\r\nhello\r\n0\r\n\r\n').read()
        with self.assertRaises(http.client.LineTooLong):
            response(b'Transfer-Encoding: chunked', b'1'*(http.client._MAXLINE+1)).read()
        with self.assertRaises(http.client.IncompleteRead):
            response(b'Transfer-Encoding: chunked', b'5\nhello\r\n0\r\n\r\n').read()

    def test_truncated_and_bounded_reads(self):
        with self.assertRaises(http.client.IncompleteRead):
            response(b'Content-Length: 20').read()
        value = response(b'Transfer-Encoding: chunked', b'A\r\n0123456789\r\n0\r\n\r\n')
        self.assertEqual(value.read(4), b'0123')
        self.assertEqual(value.read(), b'456789')

    def test_controls_rejected_before_url_normalization_or_dns(self):
        with patch('socket.getaddrinfo') as lookup:
            for value in ('https://localhost\0.example', 'https://localhost:443\0',
                          'https://local\nhost', 'https://local\thost', '\nhttps://localhost',
                          'https://localhost/\x7f', 'https://user:password@localhost',
                          'https://localhost:0', 'https://localhost:65536', 'https://localhost?query'):
                with self.subTest(url=value), self.assertRaises(ValueError):
                    configured_url(value)
            lookup.assert_not_called()
        self.assertEqual(configured_url('https://localhost:443').port, 443)
        self.assertEqual(configured_url('https://[::1]:8443').hostname, '::1')

    def test_service_clients_use_strict_response_and_verify_tls(self):
        from monitor import connection
        from transit import TransitVault
        client, path = connection('https://localhost/alert', None)
        self.assertIs(client.response_class, StrictResponse)
        self.assertEqual(client._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(client._context.check_hostname)
        self.assertEqual(path, '/alert')
        client.close()
        self.assertIs(HTTPConnection.response_class, StrictResponse)
        self.assertIs(HTTPSConnection.response_class, StrictResponse)
        for value in ('https://localhost\0.example', 'https://local\nhost', 'https://localhost:443\0'):
            with self.subTest(url=value), self.assertRaises(ValueError):
                TransitVault(value, '/unused-token')

    def test_transit_rejects_unknown_reference_domains_before_network_access(self):
        from transit import TransitVault
        vault=TransitVault('https://localhost','/unused-token')
        cases=(('registry-person-v1:fixture-registry:personnummer','195704133106\n'),
               ('registry-person-v1:fixture-registry:personnummer','19570413310'),
               ('registry-person-v1:fixture-registry:synthetic','REAL-PERSON'),
               ('registry-evidence-v1:fixture-registry','short'),
               ('registry-person-v1:fixture-registry:other','195704133106'),
               ('registry-evidence-v1:fixture-registry','a'*129),
               ('unknown-domain','195704133106'),(None,'value'),('domain',None))
        with patch.object(vault,'request') as request:
            for domain,value in cases:
                with self.subTest(domain=domain),self.assertRaises(ValueError):vault.reference(domain,value)
            request.assert_not_called()


if __name__ == '__main__':
    unittest.main()
