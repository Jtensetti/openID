"""Strict framing and configured destinations for internal HTTP clients."""
import http.client
import re
from urllib.parse import urlsplit


def configured_url(value):
    # urlsplit removes some controls before parsing; reject them first.
    if not isinstance(value, str) or not value or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ValueError('invalid service URL')
    parsed = urlsplit(value)
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError('service URL must not contain credentials, query or fragment')
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError('invalid service port')
    return parsed


class StrictResponse(http.client.HTTPResponse):
    def begin(self):
        super().begin()
        lengths = self.headers.get_all('Content-Length', [])
        encodings = self.headers.get_all('Transfer-Encoding', [])
        if (len(lengths) > 1 or len(encodings) > 1 or (lengths and encodings)
                or any(re.fullmatch(r'[0-9]+', value.strip(' \t')) is None for value in lengths)
                or any(value.strip(' \t').lower() != 'chunked' for value in encodings)):
            self.close()
            raise http.client.HTTPException('invalid response framing')

    def _read_next_chunk_size(self):
        line = self.fp.readline(http.client._MAXLINE + 1)
        if len(line) > http.client._MAXLINE:
            self.close()
            raise http.client.LineTooLong('chunk size')
        size = line.partition(b';')[0].removesuffix(b'\r\n')
        if not line.endswith(b'\r\n') or re.fullmatch(rb'[0-9A-Fa-f]+', size) is None:
            self.close()
            raise ValueError('invalid chunk size')
        return int(size, 16)


class HTTPSConnection(http.client.HTTPSConnection):
    response_class = StrictResponse


class HTTPConnection(http.client.HTTPConnection):
    """Only used for the explicitly enabled loopback OpenBao fixture."""
    response_class = StrictResponse
