"""Private server-to-server WSGI API for age sessions.

Deploy separately from the identity issuer. The RP's own backend must retain
binding in its authenticated browser session and enforce its normal CSRF policy.
Never deliver the per-site API key or binding to browser JavaScript.
"""
import json
import re

from age_gateway import AgeError


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise AgeError('duplicate JSON field')
        value[key] = item
    return value


def _constant(_):
    raise AgeError('invalid JSON constant')


class AgeApplication:
    MAX_BODY = 128 * 1024

    def __init__(self, gateway, host):
        if not isinstance(host, str) or not re.fullmatch(r'[a-z0-9.-]+(?::[1-9][0-9]{0,4})?', host):
            raise AgeError('invalid API host')
        self.gateway, self.host = gateway, host

    def __call__(self, environ, start_response):
        status, result = '400 Bad Request', {'error': 'request_rejected'}
        try:
            if (environ.get('REQUEST_METHOD') != 'POST' or environ.get('QUERY_STRING') or
                    environ.get('HTTP_HOST') != self.host or environ.get('wsgi.url_scheme') != 'https' or
                    environ.get('HTTP_ORIGIN') or environ.get('HTTP_TRANSFER_ENCODING') or
                    any(environ.get(name) for name in environ if name == 'HTTP_FORWARDED' or name.startswith('HTTP_X_FORWARDED')) or
                    environ.get('CONTENT_TYPE') != 'application/json'):
                raise AgeError('invalid request')
            raw_length = environ.get('CONTENT_LENGTH', '')
            if not re.fullmatch(r'[1-9][0-9]{0,5}', raw_length) or int(raw_length) > self.MAX_BODY:
                raise AgeError('invalid body length')
            authorization = environ.get('HTTP_AUTHORIZATION', '')
            if not re.fullmatch(r'Bearer [A-Za-z0-9_-]{43,128}', authorization):
                raise AgeError('site authentication failed')
            key = authorization.removeprefix('Bearer ')
            raw = environ['wsgi.input'].read(int(raw_length))
            if len(raw) != int(raw_length):
                raise AgeError('truncated request')
            data = json.loads(raw.decode('utf-8'), object_pairs_hook=_object, parse_constant=_constant)
            if not isinstance(data, dict):
                raise AgeError('invalid request')
            path = environ.get('PATH_INFO')
            fields = {'siteId', 'id', 'binding'}
            if path == '/age/start':
                if set(data) != {'siteId', 'origin', 'method'}:
                    raise AgeError('invalid request fields')
                result = self.gateway.start(data['siteId'], key, data['origin'], data['method'])
            elif path in ('/age/poll', '/age/cancel', '/age/consume', '/age/complete'):
                if set(data) != (fields | {'credential'} if path == '/age/complete' else fields):
                    raise AgeError('invalid request fields')
                arguments = (data['siteId'], key, data['id'], data['binding'])
                if path == '/age/complete':
                    result = self.gateway.complete(*arguments, data['credential'])
                else:
                    result = getattr(self.gateway, path.removeprefix('/age/'))(*arguments)
            else:
                raise AgeError('unknown route')
            status = '200 OK'
        except (AgeError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
            # No raw request, verifier errors, credentials or bearer keys in logs.
            result = {'error': 'request_rejected'}
        body = json.dumps(result, separators=(',', ':'), allow_nan=False).encode()
        start_response(status, [('Content-Type', 'application/json'), ('Content-Length', str(len(body))),
                                ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff')])
        return [body]
