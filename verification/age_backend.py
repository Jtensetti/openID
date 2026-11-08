"""Bounded adapter to the EC's separately operated OpenID4VP verifier.

API source: eu-digital-identity-wallet/av-srv-verifier-endpoint at
787089b7239e39dceaf31c0274d9de745b880194. This module does not validate CBOR,
COSE, holder signatures or ZK proofs itself. It requires the pinned service
with alwaysAcceptWalletResponse=false and, for this ordinary OpenID4VP flow,
mdoc.redirectUriClientIdInDeviceAuthHandover=false. The operator supplies
trusted issuer certificates, never the browser or a tenant.

The utility endpoint alone does NOT verify holder/session binding. It is
used only to extract the very same proof already validated by that service's
strict session path. The API boundary and negative tests are not a live
wallet interoperability or independent cryptographic conformance test.
"""
from dataclasses import dataclass
import json
import re
import secrets
import ssl
import threading
import time
from urllib.parse import parse_qsl, urlencode, urlsplit

from age_gateway import AgeError, site_origin
from http_transport import HTTPSConnection, configured_url


UPSTREAM_REVISION = '787089b7239e39dceaf31c0274d9de745b880194'
AGE_DOCTYPE = 'eu.europa.ec.av.1'
QUERY_ID = 'proof_of_age'


def _dcql():
    return {'credentials': [{'id': QUERY_ID, 'format': 'mso_mdoc',
                             'meta': {'doctype_value': AGE_DOCTYPE},
                             'claims': [{'path': [AGE_DOCTYPE, 'age_over_18']}]}]}


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise AgeError('invalid verifier response')
        value[key] = item
    return value


def _constant(_):
    raise AgeError('invalid verifier response')


def _json(raw):
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_object, parse_constant=_constant)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise AgeError('invalid verifier response') from None


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,256}', value):
        raise AgeError('invalid verifier session')
    return value


def _nonce(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value):
        raise AgeError('invalid presentation nonce')
    return value


def _issuer_certificates(value):
    # Parse certificate syntax with OpenSSL through ssl; these are explicit
    # operator trust anchors, not a wallet-supplied chain to trust implicitly.
    pattern = r'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----'
    if (not isinstance(value, str) or not value.isascii() or not 1 <= len(value) <= 65536):
        raise AgeError('trusted issuer certificates required')
    matches = list(re.finditer(pattern, value))
    if not 1 <= len(matches) <= 16 or re.sub(pattern, '', value).strip():
        raise AgeError('trusted issuer certificates required')
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=value)
    except (ValueError, ssl.SSLError):
        raise AgeError('invalid trusted issuer certificates') from None
    return value


@dataclass
class _Transaction:
    nonce: str
    expires: float
    polling: bool = False


class EuAgeVerifierBackend:
    """One fixed HTTPS verifier, pinned issuer trust and one-use transactions.

    begin(origin, nonce) -> {backend_id, authorization_request}
    poll(backend_id, nonce) -> None (pending), bool (verified age assertion)

    ``transport`` is an optional test seam: (method, path, body, content_type)
    -> (HTTP status, raw bytes). Production uses strict TLS HTTP framing,
    bounded bodies and no redirects. API and public wallet routes must share
    base_url; protect /ui and /utilities from public access independently.
    """
    supports_dc_api = False
    TTL = 120
    MAX_SESSIONS = 256
    MAX_RESPONSE = 256 * 1024
    MAX_PROOF = 128 * 1024

    def __init__(self, base_url, issuer_chain, *, ca_file=None, transport=None, clock=time.monotonic):
        try:
            url = configured_url(base_url)
            if (url.scheme != 'https' or not base_url.isascii() or
                    not re.fullmatch(r'(?:/[A-Za-z0-9_-]+)*', url.path) or
                    '?' in base_url or '#' in base_url or '\\' in base_url):
                raise ValueError('invalid verifier URL')
        except ValueError:
            raise AgeError('verifier requires a fixed HTTPS base URL') from None
        self.url, self.base_url = url, base_url
        self.issuer_chain = _issuer_certificates(issuer_chain)
        self.tls_context = ssl.create_default_context(cafile=ca_file)
        self.transport, self.clock = transport, clock
        self.transactions = {}
        self.lock = threading.RLock()

    def _exchange(self, method, path, body=None, content_type=None):
        connection = None
        try:
            if self.transport is not None:
                status, raw = self.transport(method, self.url.path + path, body, content_type)
            else:
                connection = HTTPSConnection(self.url.hostname, self.url.port, timeout=5,
                                             context=self.tls_context)
                headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity'}
                if content_type is not None:
                    headers['Content-Type'] = content_type
                connection.request(method, self.url.path + path, body=body, headers=headers)
                response = connection.getresponse()
                if response.getheader('Content-Encoding', 'identity').lower() != 'identity':
                    raise AgeError('invalid verifier response')
                status, raw = response.status, response.read(self.MAX_RESPONSE + 1)
                if response.length is not None and response.length != 0:
                    raise AgeError('truncated verifier response')
                if status == 200 and response.getheader('Content-Type', '').split(';', 1)[0].strip().lower() != 'application/json':
                    raise AgeError('invalid verifier response')
            if type(status) is not int or not isinstance(raw, bytes) or len(raw) > self.MAX_RESPONSE:
                raise AgeError('invalid verifier response')
            # No redirect is followed, including same-host redirects.
            if status not in (200, 400):
                raise AgeError('verifier unavailable')
            return status, raw
        except Exception:
            # Never carry a proof, backend error body or URL token into logs.
            raise AgeError('verifier request failed') from None
        finally:
            if connection is not None:
                connection.close()

    def begin(self, origin, nonce):
        site_origin(origin)
        _nonce(nonce)
        started = self.clock()
        with self.lock:
            self.transactions = {key: tx for key, tx in self.transactions.items() if tx.expires > started}
            if len(self.transactions) >= self.MAX_SESSIONS:
                raise AgeError('verifier capacity reached')
        request = {'dcql_query': _dcql(), 'nonce': nonce, 'issuer_chain': self.issuer_chain,
                   'response_mode': 'direct_post.jwt', 'jar_mode': 'by_reference',
                   'request_uri_method': 'get', 'authorization_request_scheme': 'openid4vp',
                   'profile': 'openid4vp'}
        status, raw = self._exchange('POST', '/ui/presentations/v2',
                                     json.dumps(request, separators=(',', ':'), allow_nan=False).encode(),
                                     'application/json')
        if status != 200:
            raise AgeError('could not start verifier session')
        data = _json(raw)
        if not isinstance(data, dict):
            raise AgeError('invalid verifier response')
        ident = _identifier(data.get('transaction_id'))
        authorization = self._authorization_request(data)
        with self.lock:
            if self.clock() >= started + self.TTL or ident in self.transactions or len(self.transactions) >= self.MAX_SESSIONS:
                raise AgeError('verifier session unavailable')
            self.transactions[ident] = _Transaction(nonce, started + self.TTL)
        # The origin is enforced by the RP gateway. It is deliberately not an
        # invented expected_origins claim in this ordinary redirect flow.
        return {'backend_id': ident, 'authorization_request': authorization}

    def _authorization_request(self, data):
        allowed = {'transaction_id', 'client_id', 'request', 'request_uri',
                   'request_uri_method', 'authorization_request_uri'}
        if set(data) - allowed or data.get('request') is not None or data.get('request_uri_method') != 'get':
            raise AgeError('unexpected verifier request profile')
        request_uri, client_id = data.get('request_uri'), data.get('client_id')
        if (not isinstance(request_uri, str) or
                not request_uri.startswith(self.base_url + '/wallet/request.jwt/') or
                not re.fullmatch(r'[A-Za-z0-9_-]{16,256}', request_uri.removeprefix(self.base_url + '/wallet/request.jwt/')) or
                not isinstance(client_id, str) or not 1 <= len(client_id) <= 512 or
                not client_id.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in client_id)):
            raise AgeError('invalid verifier request destination')
        authorization = data.get('authorization_request_uri')
        if (not isinstance(authorization, str) or not authorization.startswith('openid4vp://?') or
                len(authorization) > 4096 or not authorization.isascii() or
                any(ord(c) <= 32 or ord(c) == 127 for c in authorization)):
            raise AgeError('invalid verifier authorization request')
        uri = urlsplit(authorization)
        try:
            pairs = parse_qsl(uri.query, keep_blank_values=True, strict_parsing=True,
                              max_num_fields=3, encoding='utf-8', errors='strict')
        except (ValueError, UnicodeError):
            raise AgeError('invalid verifier authorization request') from None
        expected = {'client_id': client_id, 'request_uri': request_uri, 'request_uri_method': 'get'}
        if uri.fragment or uri.netloc or uri.path or len(pairs) != 3 or dict(pairs) != expected:
            raise AgeError('invalid verifier authorization request')
        return authorization

    def poll(self, backend_id, nonce):
        _identifier(backend_id)
        _nonce(nonce)
        with self.lock:
            transaction = self.transactions.get(backend_id)
            if (transaction is None or transaction.polling or self.clock() >= transaction.expires or
                    not secrets.compare_digest(transaction.nonce, nonce)):
                raise AgeError('verifier session unavailable')
            transaction.polling = True
        pending = False
        try:
            status, raw = self._exchange('GET', '/ui/presentations/' + backend_id)
            # This revision maps Requested/RequestObjectRetrieved to empty
            # HTTP 400. It also uses 400 for invalid states: none authorize,
            # and our independent lifetime bounds waiting in every case.
            if status == 400 and raw == b'':
                pending = True
                return None
            if status != 200:
                raise AgeError('verifier rejected presentation')
            wallet_response = _json(raw)
            if (not isinstance(wallet_response, dict) or
                    set(wallet_response) - {'vp_token', 'error', 'error_description', 'trust_info'} or
                    wallet_response.get('error') is not None or
                    wallet_response.get('error_description') is not None or
                    wallet_response.get('trust_info') is not None):
                # trust_info appears in the upstream's always-accept mode.
                # Even trusted:true can include skipped checks: never accept.
                raise AgeError('strict presentation verification required')
            tokens = wallet_response.get('vp_token')
            if not isinstance(tokens, dict) or set(tokens) != {QUERY_ID}:
                raise AgeError('unexpected presentation query')
            proofs = tokens[QUERY_ID]
            if (not isinstance(proofs, list) or len(proofs) != 1 or
                    not isinstance(proofs[0], str) or not 1 <= len(proofs[0]) <= self.MAX_PROOF or
                    not re.fullmatch(r'[A-Za-z0-9_-]+', proofs[0])):
                raise AgeError('invalid presentation proof')
            # Keep the original bytes opaque. This endpoint checks issuer
            # trust/signature/digests/time, but the prior session path is what
            # checked device signature, nonce and response URI binding.
            body = urlencode({'device_response': proofs[0], 'issuer_chain': self.issuer_chain}).encode()
            status, raw = self._exchange('POST', '/utilities/validations/msoMdoc/deviceResponse',
                                         body, 'application/x-www-form-urlencoded')
            if status != 200:
                raise AgeError('verifier rejected document')
            documents = _json(raw)
            if not isinstance(documents, list) or len(documents) != 1:
                raise AgeError('unexpected document set')
            document = documents[0]
            if (not isinstance(document, dict) or set(document) != {'docType', 'attributes'} or
                    document['docType'] != AGE_DOCTYPE or not isinstance(document['attributes'], dict) or
                    set(document['attributes']) != {AGE_DOCTYPE}):
                raise AgeError('unexpected age document')
            attributes = document['attributes'][AGE_DOCTYPE]
            if (not isinstance(attributes, dict) or set(attributes) != {'age_over_18'} or
                    type(attributes['age_over_18']) is not bool):
                raise AgeError('unexpected age attributes')
            if self.clock() >= transaction.expires:
                raise AgeError('verifier session expired')
            return attributes['age_over_18']
        finally:
            with self.lock:
                if pending and self.clock() < transaction.expires:
                    transaction.polling = False
                else:
                    self.transactions.pop(backend_id, None)

    def dc_begin(self, origin, nonce):
        raise AgeError('Digital Credentials API backend unavailable')

    def dc_complete(self, backend_id, nonce, credential):
        raise AgeError('Digital Credentials API backend unavailable')
