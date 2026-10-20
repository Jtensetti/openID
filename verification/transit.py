"""OpenBao Transit client: no encryption keys or decrypted profile cache in the API."""
import base64
import http.client
import json
import re
import ssl
from urllib.parse import urlsplit
from serve import private_file


class VaultUnavailable(RuntimeError):
    pass


class TransitVault:
    def __init__(self, address, token_file, ca_file=None, *, local_test=False):
        url = urlsplit(address)
        if (url.path or url.query or url.fragment or url.username or url.password or not url.hostname
                or (url.scheme != 'https' and not (local_test and url.scheme == 'http' and url.hostname in ('127.0.0.1', 'localhost')))):
            raise ValueError('OpenBao requires an HTTPS origin')
        self.url, self.token_file = url, token_file
        self.tls_context = ssl.create_default_context(cafile=ca_file) if url.scheme == 'https' else None

    def request(self, path, value=None):
        connection = None
        try:
            token = private_file(self.token_file).decode('ascii').strip()
            if not re.fullmatch('[A-Za-z0-9_.-]{16,2048}', token): raise ValueError('token')
            connection = (http.client.HTTPSConnection(self.url.hostname, self.url.port, timeout=3, context=self.tls_context)
                if self.tls_context else http.client.HTTPConnection(self.url.hostname, self.url.port, timeout=3))
            data = json.dumps(value, allow_nan=False, separators=(',', ':')).encode() if value is not None else None
            if data is not None and len(data) > 65536: raise ValueError('size')
            connection.request('POST' if data is not None else 'GET', '/v1/'+path, body=data,
                headers={'X-Vault-Token': token, 'Content-Type': 'application/json'})
            response = connection.getresponse()
            raw = response.read(131073)
            if response.status != 200 or len(raw) > 131072: raise ValueError('response')
            return json.loads(raw)['data']
        except Exception:
            raise VaultUnavailable('key service unavailable') from None
        finally:
            if connection is not None: connection.close()

    def key(self, create=False):
        # Reading key metadata proves neither unsealed status nor usable cryptographic permissions.
        # A small encrypt/HMAC operation checks the service without persisting sensitive data.
        self.request('transit/hmac/openid-index/sha2-256', {'input': 'cmVhZGluZXNz', 'key_version': 1})

    @staticmethod
    def context(credential, person):
        return base64.b64encode(f'openid-profile-v1:{credential}:{person}'.encode()).decode()

    def document_tag(self, document):
        identity = document.identity
        data = 'document-v1\0'+json.dumps([identity[k] for k in ('issuingState', 'documentNumber', 'birthDateMrz')], separators=(',', ':'))
        # This stable blind index has its own key and lifecycle; profile-key rotation never changes identity.
        return self.request('transit/hmac/openid-index/sha2-256',
            {'input': base64.b64encode(data.encode()).decode(), 'key_version': 1})['hmac']

    def crypt(self, operation, credential, person, value):
        context = self.context(credential, person)
        if operation == 'seal':
            plaintext = base64.b64encode(json.dumps(value, allow_nan=False, separators=(',', ':')).encode()).decode()
            result = self.request('transit/encrypt/openid-profile', {'plaintext': plaintext, 'context': context})
            return {'transit': result['ciphertext']}
        if operation != 'open' or not isinstance(value, dict) or set(value) != {'transit'}: raise ValueError('profile format')
        result = self.request('transit/decrypt/openid-profile', {'ciphertext': value['transit'], 'context': context})
        return json.loads(base64.b64decode(result['plaintext'], validate=True))

    def rewrap(self, credential, person, value):
        if not isinstance(value, dict) or set(value) != {'transit'}: raise ValueError('profile format')
        result = self.request('transit/rewrap/openid-profile',
            {'ciphertext': value['transit'], 'context': self.context(credential, person)})
        return {'transit': result['ciphertext']}
