"""OpenBao Transit client: no encryption keys or decrypted profile cache in the API."""
import base64
import hmac
import json
import re
import ssl
import threading
import time
from http_transport import configured_url, HTTPConnection, HTTPSConnection
from serve import private_file


class VaultUnavailable(RuntimeError):
    pass


class _TokenLease:
    """Renew only this service's periodic token; never authenticate as an operator."""
    def __init__(self, vault, policy):
        self.vault, self.policy = vault, policy
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.token, self.renew_at, self.deadline = None, 0, 0
        self.failed_token, self.retry_at, self.failures = None, 0, 0
        self.current()
        self.worker = threading.Thread(target=self.run, name='openbao-token-lease', daemon=True)
        self.worker.start()

    @staticmethod
    def duration(value):
        if type(value) is not int or not 1 <= value <= 3600:
            raise ValueError('lease duration')
        return value

    def current(self):
        with self.lock:
            if self.stop.is_set(): raise VaultUnavailable('key service unavailable')
            try:
                token = self.vault.read_token()
            except Exception:
                self.token, self.renew_at, self.deadline = None, 0, 0
                raise VaultUnavailable('key service unavailable') from None
            # Repeated requests must not turn an unavailable/denied token into
            # unbounded network and audit traffic. A different file value can
            # still be checked immediately by this same running process.
            if token == self.failed_token and time.monotonic() < self.retry_at:
                raise VaultUnavailable('key service unavailable')
            try:
                if token != self.token or time.monotonic() >= self.renew_at:
                    info = self.vault.exchange(token, 'auth/token/lookup-self')['data']
                    period = self.duration(info.get('period'))
                    self.duration(info.get('ttl'))
                    if (info.get('policies') != [self.policy] or info.get('identity_policies', [])
                            or info.get('renewable') is not True or info.get('orphan') is not True
                            or info.get('num_uses') != 0 or info.get('type') != 'service'
                            or not hmac.compare_digest(info.get('id', ''), token)):
                        raise ValueError('service token scope')
                    started = time.monotonic()
                    auth = self.vault.exchange(token, 'auth/token/renew-self', {})['auth']
                    ttl = self.duration(auth.get('lease_duration'))
                    if (ttl > period or auth.get('renewable') is not True
                            or auth.get('policies') != [self.policy]
                            or not hmac.compare_digest(auth.get('client_token', ''), token)):
                        raise ValueError('renewed token scope')
                    self.token, self.renew_at, self.deadline = token, started+ttl/2, started+ttl
                if time.monotonic() >= self.deadline: raise ValueError('expired lease')
                self.failed_token, self.retry_at, self.failures = None, 0, 0
                return token
            except Exception:
                # An old still-live token is not a fallback after a failed renewal.
                self.token, self.renew_at, self.deadline = None, 0, 0
                self.failures = min(5, self.failures+1) if token == self.failed_token else 0
                self.failed_token = token
                self.retry_at = time.monotonic()+min(30, 2**self.failures)
                raise VaultUnavailable('key service unavailable') from None

    def run(self):
        while not self.stop.wait(.25):
            try: self.current()
            except VaultUnavailable: pass

    def close(self):
        self.stop.set()
        self.worker.join(8)
        with self.lock:
            self.token, self.renew_at, self.deadline = None, 0, 0
            self.failed_token, self.retry_at, self.failures = None, 0, 0


class TransitVault:
    def __init__(self, address, token_file, ca_file=None, *, local_test=False):
        url = configured_url(address)
        if (url.path or url.query or url.fragment or url.username or url.password or not url.hostname
                or (url.scheme != 'https' and not (local_test and url.scheme == 'http' and url.hostname in ('127.0.0.1', 'localhost')))):
            raise ValueError('OpenBao requires an HTTPS origin')
        self.url, self.token_file = url, token_file
        self.tls_context = ssl.create_default_context(cafile=ca_file) if url.scheme == 'https' else None
        self.lease = None

    def read_token(self):
        token = private_file(self.token_file).decode('ascii').strip()
        if not re.fullmatch('[A-Za-z0-9_.-]{16,2048}', token): raise ValueError('token')
        return token

    def start_renewal(self, policy):
        if policy not in ('enroller', 'wallet'): raise ValueError('runtime token policy')
        if self.lease is not None: raise ValueError('token renewal already started')
        self.lease = _TokenLease(self, policy)

    def close(self):
        if self.lease is not None: self.lease.close()

    def exchange(self, token, path, value=None):
        connection = None
        try:
            connection = (HTTPSConnection(self.url.hostname, self.url.port, timeout=3, context=self.tls_context)
                if self.tls_context else HTTPConnection(self.url.hostname, self.url.port, timeout=3))
            data = json.dumps(value, allow_nan=False, separators=(',', ':')).encode() if value is not None else None
            if data is not None and len(data) > 65536: raise ValueError('size')
            connection.request('POST' if data is not None else 'GET', '/v1/'+path, body=data,
                headers={'X-Vault-Token': token, 'Content-Type': 'application/json'})
            response = connection.getresponse()
            raw = response.read(131073)
            if response.status != 200 or len(raw) > 131072: raise ValueError('response')
            return json.loads(raw)
        except Exception:
            raise VaultUnavailable('key service unavailable') from None
        finally:
            if connection is not None: connection.close()

    def request(self, path, value=None):
        try:
            token = self.lease.current() if self.lease is not None else self.read_token()
            return self.exchange(token, path, value)['data']
        except Exception:
            raise VaultUnavailable('key service unavailable') from None

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

    def reference(self, domain, value):
        if not isinstance(domain, str) or not isinstance(value, str):
            raise ValueError('reference format')
        if re.fullmatch('security-code-v1:[a-f0-9]{64}', domain):
            valid = re.fullmatch('[0-9]{6}', value)
        elif re.fullmatch(r'registry-person-v1:[a-z][a-z0-9-]{2,63}:(personnummer|samordningsnummer)', domain):
            valid = re.fullmatch('[0-9]{12}', value)
        elif re.fullmatch(r'registry-person-v1:[a-z][a-z0-9-]{2,63}:synthetic', domain):
            valid = re.fullmatch('TEST-[A-Z0-9-]{1,60}', value)
        elif re.fullmatch(r'registry-evidence-v1:[a-z][a-z0-9-]{2,63}', domain):
            valid = re.fullmatch('[A-Za-z0-9_-]{8,128}', value)
        else:
            valid = None
        if not valid:
            raise ValueError('reference format')
        data = (domain+'\0'+value).encode()
        return self.request('transit/hmac/openid-index/sha2-256',
            {'input': base64.b64encode(data).decode(), 'key_version': 1})['hmac']

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
