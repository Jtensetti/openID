"""Private mdoc/DC API interop backend with exact document-signer pins.

No EU trusted-list discovery or production trust is implied. Cryptography is
performed by the locked OWF mdoc/HPKE worker, never by browser assertions.
"""
import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import threading
import time

from age_backend import _json, _nonce, _issuer_certificates
from age_gateway import AgeError, site_origin
from bounded_process import run_bounded


class MdocDcBackend:
    supports_dc_api = True
    TTL = 120
    MAX_SESSIONS = 64

    def __init__(self, signer_pem, *, openid_backend=None, clock=time.monotonic):
        import re
        import ssl
        _issuer_certificates(signer_pem)
        self.signer_pins = [ssl.PEM_cert_to_DER_cert(pem) for pem in re.findall(
            r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', signer_pem, re.S)]
        self.openid_backend, self.clock = openid_backend, clock
        self.transactions = {}
        self.lock = threading.RLock()
        self.workers = threading.BoundedSemaphore(4)
        self.node = shutil.which('node')
        if self.node is None:
            raise AgeError('mdoc worker unavailable')

    def _run(self, value):
        if not self.workers.acquire(blocking=False):
            raise AgeError('mdoc worker capacity reached')
        try:
            raw = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
            result = run_bounded([self.node, '--max-old-space-size=128',
                                  str(Path(__file__).with_name('age_wallet') / 'worker.mjs')],
                                 input=raw, timeout=10, max_input=256 * 1024, max_output=128 * 1024,
                                 env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
            if result.returncode != 0:
                raise AgeError('mdoc verification failed')
            return _json(result.stdout)
        except Exception:
            raise AgeError('mdoc verification failed') from None
        finally:
            self.workers.release()

    def dc_begin(self, origin, nonce):
        site_origin(origin)
        _nonce(nonce)
        expires = self.clock() + self.TTL
        ident = secrets.token_urlsafe(32)
        with self.lock:
            self.transactions = {key: value for key, value in self.transactions.items()
                                 if value['expires'] > self.clock()}
            if len(self.transactions) >= self.MAX_SESSIONS:
                raise AgeError('mdoc session capacity reached')
            # Reserve before starting a worker, including concurrent requests.
            self.transactions[ident] = {'expires': expires, 'nonce': nonce, 'origin': origin, 'ready': False}
        try:
            result = self._run({'operation': 'begin', 'origin': origin, 'nonce': nonce})
            if not isinstance(result, dict) or set(result) != {'request', 'recipientKey'}:
                raise AgeError('invalid mdoc worker result')
            with self.lock:
                if self.clock() >= expires or ident not in self.transactions:
                    raise AgeError('mdoc session expired')
                self.transactions[ident].update(result, ready=True)
            return {'backend_id': ident, 'requests': [{'protocol': 'org-iso-mdoc', 'data': result['request']}]}
        except Exception:
            with self.lock:
                self.transactions.pop(ident, None)
            raise AgeError('could not start mdoc session') from None

    def dc_complete(self, backend_id, nonce, credential):
        _nonce(nonce)
        if not isinstance(backend_id, str):
            raise AgeError('mdoc session unavailable')
        with self.lock:
            tx = self.transactions.get(backend_id)
            if (tx is None or not tx['ready'] or self.clock() >= tx['expires'] or
                    not secrets.compare_digest(tx['nonce'], nonce)):
                raise AgeError('mdoc session unavailable')
            # Consume before cryptography. A failed, interrupted, or parallel
            # attempt cannot reuse the verifier's ephemeral key/session.
            del self.transactions[backend_id]
        result = self._run({'operation': 'verify', 'credential': credential,
                            'request': tx['request'], 'recipientKey': tx['recipientKey'],
                            'siteOrigin': tx['origin'],
                            'signerPins': [base64.b64encode(pin).decode() for pin in self.signer_pins]})
        if (self.clock() >= tx['expires'] or not isinstance(result, dict) or
                set(result) != {'age_over_18'} or type(result['age_over_18']) is not bool):
            raise AgeError('mdoc verification failed')
        return result['age_over_18']

    def begin(self, origin, nonce):
        if self.openid_backend is None:
            raise AgeError('OpenID4VP backend unavailable')
        return self.openid_backend.begin(origin, nonce)

    def poll(self, backend_id, nonce):
        if self.openid_backend is None:
            raise AgeError('OpenID4VP backend unavailable')
        return self.openid_backend.poll(backend_id, nonce)
