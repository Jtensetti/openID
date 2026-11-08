"""Age-only RP sessions, separate from the identity registry and credential issuer.

The configured backend verifies credentials. Browser data is never an age verdict.
This single-process integration keeps short-lived state in memory and fails closed
on restart. It has no subject, device identifier, birth date or identity database.
"""
from dataclasses import dataclass
import hashlib
import re
import secrets
import threading
import time
from urllib.parse import urlsplit


class AgeError(ValueError):
    """Deliberately contains no backend response, proof or identifying data."""


def site_origin(value):
    if not isinstance(value, str) or not value.isascii() or len(value) > 255:
        raise AgeError('invalid site origin')
    if any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise AgeError('invalid site origin')
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError:
        raise AgeError('invalid site origin') from None
    if (url.scheme != 'https' or url.username or url.password or url.path or
            url.query or url.fragment or not url.hostname or
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', url.hostname) or
            '.' not in url.hostname or not re.fullmatch(r'[a-z][a-z0-9-]*', url.hostname.rsplit('.', 1)[1]) or
            any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-')
                for label in url.hostname.split('.')) or
            (port is not None and (port == 443 or not 1 <= port <= 65535))):
        raise AgeError('invalid site origin')
    canonical = 'https://' + url.hostname + ((':' + str(port)) if port is not None else '')
    if value != canonical:
        raise AgeError('site origin must be canonical')
    return value


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', value):
        raise AgeError('invalid site configuration')
    return value


@dataclass(frozen=True)
class Site:
    customer: str
    id: str
    origin: str
    api_key_sha256: str

    def __post_init__(self):
        identifier(self.customer)
        identifier(self.id)
        site_origin(self.origin)
        if not isinstance(self.api_key_sha256, str) or not re.fullmatch('[a-f0-9]{64}', self.api_key_sha256):
            raise AgeError('invalid site key hash')


class Sites:
    """A commercial customer may own several separately authenticated site origins."""
    def __init__(self, sites):
        if not sites or len(sites) > 1000 or any(not isinstance(site, Site) for site in sites):
            raise AgeError('invalid site configuration')
        self.sites = {site.id: site for site in sites}
        if (len(self.sites) != len(sites) or len({s.origin for s in sites}) != len(sites)
                or len({s.api_key_sha256 for s in sites}) != len(sites)):
            raise AgeError('sites must have distinct IDs, origins and keys')

    def authenticate(self, ident, key):
        if not isinstance(ident, str) or not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43,128}', key):
            raise AgeError('site authentication failed')
        site = self.sites.get(ident)
        digest = hashlib.sha256(key.encode()).hexdigest()
        expected = site.api_key_sha256 if site else '0' * 64
        if not secrets.compare_digest(expected, digest) or site is None:
            raise AgeError('site authentication failed')
        return site


@dataclass
class Session:
    site: str
    binding_hash: str
    nonce: str
    method: str
    expires: float
    state: str = 'STARTING'
    backend_id: str | None = None


class AgeGateway:
    """Only the RP's authenticated server can create/consume a session.

    The RP keeps binding in its own browser session, never in a URL or wallet
    request. The browser receives only presentation. A VERIFIED UI result is
    informational; consume() is the one-use authorization decision.
    """
    TTL = 120
    MAX_SESSIONS = 256
    MAX_PER_SITE = 32

    def __init__(self, sites, backend, clock=time.monotonic):
        self.sites, self.backend, self.clock = sites, backend, clock
        self.sessions = {}
        self.lock = threading.RLock()

    def start(self, site_id, key, origin, method):
        site = self.sites.authenticate(site_id, key)
        if origin != site.origin:
            raise AgeError('site origin mismatch')
        if method not in ('openid4vp', 'dc_api'):
            raise AgeError('unsupported presentation method')
        if method == 'dc_api' and not getattr(self.backend, 'supports_dc_api', False):
            raise AgeError('Digital Credentials API backend unavailable')
        with self.lock:
            # Expired transactions have no reusable authorization after eviction.
            self.sessions = {k: v for k, v in self.sessions.items() if v.expires > self.clock()}
            if (len(self.sessions) >= self.MAX_SESSIONS or
                    sum(v.site == site.id for v in self.sessions.values()) >= self.MAX_PER_SITE):
                raise AgeError('session capacity reached')
            ident, binding, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            session = Session(site.id, hashlib.sha256(binding.encode()).hexdigest(), nonce,
                              method, self.clock() + self.TTL)
            self.sessions[ident] = session
        try:
            if method == 'dc_api':
                result = self.backend.dc_begin(site.origin, nonce)
                presentation = {'method': method, 'requests': result['requests']}
            else:
                result = self.backend.begin(site.origin, nonce)
                presentation = {'method': method, 'authorizationRequest': result['authorization_request']}
            backend_id = result['backend_id']
            if not isinstance(backend_id, str) or not 1 <= len(backend_id) <= 256:
                raise AgeError('invalid backend session')
            with self.lock:
                if self.clock() >= session.expires or session.state != 'STARTING':
                    raise AgeError('session unavailable')
                session.backend_id, session.state = backend_id, 'PENDING'
                remaining = int(session.expires - self.clock())
                if remaining < 1:
                    raise AgeError('session unavailable')
            return {'id': ident, 'binding': binding, 'expiresIn': remaining, 'presentation': presentation}
        except Exception:
            with self.lock:
                session.state = 'FAILED'
                # No binding has been returned, so this entry cannot be polled.
                if self.sessions.get(ident) is session:
                    del self.sessions[ident]
            raise AgeError('could not start presentation') from None

    def _session(self, site_id, key, ident, binding):
        site = self.sites.authenticate(site_id, key)
        if (not isinstance(ident, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', ident) or
                not isinstance(binding, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', binding)):
            raise AgeError('session binding failed')
        session = self.sessions.get(ident)
        digest = hashlib.sha256(binding.encode()).hexdigest()
        if session is None or session.site != site.id or not secrets.compare_digest(session.binding_hash, digest):
            raise AgeError('session binding failed')
        if self.clock() >= session.expires:
            session.state = 'EXPIRED'
        return session

    def poll(self, site_id, key, ident, binding):
        with self.lock:
            session = self._session(site_id, key, ident, binding)
            if session.state != 'PENDING' or session.method == 'dc_api':
                return {'state': session.state}
            session.state = 'VERIFYING'
        return self._verify(session, lambda: self.backend.poll(session.backend_id, session.nonce))

    def complete(self, site_id, key, ident, binding, credential):
        with self.lock:
            session = self._session(site_id, key, ident, binding)
            if session.method != 'dc_api' or session.state != 'PENDING':
                raise AgeError('session unavailable')
            # Mark before validation/network I/O: concurrent completions cannot race.
            session.state = 'VERIFYING'
        return self._verify(session, lambda: self.backend.dc_complete(session.backend_id, session.nonce, credential),
                            allow_pending=False)

    def _verify(self, session, operation, allow_pending=True):
        try:
            result = operation()
            if type(result) is not bool and not (allow_pending and result is None):
                raise AgeError('invalid verifier result')
            next_state = 'PENDING' if result is None else ('VERIFIED' if result else 'DENIED')
        except Exception:
            next_state = 'FAILED'
        with self.lock:
            if self.clock() >= session.expires:
                session.state = 'EXPIRED'
            elif session.state == 'VERIFYING':
                session.state = next_state
            # Cancellation wins even if an in-flight verification succeeds.
            return {'state': session.state}

    def consume(self, site_id, key, ident, binding):
        with self.lock:
            session = self._session(site_id, key, ident, binding)
            if session.state != 'VERIFIED':
                raise AgeError('no unconsumed age approval')
            session.state = 'CONSUMED'
            return {'age_over_18': True}

    def cancel(self, site_id, key, ident, binding):
        with self.lock:
            session = self._session(site_id, key, ident, binding)
            if session.state in ('STARTING', 'PENDING', 'VERIFYING', 'VERIFIED'):
                session.state = 'CANCELLED'
            return {'state': session.state}
