"""Bounded WSGI API for the private iPhone pilot."""
from collections import Counter, OrderedDict
from contextlib import contextmanager
from http import HTTPStatus
import json
import secrets
import socket
import sqlite3
import subprocess
import threading
import time
from urllib.parse import urlsplit

from native import unique_object
from biometric_worker import CameraImageRejected
from wallet import BiometricAttemptLimit, SecurityCodeError, EnrollmentQuarantine
from ingress_client import ClientAddresses

NATIVE_ROUTES = {
    '/native/start': ('start', 1024),
    '/native/attest': ('register', 65536),
    '/native/chip/start': ('begin_chip', 4_100_000),
    '/native/chip/step': ('chip_step', 16384),
    '/native/cancel': ('cancel', 1024),
    '/native/finish': ('finish', 11_000_000),
}
WALLET_ROUTES = {'/wallet/challenge': 'challenge', '/wallet/execute': 'execute'}


def validate_origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment):
        raise ValueError('Origin must be HTTPS without credentials, path or query')
    if parsed.port is not None and parsed.port != 443 and not 1024 <= parsed.port <= 65535:
        raise ValueError('HTTPS or unprivileged port required')
    return parsed


class RateLimit:
    """Bounded token buckets. Unknown clients cannot evict an existing bucket."""
    def __init__(self, rate=10, burst=160, capacity=1024, clock=time.monotonic):
        self.rate, self.burst, self.capacity, self.clock = rate, burst, capacity, clock
        self.entries = OrderedDict()
        self.lock = threading.Lock()

    def allow(self, key):
        with self.lock:
            now = self.clock()
            while self.entries and next(iter(self.entries.values()))[1] + 300 < now:
                self.entries.popitem(last=False)
            if key not in self.entries and len(self.entries) >= self.capacity:
                return False
            tokens, last = self.entries.pop(key, (self.burst, now))
            tokens = min(self.burst, tokens + max(0, now-last)*self.rate)
            allowed = tokens >= 1
            self.entries[key] = (tokens-1 if allowed else tokens, now)
            return allowed


class Runtime:
    def __init__(self, native, wallet, origin, pairing, body_timeout=15, metrics_token=None, role='combined', public_enrollment=False, trusted_proxy=None, new_registrations_enabled=False):
        self.authority = validate_origin(origin).netloc
        if not isinstance(pairing, str) or len(pairing) < 43 or not pairing.isascii():
            raise ValueError('Pairing secret must contain at least 43 ASCII characters')
        if type(public_enrollment) is not bool: raise ValueError('public enrollment flag')
        if type(new_registrations_enabled) is not bool: raise ValueError('new registration flag')
        self.public_enrollment = public_enrollment
        self.new_registrations_enabled = new_registrations_enabled
        self.client_addresses = ClientAddresses(trusted_proxy)
        self.native, self.wallet, self.origin, self.pairing = native, wallet, origin, pairing
        if role not in ('combined', 'wallet', 'proofing'): raise ValueError('runtime role')
        if metrics_token is not None and (len(metrics_token) < 43 or not metrics_token.isascii() or metrics_token == pairing):
            raise ValueError('Separate metrics credential required')
        self.metrics_token, self.role = metrics_token, role
        self.body_timeout = body_timeout
        self.native_slots = threading.BoundedSemaphore(1)
        self.wallet_slots = threading.BoundedSemaphore(8)
        self.rate = RateLimit()
        self.enrollment_rate = RateLimit(rate=1/6, burst=5)
        self.draining = threading.Event()
        self.counters = Counter()
        self.metrics_lock = threading.Lock()
        self.started = time.monotonic()
        self.latency = Counter()

    def drain(self):
        self.draining.set()

    @contextmanager
    def body_deadline(self, environ):
        connection = environ.get('gunicorn.socket')
        def interrupt():
            try: connection.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        timer = None
        if connection is not None:
            timer = threading.Timer(self.body_timeout, interrupt)
            timer.daemon = True
            timer.start()
        try:
            yield
        finally:
            if timer: timer.cancel()

    def ready(self):
        if self.draining.is_set():
            return False
        try:
            self.wallet.health()
            return True
        except (OSError, ValueError, RuntimeError, sqlite3.Error):
            return False

    def __call__(self, environ, start_response):
        started = time.monotonic()
        path = environ.get('PATH_INFO', '')
        route = path if path in NATIVE_ROUTES or path in WALLET_ROUTES or path in {
            '/health/live', '/health/ready', '/metrics'} else 'other'
        status, result = 500, {'error': 'UNAVAILABLE'}
        try:
            status, result = self.dispatch(environ)
        except Exception:
            # Never log request bodies, identifiers, exceptions or passport data.
            status, result = 503, {'error': 'UNAVAILABLE'}
        with self.metrics_lock:
            self.counters[(route, status)] += 1
            elapsed = time.monotonic()-started
            for boundary in (0.1, 0.5, 1, 5, 15, 60):
                if elapsed <= boundary: self.latency[(route, boundary)] += 1
        data = json.dumps(result, allow_nan=False, separators=(',', ':')).encode()
        headers = [('Content-Type', 'application/json'), ('Content-Length', str(len(data))),
            ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'),
            ('Referrer-Policy', 'no-referrer'), ('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'"),
            ('Strict-Transport-Security', 'max-age=31536000')]
        if status in (429, 503): headers.append(('Retry-After', '2'))
        start_response(f'{status} {HTTPStatus(status).phrase}', headers)
        print(json.dumps({'event': 'http', 'route': route, 'status': status,
            'durationMs': round((time.monotonic()-started)*1000)}), flush=True)
        return [data]

    def dispatch(self, env):
        method, path = env.get('REQUEST_METHOD'), env.get('PATH_INFO')
        if (env.get('HTTP_HOST') != self.authority or env.get('wsgi.url_scheme') != 'https'
                or env.get('QUERY_STRING') or any(k.startswith(('HTTP_X_FORWARDED_', 'HTTP_FORWARDED')) for k in env)):
            return 403, {'error': 'DENIED'}
        if method == 'GET' and path == '/health/live':
            return 200, {'status': 'LIVE'}
        if method == 'GET' and path == '/health/ready':
            return (200, {'status': 'READY'}) if self.ready() else (503, {'status': 'NOT_READY'})
        if method == 'GET' and path == '/metrics' and self.metrics_token is not None:
            token = env.get('HTTP_AUTHORIZATION', '')
            if not token.isascii() or not secrets.compare_digest(token, 'Bearer '+self.metrics_token):
                return 403, {'error': 'DENIED'}
            return self.metrics()
        token = env.get('HTTP_X_CSRF_TOKEN', '')
        paired = isinstance(token, str) and token.isascii() and secrets.compare_digest(token, self.pairing)
        # Public app admission does not authenticate identity: NativeSessions still requires
        # production App Attest, authenticated chip/face checks; wallet operations require signatures.
        public_api = self.public_enrollment and method == 'POST' and (path in NATIVE_ROUTES or path in WALLET_ROUTES)
        if not paired and not public_api:
            return 403, {'error': 'DENIED'}
        if method == 'GET' and path == '/metrics':
            return self.metrics()
        if method != 'POST': return 405, {'error': 'METHOD'}
        if env.get('HTTP_ORIGIN') != self.origin: return 403, {'error': 'DENIED'}
        if path not in NATIVE_ROUTES and path not in WALLET_ROUTES: return 404, {'error': 'NOT_FOUND'}
        if (self.role == 'wallet' and path in NATIVE_ROUTES) or (self.role == 'proofing' and path in WALLET_ROUTES):
            return 404, {'error': 'NOT_FOUND'}
        # Admission and permission to collect a new passport are separate decisions.
        # Keep cancellation and existing wallet/revocation operations available.
        # Reject before reading the body, including unfinished registration sessions.
        if path in NATIVE_ROUTES and path != '/native/cancel' and not self.new_registrations_enabled:
            return 503, {'error': 'REGISTRATION_PAUSED'}
        if self.draining.is_set(): return 503, {'error': 'DRAINING'}
        try: client = self.client_addresses.resolve(env)
        except ValueError: return 403, {'error': 'DENIED'}
        if not self.rate.allow(client): return 429, {'error': 'RATE_LIMIT'}
        if path == '/native/start' and not self.enrollment_rate.allow(client): return 429, {'error': 'RATE_LIMIT'}
        if env.get('CONTENT_TYPE') != 'application/json' or 'HTTP_TRANSFER_ENCODING' in env:
            return 415, {'error': 'CONTENT_TYPE'}
        length = env.get('CONTENT_LENGTH', '')
        if not isinstance(length, str) or not length.isascii() or not length.isdecimal():
            return 400, {'error': 'LENGTH'}
        length = int(length)
        limit = NATIVE_ROUTES[path][1] if path in NATIVE_ROUTES else 16384
        if not 0 < length <= limit: return 413, {'error': 'SIZE_LIMIT'}
        slots = self.native_slots if path in NATIVE_ROUTES else self.wallet_slots
        if not slots.acquire(blocking=False): return 503, {'error': 'CAPACITY'}
        try:
            with self.body_deadline(env):
                raw = env['wsgi.input'].read(length)
            if len(raw) != length: raise ValueError('truncated body')
            request = json.loads(raw, object_pairs_hook=unique_object,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite JSON')))
            if not isinstance(request, dict): raise ValueError('object required')
            if path == '/native/start' and request: raise ValueError('fields')
            target = self.native if path in NATIVE_ROUTES else self.wallet
            operation = NATIVE_ROUTES[path][0] if path in NATIVE_ROUTES else WALLET_ROUTES[path]
            return 200, getattr(target, operation)(request) if operation != 'start' else target.start()
        except CameraImageRejected as error:
            return 422, {'error': 'CAMERA_IMAGE_REJECTED', 'frame': error.frame}
        except EnrollmentQuarantine:
            return 503, {'error': 'REGISTRATION_PAUSED'}
        except BiometricAttemptLimit:
            return 403, {'error': 'ATTEMPT_LIMIT'}
        except SecurityCodeError as error:
            return 403, {'error': error.code, **({'attemptsRemaining': error.remaining} if error.remaining is not None else {})}
        except (ValueError, TypeError, KeyError):
            return 400, {'error': 'REJECTED'}
        except (OSError, subprocess.SubprocessError, sqlite3.Error):
            return 503, {'error': 'UNAVAILABLE'}
        finally:
            slots.release()

    def metrics(self):
        with self.metrics_lock:
            rows = [{'route': r, 'status': s, 'count': n} for (r, s), n in self.counters.items()]
            latency = [{'route': r, 'seconds': b, 'count': n} for (r, b), n in self.latency.items()]
        return 200, {'uptimeSeconds': int(time.monotonic()-self.started), 'requests': rows, 'latencyBuckets': latency}
