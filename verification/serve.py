"""Validated configuration and Gunicorn entry point for one private pilot node."""
import argparse
import base64
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl
import stat
import socket
import threading
import subprocess
import sys

from runtime import Runtime, validate_origin

ROOT = Path(__file__).resolve().parent


def private_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('Secret files must be regular files with mode 0600')
        data = stream.read(65537)
    if not 0 < len(data) <= 65536: raise ValueError('Secret file size')
    return data


def score_frames(portrait, frames):
    payload = json.dumps({'portrait': base64.b64encode(portrait).decode(),
        'frames': [base64.b64encode(frame).decode() for frame in frames]}).encode()
    try:
        result = subprocess.run([sys.executable, str(ROOT/'biometric_worker.py')], input=payload,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=45, check=False)
    except subprocess.TimeoutExpired:
        print(json.dumps({'event': 'biometric_failure', 'stage': 'WORKER', 'reason': 'TIMEOUT'}), file=sys.stderr, flush=True)
        raise
    if result.returncode or len(result.stdout) > 4096:
        from biometric_worker import STAGES, REASONS, CameraImageRejected
        diagnostic = {}
        if len(result.stdout) <= 4096:
            try: diagnostic = json.loads(result.stdout)
            except (ValueError, TypeError): pass
        if not isinstance(diagnostic, dict): diagnostic = {}
        stage = diagnostic.get('stage')
        reason = diagnostic.get('reason')
        stage = stage if isinstance(stage, str) and stage in STAGES else 'WORKER'
        reason = reason if isinstance(reason, str) and reason in REASONS else 'FAILED'
        print(json.dumps({'event': 'biometric_failure', 'stage': stage, 'reason': reason}), file=sys.stderr, flush=True)
        if stage in {'CAMERA_FACE_1', 'CAMERA_FACE_2', 'CAMERA_FACE_3'} and reason in {'IMAGE_REJECTED', 'IMAGE_SIZE_REJECTED', 'EXACTLY_ONE_FACE_REQUIRED', 'FACE_QUALITY_REJECTED'}:
            raise CameraImageRejected(int(stage[-1]))
        if stage in {'MODEL_LOAD', 'WORKER'}: raise OSError('biometric worker unavailable')
        raise ValueError('biometric analysis rejected')
    data = json.loads(result.stdout)
    return data['face'], data['pad']


def load_config(path):
    value = json.loads(Path(path).read_text())
    required = {'bind', 'origin', 'team', 'bundle', 'developmentAttestation', 'tlsCert', 'tlsKey', 'csca', 'database', 'pairingFile'}
    if not required <= set(value) or set(value) - required - {'listenPort', 'publicEnrollment'}:
        raise ValueError('Configuration fields do not match the example')
    if type(value.get('publicEnrollment', False)) is not bool: raise ValueError('Public enrollment flag')
    if value.get('publicEnrollment', False) and (value['developmentAttestation'] is not False or value['origin'] != 'https://api.openid.tensetti.io'):
        raise ValueError('Public beta requires production App Attest and the canonical origin')
    origin = validate_origin(value['origin'])
    address = ipaddress.ip_address(value['bind'])
    if address.is_unspecified or not address.is_private or address.is_multicast:
        raise ValueError('Bind to an explicit loopback or private network address')
    import re
    if not re.fullmatch('[A-Z0-9]{10}', value['team']): raise ValueError('Apple Team ID')
    if not re.fullmatch('[A-Za-z0-9.-]{3,128}', value['bundle']): raise ValueError('Bundle ID')
    if type(value['developmentAttestation']) is not bool: raise ValueError('Attestation environment')
    for key in ('tlsCert', 'tlsKey', 'csca', 'database', 'pairingFile'):
        if not Path(value[key]).is_absolute(): raise ValueError('Absolute paths required')
    for key in ('tlsCert', 'csca'):
        if not Path(value[key]).is_file(): raise ValueError('Certificate file missing')
    private_file(value['tlsKey'])
    token = private_file(value['pairingFile']).decode('ascii').strip()
    if not re.fullmatch('[A-Za-z0-9_-]{43,128}', token): raise ValueError('Pairing file format')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(value['tlsCert'], value['tlsKey'])
    jar = ROOT.parent/'prototype/target/isolated-eid-lab.jar'
    if not jar.is_file(): raise ValueError('Build the verifier JAR first')
    listen_port = value.get('listenPort', origin.port)
    if type(listen_port) is not int or not 1024 <= listen_port <= 65535:
        raise ValueError('Explicit unprivileged listener port required')
    if 'listenPort' in value and not address.is_loopback:
        raise ValueError('Separate ingress origin requires a loopback listener')
    value['port'], value['pairing'], value['jar'] = listen_port, token, str(jar)
    return value


class Lease:
    def __init__(self, database):
        path = Path(database).parent
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink() or path.stat().st_mode & 0o077: raise ValueError('Private database directory required')
        self.fd = os.open(path/'runtime.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try: fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.fd)
            raise ValueError('Only one runtime may use this database') from None

    def close(self):
        # Do not explicitly unlock: the worker inherits this lease from its master.
        os.close(self.fd)


def open_wallet(database, origin):
    from revocation import configured_wallet
    path = Path(database)
    marker = path.with_suffix('.initialized')
    if marker.exists() or marker.is_symlink():
        if private_file(marker) != b'1\n' or not path.is_file():
            raise ValueError('Previously initialized database is missing')
    wallet = configured_wallet(path, origin)
    wallet.health()
    try: fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError: pass
    else:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(b'1\n'); stream.flush(); os.fsync(stream.fileno())
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    return wallet


def bounded_worker():
    from gunicorn.workers.gthread import ThreadWorker
    class Worker(ThreadWorker):
        header_timer = threading.local()

        def handle(self, connection):
            def interrupt():
                try: connection.sock.shutdown(socket.SHUT_RDWR)
                except OSError: pass
            timer = threading.Timer(10, interrupt)
            timer.daemon = True
            self.header_timer.current = timer
            timer.start()
            try: return super().handle(connection)
            finally: timer.cancel()

        def handle_error(self, req, client, addr, exc):
            from gunicorn import util
            self.log.warning('HTTP request rejected')
            try: util.write_error(client, 400, 'Bad Request', 'Request rejected')
            except OSError: pass

        def handle_exit(self, sig, frame):
            app = getattr(self, 'wsgi', None)
            if hasattr(app, 'drain'): app.drain()
            super().handle_exit(sig, frame)

    return Worker


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    config = load_config(args.config)
    # Reject overrides which could split in-memory NFC sessions across workers.
    if os.environ.get('GUNICORN_CMD_ARGS'): raise ValueError('GUNICORN_CMD_ARGS is not supported')
    subprocess.run([sys.executable, str(ROOT/'biometric_worker.py'), '--check'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=60)
    lease = Lease(config['database'])
    wallet = open_wallet(config['database'], config['origin'])
    if args.check:
        lease.close()
        print('Configuration, models and database checked. Physical iPhone verification is separate.')
        return
    from gunicorn.app.base import BaseApplication

    Worker = bounded_worker()

    class Application(BaseApplication):
        def load_config(self):
            bind = f"[{config['bind']}]" if ':' in config['bind'] else config['bind']
            settings = {'bind': f"{bind}:{config['port']}", 'workers': 1, 'threads': 16,
                'worker_class': Worker, 'worker_connections': 32, 'backlog': 32,
                'timeout': 90, 'graceful_timeout': 60, 'keepalive': 2,
                'limit_request_line': 1024, 'limit_request_fields': 32, 'limit_request_field_size': 4096,
                'certfile': config['tlsCert'], 'keyfile': config['tlsKey'],
                'forwarded_allow_ips': '', 'forwarder_headers': '', 'secure_scheme_headers': {},
                'control_socket_disable': True, 'accesslog': None, 'errorlog': '-',
                'umask': 0o077, 'preload_app': False}
            for key, value in settings.items(): self.cfg.set(key, value)
            self.cfg.set('worker_exit', close_worker)
            self.cfg.set('pre_request', reject_duplicate_headers)

        def load(self):
            from crypto_runtime import CryptoRuntime
            crypto = CryptoRuntime()
            wallet.crypto = crypto.device
            wallet.vault.runner = crypto.profile
            from native import NativeSessions, AppAttest
            from chip import ChipProcess
            from server import verify_document
            command = ['java', '-Xmx128m', '-jar', config['jar'], 'verify-passport', config['csca']]
            native = NativeSessions(AppAttest(config['team'], config['bundle'], config['developmentAttestation']),
                lambda data: verify_document(command, data), None, None, wallet=wallet,
                chip_factory=lambda data: ChipProcess([*command[:-2], 'authenticate-chip', command[-1]], data),
                biometrics=score_frames)
            app = Runtime(native, wallet, config['origin'], config['pairing'], public_enrollment=config.get('publicEnrollment', False))
            app.crypto = crypto
            return app

    try: Application().run()
    finally: lease.close()


def close_worker(server, worker):
    app = getattr(worker, 'wsgi', None)
    if app is not None:
        if app.native is not None: app.native.close()
        if hasattr(app.wallet, 'close'): app.wallet.close()
        if hasattr(app, 'crypto'): app.crypto.close()


def reject_duplicate_headers(worker, req):
    from gunicorn.http.errors import InvalidHeader
    timer = getattr(getattr(worker, 'header_timer', None), 'current', None)
    if timer: timer.cancel()
    seen = set()
    for key, value in req.headers:
        key = key.lower()
        if key in seen: raise InvalidHeader('duplicate header')
        seen.add(key)
    # Do not accept proxy interpretation, chunked bodies, or Expect negotiation.
    if seen & {'forwarded', 'transfer-encoding', 'expect'} or any(k.startswith('x-forwarded-') for k in seen):
        raise InvalidHeader('unsupported header')


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, subprocess.SubprocessError):
        print('Startup rejected. Check configuration, private files, certificates, dependencies and models.', file=sys.stderr)
        raise SystemExit(2)
