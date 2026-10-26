"""Validate and atomically install numbered CSCA CRLs; no network or scheduling.

Rollback protection compares with the installed, signed list under a process
lock. It does not protect against an administrator replacing both state and
software, or restoring the whole host to an older snapshot.
"""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time

MAX_BYTES = 5_000_000
MIN_REMAINING = 300


def read_regular(path, *, installed=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BYTES:
            raise ValueError('CRL file type or size')
        if installed and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
            raise ValueError('installed CRL ownership or permissions')
        value = stream.read(MAX_BYTES + 1)
    if not 0 < len(value) <= MAX_BYTES: raise ValueError('CRL file size')
    return value


class Verifier:
    def __init__(self, java, jar, trust):
        self.command = [str(java), '-Xmx128m', '-jar', str(jar), 'check-crls', str(trust)]

    def __call__(self, candidate, previous=None):
        payload = {'candidate':base64.b64encode(candidate).decode('ascii')}
        if previous is not None: payload['previous'] = base64.b64encode(previous).decode('ascii')
        result = subprocess.run(self.command, input=json.dumps(payload).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=30)
        if result.returncode or len(result.stdout) > 4096: raise ValueError('CRL verification rejected')
        value = json.loads(result.stdout)
        if (set(value) != {'status','sha256','issuers','validUntil'} or value['status'] != 'VERIFIED'
                or value['sha256'] != hashlib.sha256(candidate).hexdigest()
                or type(value['issuers']) is not int or not 1 <= value['issuers'] <= 32
                or type(value['validUntil']) is not int):
            raise ValueError('CRL verifier result')
        return value


@contextmanager
def update_lock(destination):
    parent = destination.parent
    info = parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or parent.resolve() != parent
            or info.st_uid != os.geteuid() or info.st_mode & 0o022):
        raise ValueError('CRL directory must be owned by updater and not writable by others')
    fd = os.open(str(destination)+'.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('CRL lock permissions')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def install(candidate_path, destination, verifier, *, initialize=False, clock=time.time):
    destination = Path(destination).absolute()
    candidate = read_regular(candidate_path)
    with update_lock(destination):
        try: previous = read_regular(destination, installed=True)
        except FileNotFoundError:
            if not initialize: raise ValueError('initial CRL installation requires --initialize')
            previous = None
        if initialize and previous is not None: raise ValueError('CRL already initialized')
        result = verifier(candidate, previous)
        if result['validUntil'] <= clock() + MIN_REMAINING: raise ValueError('CRL too close to expiry')
        if previous == candidate: return result | {'status':'UNCHANGED'}
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.crl-', delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(candidate); stream.flush(); os.fsync(stream.fileno())
            # Expiry during validation/write must not promote an unusable list.
            if result['validUntil'] <= clock() + MIN_REMAINING: raise ValueError('CRL too close to expiry')
            os.replace(temporary, destination)
            directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: os.fsync(directory)
            finally: os.close(directory)
        finally:
            if temporary is not None: temporary.unlink(missing_ok=True)
        return result | {'status':'INSTALLED'}


def check(path, verifier, *, warn_before=259200, clock=time.time):
    result = verifier(read_regular(path, installed=True))
    remaining = result['validUntil'] - clock()
    if remaining <= 0: raise ValueError('CRL expired')
    return result | {'status':'EXPIRING' if remaining <= warn_before else 'CURRENT'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('check','install'))
    parser.add_argument('--java', default='java')
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--trust', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--initialize', action='store_true')
    parser.add_argument('--warn-before', type=int, default=259200, help='Check warning window in seconds (default 72h)')
    args = parser.parse_args()
    if (not 0 <= args.warn_before <= 31_536_000 or (args.operation == 'install' and args.candidate is None)
            or (args.operation == 'check' and (args.candidate is not None or args.initialize))):
        parser.error('invalid operation arguments')
    try:
        verifier = Verifier(args.java,args.jar,args.trust)
        result = (install(args.candidate,args.destination,verifier,initialize=args.initialize)
                  if args.operation == 'install' else check(args.destination,verifier,warn_before=args.warn_before))
        print(json.dumps(result,sort_keys=True))
        return 3 if result['status'] == 'EXPIRING' else 0
    except (ValueError,TypeError,KeyError,OSError,subprocess.SubprocessError):
        print('{"status":"REJECTED","error":"CRL_MAINTENANCE_FAILED"}')
        return 2


if __name__ == '__main__': raise SystemExit(main())
