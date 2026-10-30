"""Detached recovery evidence. Its digest must be anchored outside the backup."""
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import time

from audit_archive import decode

FORMAT = 'openid-sqlite-recovery-binding-v1'
MAX_SNAPSHOT_BYTES = 2 * 1024**3


def digest(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
        raise ValueError('trusted SHA-256 digest required')
    return value


def private_parent(path):
    info = Path(path).absolute().parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        raise ValueError('private parent directory required')


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def private_input(path, max_bytes):
    path = Path(path).absolute()
    private_parent(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_mode & 0o177
                or not 0 < info.st_size <= max_bytes):
            raise ValueError('bounded private regular file required')
        if identity(path.lstat()) != identity(info): raise ValueError('file replaced')
        yield stream
        if (identity(os.fstat(stream.fileno())) != identity(info)
                or identity(path.lstat()) != identity(info)):
            raise ValueError('file changed')


def no_sqlite_sidecars(path):
    for suffix in ('-wal', '-shm', '-journal'):
        sidecar = Path(str(path)+suffix)
        if sidecar.exists() or sidecar.is_symlink():
            raise ValueError('closed SQLite backup required; use recovery backup first')


def snapshot_copy(source, target):
    """Copy exact closed-backup bytes before SQLite opens the restored database."""
    source, target = Path(source).absolute(), Path(target).absolute()
    private_parent(target)
    no_sqlite_sidecars(source)
    end = time.monotonic()+30
    created = False
    try:
        with private_input(source, MAX_SNAPSHOT_BYTES) as input_stream:
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            created = True
            checksum, size = hashlib.sha256(), 0
            with os.fdopen(fd, 'wb') as output:
                while True:
                    if time.monotonic() >= end: raise ValueError('snapshot copy deadline')
                    chunk = input_stream.read(65536)
                    if not chunk: break
                    size += len(chunk)
                    if size > MAX_SNAPSHOT_BYTES: raise ValueError('snapshot size')
                    checksum.update(chunk); output.write(chunk)
                output.flush(); os.fsync(output.fileno())
            if size != os.fstat(input_stream.fileno()).st_size: raise ValueError('incomplete snapshot')
            no_sqlite_sidecars(source)
        return {'sha256': checksum.hexdigest(), 'bytes': size}
    except BaseException:
        if created: target.unlink(missing_ok=True)
        raise


def validate(value):
    if (not isinstance(value, dict)
            or set(value) != {'format', 'backupSHA256', 'backupBytes', 'identityKeySHA256', 'continuityRequired'}
            or value['format'] != FORMAT
            or type(value['backupBytes']) is not int
            or not 0 < value['backupBytes'] <= MAX_SNAPSHOT_BYTES
            or type(value['continuityRequired']) is not bool):
        raise ValueError('invalid recovery binding')
    digest(value['backupSHA256'])
    if value['identityKeySHA256'] is not None: digest(value['identityKeySHA256'])
    return value


def read_binding(path, expected_sha256):
    expected_sha256 = digest(expected_sha256)
    with private_input(path, 4096) as stream: raw = stream.read(4097)
    if len(raw) > 4096 or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256):
        raise ValueError('recovery binding does not match external anchor')
    return validate(decode(raw))


def write_binding(path, value):
    raw = (json.dumps(validate(value), sort_keys=True, separators=(',', ':'))+'\n').encode()
    path = Path(path).absolute(); private_parent(path)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return hashlib.sha256(raw).hexdigest()
