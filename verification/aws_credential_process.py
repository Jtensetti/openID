"""AWS credential_process for one private, expiring STS delivery.

Stdout is reserved for the SDK subprocess protocol. Never run this command
interactively against a real session file or capture its output in reports.
"""
import datetime
import json
import os
from pathlib import Path
import re
import stat
import sys


FIELDS = {'Version', 'AccessKeyId', 'SecretAccessKey', 'SessionToken', 'Expiration'}


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate credential field')
        value[key] = item
    return value


def validate(value, *, now=None):
    if type(value) is not dict or set(value) != FIELDS or type(value['Version']) is not int or value['Version'] != 1:
        raise ValueError('temporary credential format')
    for field, pattern in [('AccessKeyId', r'ASIA[A-Z0-9]{16}'),
                           ('SecretAccessKey', r'[A-Za-z0-9/+=]{40}'),
                           ('SessionToken', r'[A-Za-z0-9/+=._-]{16,8192}')]:
        if not isinstance(value[field], str) or not re.fullmatch(pattern, value[field]):
            raise ValueError('temporary credential field')
    if not isinstance(value['Expiration'], str):
        raise ValueError('temporary credential expiration')
    expiry = datetime.datetime.fromisoformat(value['Expiration'].replace('Z', '+00:00'))
    if expiry.tzinfo is None or expiry.utcoffset() != datetime.timedelta(0):
        raise ValueError('UTC credential expiration required')
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if not 60 < (expiry - now).total_seconds() <= 3660:
        raise ValueError('fresh, short-lived credentials required')
    return value


def load(path, *, now=None):
    path = Path(path)
    if not path.is_absolute() or path.parent != path.parent.resolve(strict=True):
        raise ValueError('real absolute credential directory required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('owned private credential file required')
        raw = stream.read(16385)
    if not 0 < len(raw) <= 16384:
        raise ValueError('bounded credential file required')
    return validate(json.loads(raw, object_pairs_hook=unique), now=now)


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError('one session path required')
        value = load(sys.argv[1])
        sys.stdout.write(json.dumps(value))
        return 0
    except Exception:
        print('Temporary AWS session unavailable.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
