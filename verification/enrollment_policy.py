"""Versioned, bounded enrollment notices. A decision reference is not a legal approval.

Only an explicitly selected, private policy file can supply live notices. The caller
must still authorize collection and archive the exact notice with acceptance proof.
"""
import hashlib
import base64
import json
import os
from pathlib import Path
import re
import stat
import time

MAX_FILE = 65536
TEXT_FIELDS = ('terms', 'privacy', 'biometrics', 'withdrawal')
FIELDS = {'version', 'controller', 'contact', 'locale', 'notBefore', 'notAfter', *TEXT_FIELDS}
REFERENCE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{7,95}\Z')
HEX = re.compile(r'[a-f0-9]{64}\Z')


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('ascii')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('duplicate field')
        result[key] = value
    return result


def plain(value, maximum):
    if not isinstance(value, str) or not value.strip() or len(value.encode('utf-8')) > maximum:
        raise ValueError('notice text size')
    # Render plain text only; prevent hidden direction changes in the legal choice.
    if any((ord(c) < 32 and c not in '\n\t') or 0x7f <= ord(c) <= 0x9f
           or ord(c) in {0x2028, 0x2029, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
                         0x2066, 0x2067, 0x2068, 0x2069, 0xfeff} for c in value):
        raise ValueError('notice text characters')
    return value


class EnrollmentPolicy:
    def __init__(self, value, *, clock=time.time):
        if (not isinstance(value, dict) or set(value) != {'schema', 'decisionReference', 'notice'}
                or type(value['schema']) is not int or value['schema'] != 1
                or not isinstance(value['decisionReference'], str)
                or not REFERENCE.fullmatch(value['decisionReference'])):
            raise ValueError('explicit enrollment policy required')
        notice = value['notice']
        if (not isinstance(notice, dict) or set(notice) != FIELDS
                or not isinstance(notice['version'], str) or not REFERENCE.fullmatch(notice['version'])
                or notice['locale'] != 'sv-SE'
                or any(type(notice[k]) is not int for k in ('notBefore', 'notAfter'))
                or not 0 <= notice['notBefore'] < notice['notAfter'] <= 253402300799):
            raise ValueError('enrollment notice fields')
        for field in TEXT_FIELDS: plain(notice[field], 16384)
        for field in ('controller', 'contact'): plain(notice[field], 1024)
        raw = canonical(value)
        if len(raw) > MAX_FILE: raise ValueError('enrollment policy size')
        # Freeze caller-owned nested dictionaries. Public responses are fresh copies.
        self._record = raw
        self._notice = canonical(notice)
        self.digest = hashlib.sha256(self._notice).hexdigest()
        self.clock = clock
        self.require_current()

    def require_current(self):
        notice = json.loads(self._notice)
        now = self.clock()
        if not notice['notBefore'] <= now < notice['notAfter']:
            raise ValueError('enrollment policy is not current')

    def public(self):
        self.require_current()
        # Send the exact hashed bytes. Clients decode and display these bytes;
        # language-specific JSON reserialization must not change the digest.
        return {'digest': self.digest, 'noticeJSON': base64.b64encode(self._notice).decode('ascii')}

    def archived(self):
        return json.loads(self._record)

    def acceptance(self, value):
        self.require_current()
        if (not isinstance(value, dict)
                or set(value) != {'policyDigest', 'termsAccepted', 'biometricsAccepted'}
                or not isinstance(value['policyDigest'], str)
                or value['policyDigest'] != self.digest
                or value['termsAccepted'] is not True or value['biometricsAccepted'] is not True):
            raise ValueError('explicit current acceptance required')
        return dict(value)


def read_policy(path, *, clock=time.time):
    path = Path(path)
    if not path.is_absolute(): raise ValueError('absolute enrollment policy path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077
                or info.st_uid not in (0, os.geteuid())):
            raise ValueError('private enrollment policy file required')
        raw = stream.read(MAX_FILE + 1)
    if not 0 < len(raw) <= MAX_FILE: raise ValueError('enrollment policy file size')
    value = json.loads(raw, object_pairs_hook=unique_object,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite JSON')))
    return EnrollmentPolicy(value, clock=clock)
