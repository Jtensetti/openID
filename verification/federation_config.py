"""Explicit, shared federation profile. A profile never grants identity assurance."""
import json
import os
from pathlib import Path
import stat


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate federation configuration field')
        result[key] = value
    return result


def read_profile(filename):
    path = Path(filename)
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise ValueError('Real absolute federation configuration required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise ValueError('Protected regular federation configuration required')
        raw = source.read(4097)
    if not raw or len(raw) > 4096:
        raise ValueError('Federation configuration size')
    value = json.loads(raw, object_pairs_hook=_object)
    if (not isinstance(value, dict) or set(value) != {'version', 'profile'}
            or type(value['version']) is not int or value['version'] != 1
            or value['profile'] not in ('private', 'sweden-connect-sandbox')):
        raise ValueError('Unsupported federation configuration')
    return value['profile'] == 'sweden-connect-sandbox'


def sandbox_enabled(environment=None):
    environment = os.environ if environment is None else environment
    if 'OPENID_FEDERATION_CONFIG' in environment:
        if 'OPENID_SWEDEN_CONNECT_SANDBOX' in environment:
            raise ValueError('Conflicting federation configuration')
        return read_profile(environment['OPENID_FEDERATION_CONFIG'])
    # Kept only for the explicit legacy lab entrypoints, absent from the runtime manifest.
    legacy = environment.get('OPENID_SWEDEN_CONNECT_SANDBOX', 'false')
    if legacy not in ('true', 'false'):
        raise ValueError('Invalid legacy federation switch')
    return legacy == 'true'
