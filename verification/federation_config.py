"""Explicit, shared federation profile. A profile never grants identity assurance."""
import json
import os
from pathlib import Path
import re
import stat


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate federation configuration field')
        result[key] = value
    return result


def _read_configuration(filename):
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
    return json.loads(raw, object_pairs_hook=_object)


def read_profile(filename):
    value = _read_configuration(filename)
    if (not isinstance(value, dict) or set(value) != {'version', 'profile'}
            or type(value['version']) is not int or value['version'] != 1
            or value['profile'] not in ('private', 'sweden-connect-sandbox')):
        raise ValueError('Unsupported federation configuration')
    return value['profile'] == 'sweden-connect-sandbox'


def read_origins(filename):
    """The exact idp/sp origin contract also read by Java PilotOrigins."""
    value = _read_configuration(filename)
    if (type(value) is not dict or set(value) != {'idp', 'sp'}
            or any(not isinstance(v, str) or not re.fullmatch(
                r'https://[a-z0-9]+(?:[.-][a-z0-9]+)*\.[a-z]{2,}', v) for v in value.values())
            or value['idp'] == value['sp']):
        raise ValueError('Distinct canonical HTTPS DNS origins required')
    return value


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
