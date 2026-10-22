"""Fail-closed, uncached access to the independent revocation authority.

The client is injected so the wallet does not own AWS credentials. A missing
record is not permission to authenticate. Only the operator may provision one.
"""
import json
import os
from pathlib import Path
import re
import stat


class RevocationUnavailable(ValueError):
    pass


class RevocationAuthority:
    def __init__(self, invoke):
        self.invoke = invoke

    def request(self, operation, credential):
        if not isinstance(credential, str) or not re.fullmatch('[a-f0-9]{64}', credential):
            raise ValueError('credential identifier')
        try:
            response = self.invoke({'operation': operation, 'credential': credential})
            if not isinstance(response, dict) or response.get('credential') != credential:
                raise ValueError('invalid authority response')
            state = response.get('state')
            if state not in {'ENABLED', 'REVOKED', 'UNKNOWN'}:
                raise ValueError('invalid authority state')
            return state
        except Exception:
            # Never expose provider response bodies, credentials or request tokens.
            raise RevocationUnavailable('revocation authority unavailable') from None

    def assert_allowed(self, credential):
        if self.request('status', credential) != 'ENABLED':
            raise ValueError('credential inactive at revocation authority')

    def revoke(self, credential):
        if self.request('revoke', credential) != 'REVOKED':
            raise RevocationUnavailable('revocation not confirmed')


def lambda_authority(client, function_name):
    """Use a least-privilege AWS SDK client, not a shared bearer admin secret."""
    def invoke(payload):
        result = client.invoke(FunctionName=function_name, InvocationType='RequestResponse',
                               Payload=json.dumps(payload).encode())
        if result.get('StatusCode') != 200 or result.get('FunctionError'):
            raise ValueError('authority invocation failed')
        raw = result['Payload'].read(4097)
        if len(raw) > 4096:
            raise ValueError('authority response size')
        return json.loads(raw)
    return RevocationAuthority(invoke)


def configured_wallet(database, origin, *, config_path=None, client_factory=None):
    """Shared boot path for verifier, federation bridge and operator commands.

There is no network fallback to a local ACTIVE state. The marker prevents
opening an already migrated database through a legacy unconfigured command.
"""
    from wallet import Wallet
    config_path = config_path or os.environ.get('OPENID_CONTINUITY_CONFIG')
    if not config_path:
        return Wallet(database, origin)
    path = Path(config_path)
    if not path.is_absolute(): raise ValueError('absolute continuity configuration required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('private continuity configuration required')
        raw = stream.read(4097)
    if len(raw) > 4096: raise ValueError('continuity configuration size')
    config = json.loads(raw)
    if not isinstance(config, dict) or set(config) != {'version', 'region', 'backendFunction'}:
        raise ValueError('continuity configuration fields')
    if type(config['version']) is not int or config['version'] != 1 or config['region'] != 'eu-north-1':
        raise ValueError('continuity configuration version or region')
    if not isinstance(config['backendFunction'], str) or not re.fullmatch(
            r'arn:aws:lambda:eu-north-1:[0-9]{12}:function:[A-Za-z0-9_-]{1,64}', config['backendFunction']):
        raise ValueError('continuity function ARN required')
    if client_factory is None:
        import boto3
        from botocore.config import Config
        def client_factory():
            return boto3.client('lambda', region_name=config['region'],
                endpoint_url='https://lambda.eu-north-1.amazonaws.com',
                config=Config(connect_timeout=2, read_timeout=10,
                              retries={'total_max_attempts': 1}))
    authority = lambda_authority(client_factory(), config['backendFunction'])
    return Wallet(database, origin, revocation=authority, notifications=True)
