"""Deliver two purpose-specific STS sessions; no credential values are logged."""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import tempfile
import threading

from aws_credential_process import unique, validate
from serve import private_file


TARGETS = {'continuity': (10007, 20004), 'notices': (10004, 20003)}
ROLE = r'arn:aws:iam::([0-9]{12}):role/([A-Za-z0-9+=,.@_-]{1,64})'
HEALTH = Path('/tmp/tjipp-credential-health.json')


def configuration(path):
    value = json.loads(private_file(path), object_pairs_hook=unique)
    if type(value) is not dict or set(value) != {'sourceRoleArn', 'roles'} or set(value['roles']) != set(TARGETS):
        raise ValueError('explicit credential roles required')
    source = re.fullmatch(ROLE, value['sourceRoleArn'])
    if source is None:
        raise ValueError('source role required')
    arns = {value['sourceRoleArn']}
    for name in TARGETS:
        target = re.fullmatch(ROLE, value['roles'][name])
        if target is None or target.group(1) != source.group(1) or value['roles'][name] in arns:
            raise ValueError('distinct same-account roles required')
        arns.add(value['roles'][name])
    return value


def output_directory(path, gid):
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise ValueError('real delivery directory required')
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o2710:
        raise ValueError('root-controlled delivery directory required')


def deliver(directory, value, uid, gid):
    output_directory(directory, gid)
    target = directory / 'session.json'
    if target.exists() or target.is_symlink():
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('unexpected existing delivery')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps(value).encode()); stream.flush(); os.fsync(stream.fileno())
            os.fchown(stream.fileno(), uid, gid)
        os.replace(temporary, target); temporary = None
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if temporary is not None: temporary.unlink(missing_ok=True)


def refresh(config, client, directories, *, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    source = re.fullmatch(ROLE, config['sourceRoleArn'])
    identity = client.get_caller_identity()
    expected = f'arn:aws:sts::{source.group(1)}:assumed-role/{source.group(2)}/'
    if identity.get('Account') != source.group(1) or not identity.get('Arn', '').startswith(expected):
        raise ValueError('unexpected source identity')
    sessions = {}
    # Finish both calls before replacing either current delivery.
    for name, (uid, gid) in TARGETS.items():
        output_directory(directories[name], gid)
        response = client.assume_role(RoleArn=config['roles'][name], RoleSessionName='tjipp-'+name, DurationSeconds=3600)
        role = re.fullmatch(ROLE, config['roles'][name])
        if not response['AssumedRoleUser']['Arn'].startswith(f'arn:aws:sts::{role.group(1)}:assumed-role/{role.group(2)}/'):
            raise ValueError('unexpected target identity')
        credentials = response['Credentials']
        value = {'Version': 1, 'AccessKeyId': credentials['AccessKeyId'], 'SecretAccessKey': credentials['SecretAccessKey'],
                 'SessionToken': credentials['SessionToken'], 'Expiration': credentials['Expiration'].isoformat()}
        validate(value, now=now)
        if (credentials['Expiration'] - now).total_seconds() < 3000:
            raise ValueError('new session too short')
        sessions[name] = value
    for name, value in sessions.items():
        deliver(directories[name], value, *TARGETS[name])
    return {name: value['Expiration'] for name, value in sessions.items()}


def metadata_client():
    import boto3
    import botocore.session
    from botocore.config import Config
    session = botocore.session.get_session()
    resolver = session.get_component('credential_provider')
    # Never use environment keys, shared profiles, container credentials or a
    # developer session. The dedicated host role is the only source.
    resolver.providers = [provider for provider in resolver.providers if provider.METHOD == 'iam-role']
    if len(resolver.providers) != 1:
        raise ValueError('instance role provider required')
    return boto3.Session(botocore_session=session).client('sts', region_name='eu-north-1',
        endpoint_url='https://sts.eu-north-1.amazonaws.com',
        config=Config(connect_timeout=2, read_timeout=3, retries={'total_max_attempts': 1}, proxies={}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    try:
        if args.check:
            value = json.loads(HEALTH.read_text())
            now = datetime.datetime.now(datetime.timezone.utc)
            if (set(value) != {'refreshedAt', 'expires'} or set(value['expires']) != set(TARGETS)
                    or not 0 <= (now-datetime.datetime.fromisoformat(value['refreshedAt'])).total_seconds() < 600
                    or any((datetime.datetime.fromisoformat(v)-now).total_seconds() < 1200 for v in value['expires'].values())):
                raise ValueError('credential refresh overdue')
            return 0
        if os.geteuid() != 0 or not args.config:
            raise ValueError('dedicated root delivery process required')
        config = configuration(args.config)
        directories = {name: Path('/srv/openid/credentials') / name for name in TARGETS}
        client = metadata_client(); stop = threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT): signal.signal(sig, lambda *_: stop.set())
        while not stop.is_set():
            try:
                expiry = refresh(config, client, directories)
                status = {'refreshedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'expires': expiry}
                temporary = HEALTH.with_suffix('.new'); temporary.write_text(json.dumps(status)); temporary.chmod(0o600)
                os.replace(temporary, HEALTH)
                delay = 300
            except Exception:
                print('AWS credential refresh unavailable.', file=sys.stderr, flush=True)
                delay = 30
            stop.wait(delay)
        return 0
    except Exception:
        print('AWS credential delivery unavailable.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
