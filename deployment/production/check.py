"""Check the one PG/OpenBao runtime; never provisions resources or approves a release."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit

from contract import (VENDORS, IDENTITIES, GROUPS, LIMITS, MOUNTS, ENVIRONMENTS,
                      ENTRYPOINTS, COMMANDS, DEPENDENCIES, PRIVATE_FILES, HEALTH)
ROOT = Path(__file__).resolve().parent
ENROLLMENT_PATH = '/srv/openid/service/enrollment-policy.json'


def enrollment_policy(value):
    # Use the same notice validation as the serving process, from this source tree.
    spec = importlib.util.spec_from_file_location('tjipp_enrollment_policy',
                                                ROOT.parents[1] / 'verification/enrollment_policy.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.EnrollmentPolicy(value)


def private_files(name, config):
    names = set(PRIVATE_FILES[name])
    if name == 'verifier' and config.get('newRegistrationsEnabled') is True:
        require(config.get('enrollmentPolicyFile') == ENROLLMENT_PATH, 'pinned enrollment policy path required')
        names.add('enrollment-policy.json')
    return names


def require(value, message):
    if not value: raise ValueError(message)


def example(name):
    return json.loads((ROOT / name).read_text())


def byte_limit(value, expected):
    # Compose emits byte limits as decimal strings in newer config JSON.
    return ((type(value) is int and value == expected) or
            (isinstance(value, str) and re.fullmatch(r'[0-9]+', value) is not None and int(value) == expected))


def check_compose(config, image_id, directory):
    require(re.fullmatch(r'sha256:[a-f0-9]{64}', image_id), 'full imported application image required')
    root = Path(directory)
    require(root.is_absolute() and root == root.resolve(), 'real absolute runtime directory required')
    require(config.get('name') == 'tjipp' and set(config.get('services', {})) == set(IDENTITIES), 'complete service set required')
    for name, service in config['services'].items():
        expected_image = VENDORS[name]['id'] if name in VENDORS else image_id
        require(service.get('image') == expected_image and service.get('pull_policy') == 'never' and not service.get('build'),
                'every service requires its imported, verified image')
        require(service.get('user') == IDENTITIES[name] and
                set(map(str, service.get('group_add', []))) == set(GROUPS.get(name, [])), 'service identity changed')
        require(service.get('network_mode') == 'host' and service.get('read_only') is True and service.get('init') is True
                and service.get('cap_drop') == ['ALL'] and service.get('cap_add', []) == (['CHOWN'] if name == 'credential-rotator' else [])
                and service.get('security_opt') == ['no-new-privileges:true'], 'runtime isolation changed')
        require(not any(service.get(k) for k in ('privileged', 'ports', 'devices', 'configs', 'secrets', 'volumes_from', 'pid', 'ipc',
                                                'use_api_socket', 'extra_hosts', 'env_file', 'post_start', 'pre_stop')),
                'unreviewed runtime capability or override')
        memory, cpu = LIMITS[name]
        require(byte_limit(service.get('mem_limit'), memory * 1024 * 1024) and byte_limit(service.get('memswap_limit'), memory * 1024 * 1024)
                and float(service.get('cpus', 0)) == cpu and service.get('pids_limit') == 128
                and service.get('tmpfs') == ['/tmp:size=128m,mode=1777'], 'resource or swap boundary changed for '+name)
        limits = service.get('ulimits', {})
        core = limits.get('core', {})
        require(set(limits) == {'core', 'nofile'} and limits['nofile'] == {'soft': 1024, 'hard': 1024}
                and set(core) <= {'soft', 'hard'} and core.get('soft', 0) == core.get('hard', 0) == 0,
                'core dumps or file descriptor limit changed')
        require(service.get('entrypoint') == ENTRYPOINTS[name] and (service.get('command') or []) == COMMANDS[name],
                'explicit runtime command required')
        expected = {target: (str(root / source), ro) for target, (source, ro) in MOUNTS[name].items()}
        mounts = service.get('volumes', [])
        require(len(mounts) == len(expected) and {m.get('target') for m in mounts} == set(expected), 'unexpected or missing mount')
        for mount in mounts:
            binding = mount.get('bind')
            require(mount.get('type') == 'bind' and
                    (mount.get('source'), mount.get('read_only', False)) == expected[mount['target']]
                    and isinstance(binding, dict) and set(binding) <= {'create_host_path'}
                    and binding.get('create_host_path', False) is False, 'mount boundary changed')
        env = dict(ENVIRONMENTS[name])
        if name == 'notice-exporter':
            queue = service.get('environment', {}).get('OPENID_NOTICE_QUEUE_URL', '')
            require(re.fullmatch(r'https://sqs.eu-north-1.amazonaws.com/[0-9]{12}/[A-Za-z0-9_-]{1,80}', queue), 'explicit queue required')
            env['OPENID_NOTICE_QUEUE_URL'] = queue
        require(service.get('environment', {}) == env, 'credential or runtime environment override')
        dependencies = service.get('depends_on', {})
        require(set(dependencies) == set(DEPENDENCIES.get(name, [])) and
                all(d.get('condition') == 'service_healthy' and d.get('required', True) is True for d in dependencies.values()),
                'healthy dependency chain required')
        health = service.get('healthcheck', {})
        require(health.get('test') == HEALTH[name] and not health.get('disable'), 'component readiness required')


def check_values(values):
    proofing, wallet, bridge = (values[n] for n in ('verifier', 'wallet', 'bridge'))
    origin = proofing.get('origin')
    origins = values['origins']
    from ingress import render
    render(proofing, origins)
    for name, filename in [('verifier', 'runtime.example.json'), ('wallet', 'wallet.example.json'), ('bridge', 'bridge.example.json')]:
        config, expected = values[name], example(filename)
        if name == 'verifier' and config.get('newRegistrationsEnabled') is True:
            expected.update(newRegistrationsEnabled=True, enrollmentPolicyFile=ENROLLMENT_PATH)
            enrollment_policy(values.get('enrollment'))
        elif name == 'verifier':
            require('enrollment' not in values, 'closed registration must not install enrollment information')
        require(set(config) == set(expected), 'explicit service fields required')
        for key, value in expected.items():
            if key in ('origin', 'team', 'bundle'): continue
            require(type(config[key]) is type(value) and config[key] == value, 'closed service or dependency configuration changed')
        require(config['origin'] == origin, 'one API origin required')
    require(re.fullmatch(r'[A-Z0-9]{10}', proofing['team']) and
            re.fullmatch(r'[A-Za-z0-9.-]{3,128}', proofing['bundle']), 'Apple application binding required')
    require(values['continuity'] == example('controller.example.json'), 'explicit controller configuration required')
    authority = values['authority']
    require(set(authority) == {'version', 'region', 'backendFunction'} and type(authority['version']) is int
            and authority['version'] == 1 and authority['region'] == 'eu-north-1', 'fresh independent authority required')
    match = re.fullmatch(r'arn:aws:lambda:eu-north-1:([0-9]{12}):function:[A-Za-z0-9_-]{1,64}', authority['backendFunction'])
    require(match is not None, 'canonical authority ARN required')
    client = values['client']
    require(client == {'version': 1, 'socket': '/srv/openid/continuity-ipc/continuity.sock', 'authority': authority['backendFunction']},
            'one pinned controller authority required')
    rotation = values['rotation']
    require(set(rotation) == {'sourceRoleArn', 'roles'} and set(rotation['roles']) == {'continuity', 'notices'},
            'two independent client roles required')
    arns = [rotation['sourceRoleArn'], *rotation['roles'].values()]
    require(len(set(arns)) == 3 and all(re.fullmatch(r'arn:aws:iam::'+match.group(1)+r':role/[A-Za-z0-9+=,.@_-]{1,64}', arn) for arn in arns),
            'distinct same-account source and client roles required')
    require(values['openbao'] == example('openbao.example.json'), 'non-dev loopback TLS/Raft configuration required')
    require(values['federation'] in ({'version': 1, 'profile': 'private'}, {'version': 1, 'profile': 'sweden-connect-sandbox'}),
            'explicit federation profile required')
    return match.group(1)


def metadata(path, uid, gid, mode, *, directory=False):
    require(path.is_absolute() and not path.is_symlink() and path == path.resolve(strict=True), 'real protected path required')
    info = path.stat()
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, mode), 'runtime ownership or permissions changed')


def private_json(path, maximum=16384):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        require(os.fstat(stream.fileno()).st_nlink == 1, 'configuration must not have hard links')
        raw = stream.read(maximum + 1)
    require(0 < len(raw) <= maximum, 'bounded configuration required')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate configuration field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def check_directory(root):
    require(root.is_absolute() and root == root.resolve(strict=True), 'real absolute runtime directory required')
    values = {}
    for name in PRIVATE_FILES:
        uid, gid = map(int, IDENTITIES[name].split(':')); directory = root / 'services' / name
        metadata(directory, uid, gid, 0o700, directory=True)
        metadata(directory / 'runtime.json', uid, gid, 0o600)
        config = private_json(directory / 'runtime.json')
        names = private_files(name, config)
        require({p.name for p in directory.iterdir()} == names, 'unexpected private service file')
        for filename in names: metadata(directory / filename, uid, gid, 0o600)
        values['rotation' if name == 'credential-rotator' else name] = config
        if name == 'verifier' and 'enrollment-policy.json' in names:
            values['enrollment'] = private_json(directory / 'enrollment-policy.json', 65536)
    for name, uid, gid, names in [
        ('postgres/config', 70, 70, {'postgresql.conf', 'pg_hba.conf', 'server.pem', 'server.key'}),
        ('openbao/config', 10008, 20008, {'openbao.json', 'tls.pem', 'tls.key'}),
        ('federation-idp', 10002, 20001, {'tls.p12', 'tls.password', 'idp.p12', 'idp.password', 'encryption.p12', 'encryption.password', 'sp.crt', 'subject-secret'}),
        ('federation-sp', 10003, 20001, {'tls.p12', 'tls.password', 'sp.p12', 'sp.password', 'idp.crt', 'idp-encryption.crt'})]:
        directory = root / name; metadata(directory, uid, gid, 0o700, directory=True)
        require({p.name for p in directory.iterdir()} == names, 'unexpected service key/configuration file')
        for filename in names: metadata(directory / filename, uid, gid, 0o600)
    for name, uid, gid, mode in [('postgres/data', 70, 70, 0o700), ('openbao/data', 10008, 20008, 0o700),
            ('openbao/audit', 10008, 20008, 0o700), ('federation-state', 10002, 20001, 0o700),
            ('ipc/continuity', 10007, 20004, 0o2710), ('ipc/federation', 10009, 20001, 0o2710),
            ('ipc/notice', 10009, 20003, 0o2710), ('aws/continuity', 0, 20004, 0o2710), ('aws/notices', 0, 20003, 0o2710)]:
        metadata(root / name, uid, gid, mode, directory=True)
    for name in ('idp', 'sp'): metadata(root / 'public' / (name+'.pem'), 0, 0, 0o644)
    for name in ('origins', 'federation'):
        metadata(root / (name+'.json'), 0, 0, 0o644); values[name] = private_json(root / (name+'.json'))
    for name, uid, gid in [('continuity', 10007, 20004), ('notices', 10004, 20003)]:
        directory = root / 'aws' / name
        require({p.name for p in directory.iterdir()} <= {'session.json'}, 'unexpected shared credential file')
        if (directory / 'session.json').exists(): metadata(directory / 'session.json', uid, gid, 0o600)
    values['authority'] = private_json(root / 'services/continuity/authority.json')
    values['client'] = private_json(root / 'services/verifier/continuity.json')
    require((root / 'services/verifier/pairing').read_bytes() == (root / 'services/wallet/pairing').read_bytes(),
            'one application pairing code required across both API roles')
    for service in ('wallet', 'bridge'):
        require(private_json(root / 'services' / service / 'continuity.json') == values['client'], 'controller clients disagree')
    values['openbao'] = private_json(root / 'openbao/config/openbao.json')
    for filename in ('postgresql.conf', 'pg_hba.conf'):
        require((root / 'postgres/config' / filename).read_bytes() == (ROOT / filename).read_bytes(), 'reviewed PostgreSQL configuration required')
    return check_values(values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    compose = sub.add_parser('compose'); compose.add_argument('--image-id', required=True); compose.add_argument('--directory', required=True)
    settings = sub.add_parser('settings'); settings.add_argument('--directory', required=True, type=Path)
    sub.add_parser('host')
    args = parser.parse_args()
    try:
        if args.command == 'compose': check_compose(json.load(sys.stdin), args.image_id, args.directory)
        elif args.command == 'settings': check_directory(args.directory)
        else:
            require(sys.platform == 'linux' and os.geteuid() == 0, 'Linux host administrator required')
            require(len(Path('/proc/swaps').read_text().splitlines()) == 1, 'host swap must be disabled')
            memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
            require(int(memory['MemTotal'].split()[0]) >= (sum(value[0] for value in LIMITS.values()) + 1024) * 1024,
                    'configured service limits plus host memory reserve required')
            from metadata_guard import check
            check()
        print('Runtime configuration checked; release approval and operational verification remain separate.')
        return 0
    except Exception:
        print('Runtime configuration rejected.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
