"""Check the closed-issuance runtime configuration; never starts or approves a release."""
import argparse
import json
from pathlib import Path
import re
import sys

MOUNTS = {
    'vault': {'keys': ('vault/private', True), 'vault-ipc': ('vault/socket', False)},
    'verifier': {'runtime.json': ('runtime.json', True), 'secrets': ('secrets', True),
                 'data': ('data', False), 'continuity.json': ('continuity.json', True),
                 'vault-ipc': ('vault/socket', True)},
    'bridge': {'data': ('data', False), 'continuity.json': ('continuity.json', True),
               'origins.json': ('origins.json', True), 'federation.json': ('federation.json', True),
               'federation-ipc': ('ipc/federation', False),
               'notice-ipc': ('ipc/notice', False), 'vault-ipc': ('vault/socket', True)},
    'idp': {'federation': ('federation-idp', True), 'federation-ipc': ('ipc/federation', True),
            'origins.json': ('origins.json', True), 'federation.json': ('federation.json', True),
            'federation-state': ('federation-state', False)},
    'sp': {'federation': ('federation-sp', True), 'federation-ipc': ('ipc/federation', True),
           'origins.json': ('origins.json', True), 'federation.json': ('federation.json', True)},
    'notice-exporter': {'notice-ipc': ('ipc/notice', True)},
}
IDENTITIES = {'vault': '10005:20002', 'verifier': '10001:20002', 'bridge': '10001:20001',
              'idp': '10002:20001', 'sp': '10003:20001', 'notice-exporter': '10004:20003'}
ENVIRONMENTS = {
    'vault': {'OPENID_VAULT_KEY': '/srv/openid/keys/wallet.identity-key',
              'OPENID_VAULT_SOCKET': '/srv/openid/vault-ipc/vault.sock'},
    'verifier': {'OPENID_CONTINUITY_CONFIG': '/srv/openid/continuity.json',
                 'OPENID_IDENTITY_VAULT_SOCKET': '/srv/openid/vault-ipc/vault.sock'},
    'bridge': {'OPENID_CONTINUITY_CONFIG': '/srv/openid/continuity.json',
               'OPENID_PILOT_ORIGINS': '/srv/openid/origins.json',
               'OPENID_FEDERATION_CONFIG': '/srv/openid/federation.json',
               'OPENID_IDENTITY_VAULT_SOCKET': '/srv/openid/vault-ipc/vault.sock',
               'OPENID_FEDERATION_SOCKET': '/srv/openid/federation-ipc/federation.sock',
               'OPENID_FEDERATION_GROUP': '20001', 'OPENID_NOTICE_SOCKET': '/srv/openid/notice-ipc/notice.sock',
               'OPENID_NOTICE_GROUP': '20003'},
    'idp': {}, 'sp': {},
    'notice-exporter': {'OPENID_NOTICE_SOCKET': '/srv/openid/notice-ipc/notice.sock'},
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_compose(config, image_id, directory):
    require(re.fullmatch(r'sha256:[a-f0-9]{64}', image_id), 'Full verified image ID required')
    root = Path(directory)
    require(root.is_absolute() and '..' not in root.parts, 'Absolute runtime directory required')
    require(config.get('name') == 'tjipp', 'Unexpected Compose project')
    services = config.get('services', {})
    require(set(services) == set(MOUNTS), 'Complete service set required')
    for name, service in services.items():
        require(service.get('image') == image_id and 'build' not in service and service.get('pull_policy') == 'never',
                'Every service must use the imported image without building or pulling')
        require(service.get('user') == IDENTITIES[name], 'Unexpected service identity')
        groups = {str(group) for group in service.get('group_add', [])}
        require(groups == ({'20002', '20003'} if name == 'bridge' else set()), 'Unexpected service groups')
        require(service.get('read_only') is True and service.get('network_mode') == 'host'
                and service.get('cap_drop') == ['ALL'] and not service.get('cap_add')
                and 'no-new-privileges:true' in service.get('security_opt', [])
                and not any(service.get(k) for k in ('build', 'privileged', 'ports', 'devices', 'configs', 'secrets',
                                                    'volumes_from', 'pid', 'ipc', 'use_api_socket')),
                'Runtime isolation changed')
        mounts = service.get('volumes', [])
        expected = {f'/srv/openid/{target}': (str(root / source), ro) for target, (source, ro) in MOUNTS[name].items()}
        require(len(mounts) == len(expected) and {m.get('target') for m in mounts} == set(expected),
                'Unexpected or missing mount')
        for mount in mounts:
            target = mount.get('target')
            require(mount.get('type') == 'bind' and target in expected
                    and (mount.get('source'), mount.get('read_only', False)) == expected[target],
                    'Runtime mount boundary changed')
        environment = service.get('environment', {})
        expected_environment = dict(ENVIRONMENTS[name])
        if name == 'notice-exporter':
            queue = environment.get('OPENID_NOTICE_QUEUE_URL', '')
            require(re.fullmatch(r'https://sqs.eu-north-1.amazonaws.com/[0-9]{12}/[A-Za-z0-9_-]{1,80}', queue),
                    'Explicit Stockholm notice queue required')
            expected_environment['OPENID_NOTICE_QUEUE_URL'] = queue
        require(environment == expected_environment, 'Unexpected runtime environment or missing dependency')
        if name in {'idp', 'sp'}:
            require(service.get('entrypoint') == ['java', '-Xmx384m' if name == 'idp' else '-Xmx192m',
                    '-jar', '/app/prototype/target/isolated-eid-lab.jar'], 'Unexpected Java entrypoint')
            command = [f'runtime-{name}', '/srv/openid/federation', '/srv/openid/federation-ipc/federation.sock',
                       '/srv/openid/origins.json', '/srv/openid/federation.json']
            if name == 'idp': command.append('/srv/openid/federation-state')
            require(service.get('command') == command,
                    'Explicit runtime credentials required')
        elif name == 'verifier':
            require(not service.get('entrypoint') and not service.get('command'), 'Use the packaged verifier entrypoint')
        else:
            module = {'vault': 'vault_service', 'bridge': 'saml_bridge', 'notice-exporter': 'notice_exporter'}[name]
            require(service.get('entrypoint') == ['python', f'/app/verification/{module}.py']
                    and not service.get('command'), 'Unexpected Python entrypoint')


def check_settings(runtime, continuity):
    for key, value in {'bind': '127.0.0.1', 'listenPort': 8767, 'trustedProxy': '127.0.0.1',
                       'developmentAttestation': False, 'publicEnrollment': False,
                       'newRegistrationsEnabled': False, 'poseCheck': 'enforce'}.items():
        require(type(runtime.get(key)) is type(value) and runtime[key] == value,
                'Closed issuance and production App Attest settings required')
    require(runtime.get('database') == '/srv/openid/data/wallet.sqlite' and 'cscaCrl' in runtime,
            'Registry and document revocation configuration required')
    require(set(continuity) == {'version', 'region', 'backendFunction'}
            and type(continuity['version']) is int and continuity['version'] == 1
            and continuity['region'] == 'eu-north-1'
            and re.fullmatch(r'arn:aws:lambda:eu-north-1:[0-9]{12}:function:[A-Za-z0-9_-]{1,64}', continuity['backendFunction']),
            'Non-beta independent revocation configuration required')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    compose = sub.add_parser('compose')
    compose.add_argument('--image-id', required=True)
    compose.add_argument('--directory', required=True)
    settings = sub.add_parser('settings')
    settings.add_argument('--directory', required=True, type=Path)
    args = parser.parse_args()
    if args.command == 'compose':
        check_compose(json.load(sys.stdin), args.image_id, args.directory)
    else:
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'verification'))
        from federation_config import read_profile
        read_profile(args.directory / 'federation.json')
        check_settings(json.loads((args.directory / 'runtime.json').read_text()),
                       json.loads((args.directory / 'continuity.json').read_text()))
    print('Configuration checked; deployment, end-to-end checks and release approval are separate')


if __name__ == '__main__':
    main()
