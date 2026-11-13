"""Declared boundaries for the single closed-issuance production candidate."""
import json
from pathlib import Path

VENDORS = json.loads(Path(__file__).with_name("vendor-images.lock.json").read_text())
IDENTITIES = {'postgres': '70:70', 'openbao': '10008:20008', 'credential-rotator': '0:0',
              'verifier': '10001:20010', 'wallet': '10006:20011', 'bridge': '10009:20001',
              'continuity': '10007:20004', 'idp': '10002:20001', 'sp': '10003:20001', 'notice-exporter': '10004:20003'}
GROUPS = {'verifier': ['20004'], 'wallet': ['20004'], 'bridge': ['20003', '20004']}
LIMITS = {'postgres': (768, 1), 'openbao': (384, .5), 'credential-rotator': (128, .25),
          'verifier': (2048, 2), 'wallet': (384, 1), 'bridge': (256, .5),
          'continuity': (128, .5), 'idp': (640, 1), 'sp': (384, .5), 'notice-exporter': (128, .25)}
MOUNTS = {
    'postgres': {'/srv/postgresql/config': ('postgres/config', True), '/srv/postgresql/data': ('postgres/data', False)},
    'openbao': {'/srv/openbao/config': ('openbao/config', True), '/srv/openbao/data': ('openbao/data', False),
                '/srv/openbao/audit': ('openbao/audit', False)},
    'credential-rotator': {'/srv/openid/service': ('services/credential-rotator', True),
                '/srv/openid/credentials/continuity': ('aws/continuity', False), '/srv/openid/credentials/notices': ('aws/notices', False)},
    'verifier': {'/srv/openid/service': ('services/verifier', True), '/srv/openid/continuity-ipc': ('ipc/continuity', True)},
    'wallet': {'/srv/openid/service': ('services/wallet', True), '/srv/openid/continuity-ipc': ('ipc/continuity', True)},
    'bridge': {'/srv/openid/service': ('services/bridge', True), '/srv/openid/continuity-ipc': ('ipc/continuity', True),
                '/srv/openid/origins.json': ('origins.json', True), '/srv/openid/federation.json': ('federation.json', True),
                '/srv/openid/federation-ipc': ('ipc/federation', False), '/srv/openid/notice-ipc': ('ipc/notice', False)},
    'continuity': {'/srv/openid/service': ('services/continuity', True), '/srv/openid/aws': ('aws/continuity', True),
                '/srv/openid/continuity-ipc': ('ipc/continuity', False)},
    'idp': {'/srv/openid/federation': ('federation-idp', True), '/srv/openid/federation-ipc': ('ipc/federation', True),
                '/srv/openid/origins.json': ('origins.json', True), '/srv/openid/federation.json': ('federation.json', True),
                '/srv/openid/federation-state': ('federation-state', False), '/srv/openid/health-ca.pem': ('public/idp.pem', True)},
    'sp': {'/srv/openid/federation': ('federation-sp', True), '/srv/openid/federation-ipc': ('ipc/federation', True),
                '/srv/openid/origins.json': ('origins.json', True), '/srv/openid/federation.json': ('federation.json', True),
                '/srv/openid/health-ca.pem': ('public/sp.pem', True)},
    'notice-exporter': {'/srv/openid/notice-ipc': ('ipc/notice', True), '/srv/openid/aws': ('aws/notices', True)},
}
AWS_EMPTY = {'AWS_EC2_METADATA_DISABLED': 'true', 'AWS_SHARED_CREDENTIALS_FILE': '/dev/null',
             'AWS_CONFIG_FILE': '/dev/null', 'BOTO_CONFIG': '/dev/null'}
ENVIRONMENTS = {name: dict(AWS_EMPTY) for name in IDENTITIES if name not in VENDORS}
ENVIRONMENTS['credential-rotator'].update(AWS_EC2_METADATA_DISABLED='false', AWS_EC2_METADATA_V1_DISABLED='true')
for name in ('continuity', 'notice-exporter'):
    ENVIRONMENTS[name]['OPENID_AWS_SESSION_FILE'] = '/srv/openid/aws/session.json'
ENVIRONMENTS['notice-exporter']['OPENID_NOTICE_SOCKET'] = '/srv/openid/notice-ipc/notice.sock'
ENVIRONMENTS['openbao'] = {'BAO_ENABLE_FILE_PERMISSIONS_CHECK': 'true', 'USER': 'tjipp-openbao', 'HOME': '/tmp'}
ENVIRONMENTS['postgres'] = {}
ENTRYPOINTS = {'postgres': ['postgres'], 'openbao': ['bao']}
COMMANDS = {'postgres': ['-D', '/srv/postgresql/data', '-c', 'config_file=/srv/postgresql/config/postgresql.conf'],
            'openbao': ['server', '-config=/srv/openbao/config/openbao.json']}
for name, module in {'credential-rotator': 'aws_credential_rotate', 'verifier': 'cluster_serve', 'wallet': 'cluster_serve',
                     'bridge': 'cluster_bridge', 'continuity': 'postgres_continuity'}.items():
    ENTRYPOINTS[name] = ['python', f'/app/verification/{module}.py']
    COMMANDS[name] = ['--config', '/srv/openid/service/runtime.json']
ENTRYPOINTS['notice-exporter'] = ['python', '/app/verification/notice_exporter.py']; COMMANDS['notice-exporter'] = []
for name, memory in [('idp', 384), ('sp', 192)]:
    ENTRYPOINTS[name] = ['java', f'-Xmx{memory}m', '-jar', '/app/prototype/target/isolated-eid-lab.jar']
    COMMANDS[name] = [f'runtime-{name}', '/srv/openid/federation', '/srv/openid/federation-ipc/federation.sock',
                      '/srv/openid/origins.json', '/srv/openid/federation.json']
COMMANDS['idp'].append('/srv/openid/federation-state')
DEPENDENCIES = {'continuity': ['postgres', 'credential-rotator'], 'verifier': ['postgres', 'openbao', 'continuity'],
                'wallet': ['postgres', 'openbao', 'continuity'], 'bridge': ['postgres', 'openbao', 'continuity'],
                'idp': ['bridge'], 'sp': ['bridge', 'idp'], 'notice-exporter': ['bridge', 'credential-rotator']}
PRIVATE_FILES = {
    'verifier': {'runtime.json', 'database', 'postgres-ca.pem', 'bao.token', 'bao-ca.pem', 'server.pem', 'server.key',
                 'pairing', 'metrics', 'csca.pem', 'csca.crl', 'continuity.json'},
    'wallet': {'runtime.json', 'database', 'postgres-ca.pem', 'bao.token', 'bao-ca.pem', 'server.pem', 'server.key',
               'pairing', 'metrics', 'continuity.json'},
    'bridge': {'runtime.json', 'database', 'postgres-ca.pem', 'bao.token', 'bao-ca.pem', 'continuity.json'},
    'continuity': {'runtime.json', 'database', 'postgres-ca.pem', 'authority.json'},
    'credential-rotator': {'runtime.json'},
}
HEALTH = {
    'postgres': ['CMD', 'pg_isready', '-h', '127.0.0.1', '-p', '15432', '-d', 'postgres'],
    'openbao': ['CMD', 'bao', 'status', '-address=https://127.0.0.1:18210', '-ca-cert=/srv/openbao/config/tls.pem'],
    'credential-rotator': ['CMD', 'python', '/app/verification/aws_credential_rotate.py', '--check'],
}
for name in ('verifier', 'wallet'):
    HEALTH[name] = ['CMD', 'python', '/app/verification/cluster_probe.py', '/srv/openid/service/runtime.json']
for name in ('bridge', 'continuity', 'idp', 'sp', 'notice-exporter'):
    HEALTH[name] = ['CMD', 'python', '/app/deployment/production/probe.py', name]
