"""Disposable TLS/Raft nodes. One-share seals are confined to tests."""
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request


class RaftCluster:
    def __init__(self, directory):
        self.root = Path(directory)
        self.root.mkdir(mode=0o700)
        self.cert = self.root / 'ca.pem'
        self.key = self.root / 'tls.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', str(self.key), '-out', str(self.cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.context = ssl.create_default_context(cafile=str(self.cert))
        self.nodes = []

    def start(self):
        directory = self.root / str(len(self.nodes))
        directory.mkdir(mode=0o700)
        (directory / 'data').mkdir(mode=0o700)
        with socket.socket() as first, socket.socket() as second:
            first.bind(('127.0.0.1', 0))
            second.bind(('127.0.0.1', 0))
            api_port, cluster_port = first.getsockname()[1], second.getsockname()[1]
        address = f'https://localhost:{api_port}'
        config = {'disable_mlock': True, 'ui': False, 'api_addr': address,
                  'cluster_addr': f'https://127.0.0.1:{cluster_port}',
                  'storage': {'raft': {'path': str(directory / 'data'), 'node_id': 'node-' + directory.name}},
                  'listener': {'tcp': {'address': f'127.0.0.1:{api_port}',
                                      'cluster_address': f'127.0.0.1:{cluster_port}',
                                      'tls_cert_file': str(self.cert), 'tls_key_file': str(self.key)}}}
        path = directory / 'bao.json'
        path.write_text(json.dumps(config))
        log = open(directory / 'server.log', 'wb')
        process = subprocess.Popen([os.environ['OPENID_TEST_BAO'], 'server', '-config', str(path)],
                                   stdout=log, stderr=log)
        node = {'address': address, 'process': process, 'log': log}
        self.nodes.append(node)
        self.wait(lambda: self.call(node, 'sys/seal-status'))
        return node

    def call(self, node, path, data=None, token=None, raw=False):
        headers = {'Content-Type': 'application/octet-stream' if isinstance(data, bytes) else 'application/json'}
        if token:
            headers['X-Vault-Token'] = token
        body = data if isinstance(data, bytes) else json.dumps(data).encode() if data is not None else None
        request = urllib.request.Request(node['address'] + '/v1/' + path, data=body, headers=headers)
        with urllib.request.urlopen(request, context=self.context, timeout=15) as response:
            value = response.read(10 * 1024 * 1024 + 1)
            if len(value) > 10 * 1024 * 1024:
                raise ValueError('test response limit')
            return value if raw else json.loads(value) if value else {}

    @staticmethod
    def wait(operation, timeout=20):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                value = operation()
                if value:
                    return value
            except (OSError, urllib.error.HTTPError):
                pass
            time.sleep(.1)
        raise AssertionError('Raft operation did not become ready')

    def initialize(self, node):
        result = self.call(node, 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
        seal = result['keys_base64'][0]
        self.call(node, 'sys/unseal', {'key': seal})
        self.wait(lambda: self.call(node, 'sys/leader').get('is_self'))
        return result['root_token'], seal

    def join(self, node, leader, seal):
        self.call(node, 'sys/storage/raft/join', {'leader_api_addr': leader['address'], 'leader_ca_cert': self.cert.read_text()})
        self.call(node, 'sys/unseal', {'key': seal})
        self.wait(lambda: not self.call(node, 'sys/seal-status')['sealed'])

    def provision(self, node, token):
        self.call(node, 'sys/mounts/transit', {'type': 'transit'}, token)
        self.call(node, 'transit/keys/openid-profile', {'type': 'aes256-gcm96', 'derived': True, 'exportable': False}, token)
        self.call(node, 'transit/keys/openid-index', {'type': 'hmac', 'key_size': 32, 'exportable': False}, token)
        result = {}
        for role in ('enroller', 'wallet', 'maintenance', 'backup', 'recovery'):
            policy = (Path(__file__).parents[1] / 'deployment/cluster' / (role + '.hcl')).read_text()
            self.call(node, 'sys/policies/acl/' + role, {'policy': policy}, token)
            issued = self.call(node, 'auth/token/create', {'policies': [role], 'no_default_policy': True, 'ttl': '1h'}, token)
            path = self.root / (role + '-' + secrets.token_hex(8) + '.token')
            path.write_text(issued['auth']['client_token'])
            path.chmod(0o600)
            result[role] = path
        return result

    def restore_snapshot(self, snapshot, seal):
        node = self.start()
        bootstrap_token, bootstrap_seal = self.initialize(node)
        # A separately initialized service has a different seal: ordinary restore must reject it.
        try:
            self.call(node, 'sys/storage/raft/snapshot', snapshot, bootstrap_token)
        except urllib.error.HTTPError as error:
            if error.code != 400:
                raise
        else:
            raise AssertionError('Foreign seal accepted without explicit force restore')
        self.call(node, 'sys/storage/raft/snapshot-force', snapshot, bootstrap_token)
        self.wait(lambda: self.call(node, 'sys/seal-status')['sealed'])
        try:
            self.call(node, 'sys/unseal', {'key': bootstrap_seal})
        except urllib.error.HTTPError as error:
            if error.code != 400:
                raise
        else:
            raise AssertionError('Wrong unseal key accepted')
        self.call(node, 'sys/unseal', {'key': seal})
        self.wait(lambda: self.call(node, 'sys/leader').get('is_self'))
        return node

    @staticmethod
    def stop(node):
        process = node['process']
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        node['log'].close()

    def close(self):
        for node in self.nodes:
            self.stop(node)
