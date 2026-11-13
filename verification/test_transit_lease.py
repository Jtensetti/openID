"""Real TLS/Raft lease boundaries with generated service credentials only."""
import os
from pathlib import Path
import tempfile
import time
import unittest
import urllib.error
from unittest.mock import patch

from raft_test_support import RaftCluster
from transit import TransitVault, VaultUnavailable


@unittest.skipUnless(os.environ.get('OPENID_TEST_BAO'), 'requires pinned OpenBao executable')
class TransitLeaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cluster = RaftCluster(Path(cls.directory.name)/'raft')
        cls.addClassCleanup(cls.cluster.close)
        cls.node = cls.cluster.start()
        cls.root_token, _ = cls.cluster.initialize(cls.node)
        cls.cluster.provision(cls.node, cls.root_token)
        cls.wallet_policy = (Path(__file__).parents[1]/'deployment/cluster/wallet.hcl').read_text()

    def call(self, path, data=None, token=None):
        return self.cluster.call(self.node, path, data, token or self.root_token)

    def issue(self, policy='wallet', period='6s', **extra):
        return self.call('auth/token/create', {'policies':[policy], 'no_default_policy':True,
            'no_parent':True, 'period':period, **extra})['auth']['client_token']

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=self.directory.name)
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'service.token'
        self.token = self.issue()
        self.replace(self.token)
        self.vault = TransitVault(self.node['address'], self.path, str(self.cluster.cert))
        self.addCleanup(self.vault.close)

    def replace(self, token):
        stage = self.path.with_suffix('.new')
        stage.write_text(token)
        stage.chmod(0o600)
        os.replace(stage, self.path)

    def test_idle_service_renews_beyond_original_expiry_without_crypto_requests(self):
        self.vault.start_renewal('wallet')
        before = self.call('auth/token/lookup-self', token=self.token)['data']
        time.sleep(7)
        after = self.call('auth/token/lookup-self', token=self.token)['data']
        self.assertGreater(after['last_renewal_time'], before['last_renewal_time'])
        self.assertGreater(after['ttl'], 0)
        self.vault.key()

    def test_failed_renewal_blocks_still_valid_crypto_and_atomic_replacement_recovers(self):
        self.vault.start_renewal('wallet')
        denied = self.wallet_policy.replace('path "auth/token/renew-self" { capabilities = ["update"] }', '')
        self.call('sys/policies/acl/wallet', {'policy':denied})
        self.addCleanup(self.call, 'sys/policies/acl/wallet', {'policy':self.wallet_policy})
        end = time.monotonic()+5
        while True:
            try: self.vault.key()
            except VaultUnavailable: break
            self.assertLess(time.monotonic(), end, 'renewal failure did not close the client')
            time.sleep(.05)
        with patch.object(self.vault, 'exchange', wraps=self.vault.exchange) as requests:
            with self.assertRaises(VaultUnavailable): self.vault.key()
            self.assertEqual(requests.call_count, 0, 'failed credential ignored retry backoff')
        # The token still has cryptographic rights and TTL; the managed client
        # must not use that fact as fallback after renewal has failed.
        unmanaged = TransitVault(self.node['address'], self.path, str(self.cluster.cert))
        unmanaged.key()
        self.call('sys/policies/acl/wallet', {'policy':self.wallet_policy})
        new = self.issue()
        self.call('auth/token/revoke', {'token':self.token})
        self.replace(new)
        self.vault.key()

    def test_revoked_token_is_denied_until_authorized_replacement(self):
        self.vault.start_renewal('wallet')
        self.call('auth/token/revoke', {'token':self.token})
        with self.assertRaisesRegex(VaultUnavailable, '^key service unavailable$'):
            self.vault.key()
        self.replace(self.issue())
        self.vault.key()

    def test_wrong_role_and_expired_replacements_never_reuse_previous_token(self):
        self.vault.start_renewal('wallet')
        self.replace(self.issue('enroller'))
        with self.assertRaises(VaultUnavailable): self.vault.key()
        expired = self.issue(period='1s')
        end = time.monotonic()+5
        while True:
            try: self.call('auth/token/lookup-self', token=expired)
            except urllib.error.HTTPError as error:
                self.assertEqual(error.code, 403)
                break
            self.assertLess(time.monotonic(), end, 'short test token did not expire')
            time.sleep(.05)
        self.replace(expired)
        with self.assertRaises(VaultUnavailable): self.vault.key()
        self.replace(self.issue())
        self.vault.key()

    def test_runtime_cannot_create_tokens_manage_others_or_export_keys(self):
        self.vault.start_renewal('wallet')
        for path, data in [('auth/token/create', {'policies':['root']}),
                ('auth/token/renew', {'token':'synthetic-other-token'}),
                ('auth/token/lookup', {'token':'synthetic-other-token'}),
                ('transit/export/encryption-key/openid-profile', None),
                ('transit/encrypt/openid-profile', {'plaintext':'dGVzdA==','context':'dGVzdA=='})]:
            with self.subTest(path=path), self.assertRaises(VaultUnavailable):
                self.vault.request(path, data)
        self.vault.key()

    def test_private_file_checks_remain_effective_after_lease_is_cached(self):
        self.vault.start_renewal('wallet')
        self.path.chmod(0o644)
        with self.assertRaises(VaultUnavailable): self.vault.key()
        self.path.chmod(0o600)
        self.vault.key()
        original = self.path.with_suffix('.original')
        self.path.rename(original)
        self.path.symlink_to(original)
        with self.assertRaises(VaultUnavailable): self.vault.key()
        self.path.unlink()
        original.rename(self.path)
        self.vault.key()

    def test_root_nonperiodic_and_default_policy_credentials_cannot_start_runtime(self):
        for token in [self.root_token,
                self.issue(period='0s', ttl='1h'),
                self.issue(no_default_policy=False)]:
            self.replace(token)
            with self.assertRaisesRegex(VaultUnavailable, '^key service unavailable$'):
                self.vault.start_renewal('wallet')
            self.assertIsNone(self.vault.lease)

    def test_close_stops_background_renewal_and_prevents_crypto_reuse(self):
        self.vault.start_renewal('wallet')
        self.assertTrue(self.vault.lease.worker.is_alive())
        self.vault.close()
        self.assertFalse(self.vault.lease.worker.is_alive())
        with self.assertRaises(VaultUnavailable): self.vault.key()


if __name__ == '__main__': unittest.main()
