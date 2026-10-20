import os
from pathlib import Path
import tempfile
import unittest

from raft_test_support import RaftCluster
from transit import TransitVault, VaultUnavailable


@unittest.skipUnless(os.environ.get('OPENID_TEST_BAO'), 'requires pinned OpenBao binary')
class KeyRecoveryTests(unittest.TestCase):
    def test_tls_raft_leader_loss_and_restore_with_separate_seal(self):
        with tempfile.TemporaryDirectory() as directory:
            cluster = RaftCluster(Path(directory) / 'raft')
            self.addCleanup(cluster.close)
            first = cluster.start()
            token, seal = cluster.initialize(first)
            tokens = cluster.provision(first, token)
            enroller = TransitVault(first['address'], tokens['enroller'], str(cluster.cert))
            wallet = TransitVault(first['address'], tokens['wallet'], str(cluster.cert))
            profile = {'displayName': 'GENERATED TEST PROFILE'}
            old = enroller.crypt('seal', 'test-credential', 'test-person', profile)
            stale = cluster.call(first, 'sys/storage/raft/snapshot', token=token, raw=True)
            cluster.call(first, 'transit/keys/openid-profile/rotate', {}, token)
            latest = enroller.crypt('seal', 'test-credential', 'test-person', profile)
            second, third = cluster.start(), cluster.start()
            cluster.join(second, first, seal)
            cluster.join(third, first, seal)
            def voters_ready():
                servers = cluster.call(first, 'sys/storage/raft/configuration', token=token)['data']['config']['servers']
                return len(servers) == 3 and all(server['voter'] for server in servers)
            cluster.wait(voters_ready, timeout=30)
            backup_token = tokens['backup'].read_text()
            snapshot = cluster.call(first, 'sys/storage/raft/snapshot', token=backup_token, raw=True)
            import urllib.error
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                cluster.call(first, 'sys/storage/raft/snapshot-force', snapshot, backup_token)
            self.assertEqual(403, rejected.exception.code)
            with self.assertRaises(VaultUnavailable):
                TransitVault(first['address'], tokens['backup'], str(cluster.cert)).crypt('open', 'test-credential', 'test-person', latest)
            cluster.stop(first)
            active = cluster.wait(lambda: next((node for node in (second, third)
                if cluster.call(node, 'sys/leader').get('is_self')), None), timeout=30)
            failover_wallet = TransitVault(active['address'], tokens['wallet'], str(cluster.cert))
            self.assertEqual(profile, failover_wallet.crypt('open', 'test-credential', 'test-person', latest))
            cluster.stop(second)
            cluster.stop(third)
            with self.assertRaises(VaultUnavailable):
                wallet.crypt('open', 'test-credential', 'test-person', old)
            restored = cluster.restore_snapshot(snapshot, seal)
            recovered = TransitVault(restored['address'], tokens['wallet'], str(cluster.cert))
            for value in (old, latest):
                self.assertEqual(profile, recovered.crypt('open', 'test-credential', 'test-person', value))
            with self.assertRaises(VaultUnavailable):
                TransitVault(restored['address'], tokens['wallet']).crypt('open', 'test-credential', 'test-person', latest)
            self.assertEqual(profile, recovered.crypt('open', 'test-credential', 'test-person', latest))
            obsolete = cluster.restore_snapshot(stale, seal)
            obsolete_wallet = TransitVault(obsolete['address'], tokens['wallet'], str(cluster.cert))
            with self.assertRaises(VaultUnavailable):
                obsolete_wallet.crypt('open', 'test-credential', 'test-person', latest)


if __name__ == '__main__':
    unittest.main()
