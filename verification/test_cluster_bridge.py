"""Local configuration/socket boundaries; real PG/Transit tests live in test_cluster."""
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from cluster_bridge import config_file, RegistryBridge
from federation_config import read_origins
from ipc_support import LocalService, request
from wallet import Wallet


class ClusterBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        for name in ('federation', 'notice'):
            (self.root/name).mkdir(mode=0o2710)
            (self.root/name).chmod(0o2710)
        self.profile = self.root/'profile.json'
        self.profile.write_text('{"version":1,"profile":"private"}')
        self.profile.chmod(0o644)
        self.origins = self.root/'origins.json'
        self.origins.write_text('{"idp":"https://idp.example.test","sp":"https://sp.example.test"}')
        self.origins.chmod(0o644)
        self.config = dict(databaseFile=str(self.root/'dsn'), baoAddress='https://bao.example.test',
            baoTokenFile=str(self.root/'token'), baoCA=str(self.root/'ca'), origin='https://api.example.test',
            socket=str(self.root/'federation'/'bridge.sock'), federationGroup=os.getgid(),
            noticeSocket=str(self.root/'notice'/'notice.sock'), noticeGroup=os.getgid(),
            continuityFile=str(self.root/'continuity.json'), federationFile=str(self.profile), originsFile=str(self.origins))
        self.path = self.root/'bridge.json'
        self.wallet = Wallet(self.root/'wallet.sqlite', 'https://api.example.test', notifications=True)

    def save(self, value=None):
        self.path.write_text(json.dumps(self.config if value is None else value))
        self.path.chmod(0o600)
        return self.path

    def start(self):
        bridge = RegistryBridge(config_file(self.save()), self.wallet)
        self.addCleanup(bridge.close)
        return bridge

    def test_shared_origin_contract_rejects_noncanonical_or_ambiguous_values(self):
        for value in ({'idp':'https://idp.example.test','sp':'https://sp.example.test'},):
            self.assertEqual(value, read_origins(self.origins))
        for change in ({'sp':'https://sp.example.test/'}, {'sp':'https://sp.example.test:443'},
                       {'sp':'https://user@sp.example.test'}, {'sp':'https://SP.example.test'},
                       {'sp':'https://localhost:8444'}, {'sp':'https://idp.example.test'},
                       {'other':'https://other.example.test'}, {'sp':None}):
            self.origins.write_text(json.dumps({'idp':'https://idp.example.test','sp':'https://sp.example.test'}|change))
            with self.subTest(change=change), self.assertRaises(ValueError):read_origins(self.origins)
        self.origins.write_text('{"idp":"https://idp.example.test","sp":"https://sp.example.test","sp":"https://other.example.test"}')
        with self.assertRaises(ValueError):read_origins(self.origins)

    def test_private_profile_fixed_audience_and_minimal_notice_surface(self):
        self.start()
        audience='https://sp.example.test/sp'
        self.assertEqual({'state':'READY'}, request(self.config['socket'],{'operation':'health','audience':audience}))
        for wrong in ('https://testclient.sandbox.swedenconnect.se/testsp1','https://unknown.example.test/sp'):
            with self.assertRaises(ValueError):request(self.config['socket'],{'operation':'start','audience':wrong,'binding':'test-binding'})
        self.assertIsNone(request(self.config['noticeSocket'],{'operation':'next'}))
        for forbidden in ('activate','get-profile','revoke'):
            with self.assertRaises(ValueError):request(self.config['noticeSocket'],{'operation':forbidden})

    def test_sandbox_profile_adds_only_existing_fixed_parties(self):
        from federation_parties import SANDBOX_PARTIES
        self.profile.write_text('{"version":1,"profile":"sweden-connect-sandbox"}')
        self.start()
        for audience in SANDBOX_PARTIES:
            item=request(self.config['socket'],{'operation':'start','audience':audience,'binding':'test-binding'})
            self.assertEqual(SANDBOX_PARTIES[audience],item['relyingParty'])
        with self.assertRaises(ValueError):
            request(self.config['socket'],{'operation':'start','audience':'https://unknown.example.test/sp','binding':'test-binding'})

    def test_explicit_configuration_rejects_legacy_environment_overrides(self):
        for name in ('OPENID_SWEDEN_CONNECT_SANDBOX','OPENID_FEDERATION_CONFIG','OPENID_PILOT_ORIGINS'):
            with self.subTest(name=name), patch.dict(os.environ,{name:'true'}),self.assertRaises(ValueError):
                config_file(self.save())

    def test_invalid_config_or_permissions_never_fall_back(self):
        for change in ({'audience':'https://other.example.test/sp'}, {'noticeGroup':True},
                       {'federationGroup':0}, {'federationFile':'relative.json'},
                       {'noticeSocket':self.config['socket']}):
            with self.subTest(change=change),self.assertRaises(ValueError):config_file(self.save(self.config|change))
        self.save();self.path.chmod(0o644)
        with self.assertRaises(ValueError):config_file(self.path)
        self.save();self.profile.chmod(0o666)
        with self.assertRaises(ValueError):config_file(self.path)

    def test_abandoned_sockets_restart_but_active_service_is_preserved(self):
        for key in ('socket','noticeSocket'):
            endpoint=socket.socket(socket.AF_UNIX);endpoint.bind(self.config[key]);endpoint.close()
        bridge=self.start()
        with self.assertRaises(ValueError):RegistryBridge(self.config,self.wallet)
        self.assertEqual({'state':'READY'},request(self.config['socket'],{'operation':'health','audience':'https://sp.example.test/sp'}))
        bridge.close();self.start()

    def test_bad_parent_is_checked_before_deleting_an_abandoned_socket(self):
        endpoint=socket.socket(socket.AF_UNIX);endpoint.bind(self.config['socket']);endpoint.close()
        (self.root/'notice').chmod(0o2770)
        with self.assertRaises(ValueError):RegistryBridge(self.config,self.wallet)
        self.assertTrue(Path(self.config['socket']).exists())
        (self.root/'notice').chmod(0o2710)
        with patch('ipc_support.os.getuid',return_value=os.getuid()+1),self.assertRaises(ValueError):
            RegistryBridge(self.config,self.wallet)
        with self.assertRaises(ValueError):RegistryBridge(self.config|{'federationGroup':os.getgid()+1},self.wallet)
        self.assertTrue(Path(self.config['socket']).exists())

    def test_notice_start_failure_closes_federation_and_preserves_existing_service(self):
        server=LocalService(self.config['noticeSocket'],os.getgid(),lambda _: 'existing-service')
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(server.close)
        with self.assertRaises(ValueError):RegistryBridge(self.config,self.wallet)
        self.assertFalse(Path(self.config['socket']).exists())
        self.assertEqual('existing-service',request(self.config['noticeSocket'],{'operation':'probe'}))

    def test_ordinary_file_or_symlink_is_preserved_on_rejected_start(self):
        target=self.root/'keep';target.write_text('keep')
        path=Path(self.config['socket']);path.symlink_to(target)
        with self.assertRaises(ValueError):RegistryBridge(self.config,self.wallet)
        self.assertTrue(path.is_symlink());self.assertEqual('keep',target.read_text())
        path.unlink();path.write_text('keep')
        with self.assertRaises(ValueError):RegistryBridge(self.config,self.wallet)
        self.assertEqual('keep',path.read_text())


if __name__ == '__main__':unittest.main()
