import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from revocation import configured_wallet
from wallet import Wallet


class Client:
    def invoke(self, **kwargs):
        request = json.loads(kwargs['Payload'])
        return {'StatusCode': 200, 'Payload': io.BytesIO(json.dumps({
            'credential': request['credential'], 'state': 'UNKNOWN'}).encode())}


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name)/'wallet.sqlite'
        self.config = Path(self.tmp.name)/'continuity.json'
        self.value = {'version': 1, 'region': 'eu-north-1',
            'backendFunction': 'arn:aws:lambda:eu-north-1:123456789012:function:synthetic-authority'}
        self.save()

    def save(self):
        self.config.write_text(json.dumps(self.value))
        self.config.chmod(0o600)

    def open(self):
        return configured_wallet(self.db, 'https://example.invalid',
            config_path=self.config, client_factory=Client)

    def test_common_boot_path_enforces_both_controls(self):
        wallet = self.open()
        self.assertIsNotNone(wallet.revocation)
        self.assertTrue(wallet.notifications)
        with wallet.transaction() as db:
            self.assertEqual(0, db.execute('SELECT count(*) FROM notice_outbox').fetchone()[0])

    def test_migrated_wallet_cannot_open_without_configuration(self):
        self.open()
        with self.assertRaises(ValueError): Wallet(self.db, 'legacy-operator')
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            configured_wallet(self.db, 'legacy-bridge')

    def test_missing_config_does_not_fall_back(self):
        self.config.unlink()
        with self.assertRaises(FileNotFoundError): self.open()

    def test_bad_mode_and_symlink_are_rejected(self):
        self.config.chmod(0o644)
        with self.assertRaises(ValueError): self.open()
        original = self.config.with_suffix('.original')
        self.config.rename(original)
        self.config.symlink_to(original)
        with self.assertRaises(OSError): self.open()

    def test_invalid_region_version_endpoint_and_extra_fields(self):
        for name, value in [('version', True), ('region', 'us-east-1'),
                            ('backendFunction', 'https://attacker.invalid'), ('disabled', True)]:
            with self.subTest(name=name):
                old = dict(self.value)
                self.value[name] = value
                self.save()
                with self.assertRaises(ValueError): self.open()
                self.value = old

    def test_legacy_private_lab_remains_explicitly_unmigrated(self):
        with patch.dict(os.environ, {}, clear=True):
            wallet = configured_wallet(self.db, 'https://example.invalid')
        self.assertIsNone(wallet.revocation)
        self.assertFalse(self.db.with_suffix('.continuity-required').exists())


if __name__ == '__main__': unittest.main()
