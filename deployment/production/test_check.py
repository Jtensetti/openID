import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

import check

ROOT = Path(__file__).resolve().parent
IMAGE = 'sha256:' + 'a' * 64
DIRECTORY = '/tmp/tjipp-config-test'


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.runtime = json.loads((ROOT / 'runtime.example.json').read_text())
        self.continuity = json.loads((ROOT / 'continuity.example.json').read_text())

    def test_closed_settings(self):
        check.check_settings(self.runtime, self.continuity)

    def test_issuance_or_development_cannot_be_enabled(self):
        for flag in ('newRegistrationsEnabled', 'developmentAttestation', 'publicEnrollment'):
            with self.subTest(flag=flag):
                settings = {**self.runtime, flag: True}
                with self.assertRaises(ValueError): check.check_settings(settings, self.continuity)

    def test_revocation_cannot_use_beta_or_omit_authority(self):
        for settings in ({**self.continuity, 'testBeta': True}, {},
                         {**self.continuity, 'region': 'us-east-1'}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                check.check_settings(self.runtime, settings)

    def test_public_listener_or_observation_only_pose_is_rejected(self):
        for key, value in (('bind', '0.0.0.0'), ('trustedProxy', '10.0.0.1'), ('poseCheck', 'log')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                check.check_settings({**self.runtime, key: value}, self.continuity)


class ComposeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('docker'):
            raise unittest.SkipTest('Docker Compose required; CI renders the actual manifest')
        environment = {**os.environ, 'TJIPP_IMAGE_ID': IMAGE, 'TJIPP_DIRECTORY': DIRECTORY,
                       'TJIPP_NOTICE_QUEUE_URL': 'https://sqs.eu-north-1.amazonaws.com/000000000000/test-notices'}
        result = subprocess.run(['docker', 'compose', '-f', str(ROOT / 'compose.yaml'), 'config', '--format', 'json'],
                                check=True, capture_output=True, text=True, env=environment)
        cls.configuration = json.loads(result.stdout)

    def setUp(self):
        self.config = copy.deepcopy(self.configuration)

    def check(self):
        check.check_compose(self.config, IMAGE, DIRECTORY)

    def test_actual_rendered_compose(self):
        self.check()

    def test_recipient_cannot_mount_issuer_keys_or_registry(self):
        for source, target in (('federation-idp', '/srv/openid/federation'), ('data', '/srv/openid/data')):
            self.config = copy.deepcopy(self.configuration)
            self.config['services']['sp']['volumes'][0].update(source=DIRECTORY + '/' + source, target=target)
            with self.subTest(source=source), self.assertRaises(ValueError): self.check()

    def test_code_overlay_and_writable_credentials_are_rejected(self):
        service = self.config['services']['idp']
        service['volumes'][0]['read_only'] = False
        with self.assertRaises(ValueError): self.check()
        self.config = copy.deepcopy(self.configuration)
        self.config['services']['bridge']['volumes'].append(
            {'type': 'bind', 'source': '/tmp/federation.py', 'target': '/app/verification/federation.py', 'read_only': True})
        with self.assertRaises(ValueError): self.check()

    def test_lab_mode_or_entrypoint_override_is_rejected(self):
        for field, value in (('command', ['phone-sp']), ('entrypoint', ['python', '-c', 'pass'])):
            self.config = copy.deepcopy(self.configuration)
            self.config['services']['sp'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.check()

    def test_missing_revocation_or_added_privilege_is_rejected(self):
        del self.config['services']['bridge']['environment']['OPENID_CONTINUITY_CONFIG']
        with self.assertRaises(ValueError): self.check()
        self.config = copy.deepcopy(self.configuration)
        self.config['services']['verifier']['cap_add'] = ['SYS_ADMIN']
        with self.assertRaises(ValueError): self.check()

    def test_mutable_image_or_environment_override_is_rejected(self):
        self.config['services']['sp']['image'] = 'openid-pilot:latest'
        with self.assertRaises(ValueError): self.check()
        self.config = copy.deepcopy(self.configuration)
        self.config['services']['idp'].setdefault('environment', {})['JAVA_TOOL_OPTIONS'] = '-javaagent:/tmp/agent.jar'
        with self.assertRaises(ValueError): self.check()


if __name__ == '__main__': unittest.main()
