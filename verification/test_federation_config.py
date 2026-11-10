import json
from pathlib import Path
import tempfile
import unittest
from federation_config import read_profile, sandbox_enabled


class FederationConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name).resolve() / 'federation.json'

    def write(self, value):
        self.path.write_text(value)
        self.path.chmod(0o644)
        return self.path

    def test_only_two_explicit_profiles(self):
        for profile, expected in [('private', False), ('sweden-connect-sandbox', True)]:
            self.assertEqual(expected, read_profile(self.write(json.dumps({'version': 1, 'profile': profile}))))
        for value in ({}, None, [], {'version': True, 'profile': 'private'}, {'version': 1, 'profile': 'production'},
                      {'version': 1, 'profile': 'private', 'url': 'https://attacker.invalid'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                read_profile(self.write(json.dumps(value)))

    def test_duplicate_trailing_missing_and_oversize_input_rejected(self):
        for value in ('', ' ' * 4097, '{"version":1,"profile":"private","profile":"sweden-connect-sandbox"}',
                      '{"version":1,"profile":"private"} {}'):
            with self.subTest(value=value[:80]), self.assertRaises(ValueError):
                read_profile(self.write(value))
        self.path.unlink()
        with self.assertRaises(OSError): read_profile(self.path)

    def test_writable_and_linked_files_rejected(self):
        self.write('{"version":1,"profile":"private"}')
        self.path.chmod(0o664)
        with self.assertRaises(ValueError): read_profile(self.path)
        link = self.path.with_name('link.json')
        link.symlink_to(self.path)
        with self.assertRaises(ValueError): read_profile(link)

    def test_no_legacy_override_of_shared_profile(self):
        self.write('{"version":1,"profile":"sweden-connect-sandbox"}')
        environment = {'OPENID_FEDERATION_CONFIG': str(self.path)}
        self.assertTrue(sandbox_enabled(environment))
        for value in ('true', 'false', ''):
            with self.assertRaises(ValueError):
                sandbox_enabled({**environment, 'OPENID_SWEDEN_CONNECT_SANDBOX': value})
        self.assertFalse(sandbox_enabled({}))
        self.assertTrue(sandbox_enabled({'OPENID_SWEDEN_CONNECT_SANDBOX': 'true'}))
        with self.assertRaises(ValueError): sandbox_enabled({'OPENID_SWEDEN_CONNECT_SANDBOX': 'TRUE'})


if __name__ == '__main__': unittest.main()
