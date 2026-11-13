"""Exercise password transport with the real JDK launcher and PKCS12 reader."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from runtime_test_fixture import RuntimeFixture


@unittest.skipUnless(shutil.which('keytool') and shutil.which('openssl'), 'JDK and OpenSSL required')
class FixturePasswordTests(unittest.TestCase):
    def test_launcher_prefix_password_is_not_a_java_option(self):
        password = '-J' + 'A' * 41
        run = subprocess.run
        with tempfile.TemporaryDirectory() as directory, \
                patch('runtime_test_fixture.secrets.token_urlsafe', return_value=password), \
                patch('runtime_test_fixture.subprocess.run', wraps=run) as calls:
            fixture = RuntimeFixture(Path(directory))
            for call in calls.call_args_list:
                if call.args[0][0] == 'keytool':
                    self.assertNotIn(password, call.args[0])
                    self.assertEqual(call.kwargs['env']['OPENID_FIXTURE_PASSWORD'], password)
            self.assertNotEqual(os.environ.get('OPENID_FIXTURE_PASSWORD'), password)
            for alias in ('idp', 'sp'):
                self.assertIn('PRIVATE KEY', fixture.private_pem(alias).read_text())


if __name__ == '__main__':
    unittest.main()
