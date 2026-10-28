"""Real OpenPGP regressions with generated public fixtures, never issuer keys."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from bootstrap import sha
from build import verify_signature


class RealSignaturePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('gpg') or not shutil.which('gpgv'):
            raise RuntimeError('GnuPG gpg and gpgv are required; signature policy must not be skipped')
        cls.fixtures = Path(__file__).with_name('fixtures') / 'signature-policy'
        cls.manifest = json.loads((cls.fixtures / 'manifest.json').read_text())
        for name, digest in cls.manifest['files'].items():
            if sha((cls.fixtures / name).read_bytes()) != digest:
                raise ValueError('generated signature fixture changed: ' + name)
        print(subprocess.check_output(['gpgv', '--version'], text=True).splitlines()[0])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='openid-sig-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.log = self.home / 'verification.log'

    def verify(self, key='valid-key.asc', signature='valid.sig.asc', signer=None, payload=None):
        ring = self.home / 'fixture.gpg'
        subprocess.run(['gpg', '--batch', '--no-options', '--homedir', str(self.home),
                        '--dearmor', '--output', str(ring), str(self.fixtures / key)],
                       check=True, capture_output=True, timeout=15)
        with contextlib.redirect_stdout(io.StringIO()):
            return verify_signature(self.fixtures / signature,
                                    payload or self.fixtures / 'payload.txt', ring,
                                    self.home, self.log,
                                    signer or self.manifest['validPrimaryFingerprint'])

    def rejected(self, status, **kwargs):
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            self.verify(**kwargs)
        self.assertIn('[GNUPG:] ' + status + ' ', self.log.read_text())

    def test_valid_signature_requires_the_full_expected_signer(self):
        self.assertEqual(self.verify(), self.manifest['validPrimaryFingerprint'])

    def test_expired_key_rejected_even_if_the_cryptographic_signature_is_valid(self):
        self.rejected('EXPKEYSIG', key='expired-key.asc', signature='expired-key.sig.asc',
                      signer=self.manifest['expiredPrimaryFingerprint'])
        self.assertIn('[GNUPG:] VALIDSIG ', self.log.read_text())

    def test_revocation_in_the_key_copy_is_rejected(self):
        self.rejected('REVKEYSIG', key='revoked-key.asc')
        self.assertIn('[GNUPG:] VALIDSIG ', self.log.read_text())

    def test_expired_signature_is_rejected(self):
        self.rejected('EXPSIG', signature='expired-signature.sig.asc')

    def test_modified_payload_is_rejected(self):
        payload = self.home / 'changed.txt'
        payload.write_bytes((self.fixtures / 'payload.txt').read_bytes() + b'changed\n')
        self.rejected('BADSIG', payload=payload)

    def test_missing_signer_is_rejected(self):
        self.rejected('NO_PUBKEY', key='expired-key.asc')

    def test_valid_signature_from_unexpected_signer_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unexpected signing key'):
            self.verify(signer=self.manifest['expiredPrimaryFingerprint'])
        self.assertIn('[GNUPG:] VALIDSIG ', self.log.read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
