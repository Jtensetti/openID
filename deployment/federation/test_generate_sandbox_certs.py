"""Local safety tests for the disposable, separate federation certificates."""
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).with_name("generate-sandbox-certs.sh")


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
class SandboxCertificatesTest(unittest.TestCase):
    def test_generates_distinct_keys_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp, SOURCE.name)
            shutil.copyfile(SOURCE, script)
            first = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=45)
            self.assertEqual(first.returncode, 0, first.stderr)
            output = Path(tmp, ".local")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            fingerprints = set()
            for role in ("signing", "encryption"):
                private = output / f"saml-{role}.key"
                public = output / f"saml-{role}.crt"
                for path in (private, public):
                    self.assertTrue(path.is_file())
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                verified = subprocess.run(["openssl", "verify", "-CAfile", str(public), str(public)], capture_output=True, text=True)
                self.assertEqual(verified.returncode, 0, verified.stderr)
                fingerprint = subprocess.check_output(["openssl", "x509", "-in", str(public), "-noout", "-fingerprint", "-sha256"], text=True)
                fingerprints.add(fingerprint)
                cert = subprocess.check_output(["openssl", "x509", "-in", str(public), "-noout", "-text"], text=True)
                self.assertIn("CA:FALSE", cert)
                self.assertIn("Digital Signature" if role == "signing" else "Key Encipherment", cert)
                pub_from_key = subprocess.check_output(["openssl", "pkey", "-in", str(private), "-pubout"], text=True)
                pub_from_cert = subprocess.check_output(["openssl", "x509", "-in", str(public), "-pubkey", "-noout"], text=True)
                self.assertEqual(pub_from_key, pub_from_cert)
            self.assertEqual(len(fingerprints), 2)
            original = (output / "saml-signing.key").read_bytes()
            second = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(original, (output / "saml-signing.key").read_bytes())

    def test_rejects_existing_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp, SOURCE.name)
            shutil.copyfile(SOURCE, script)
            external = Path(tmp, "outside")
            external.mkdir()
            Path(tmp, ".local").symlink_to(external)
            res = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(res.returncode, 0)
            self.assertEqual(list(external.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
