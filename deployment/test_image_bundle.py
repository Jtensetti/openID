"""Reject untrusted, damaged or mismatched bundles before changing Docker."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import image_bundle as bundle


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.revision = "a" * 40
        report = {"schema": "openid-protocol-evidence-v1", "status": "PASS", "suites": [
            {"protocol": name, "status": "PASS", "exitCode": 0, "expectedGroups": count,
             "checks": [{"result": "PASS"} for _ in range(count)]}
            for name, count in [("SAML", 5), ("OIDC", 11)]]}
        (self.root / "protocol-results.json").write_text(json.dumps(report))
        (self.root / "python-packages.json").write_text("{}")
        (self.root / "image.tar.gz").write_bytes(b"synthetic unit-test payload")
        (self.root / "source.tar.gz").write_bytes(b"synthetic source payload")
        self.data = {
            "schema": bundle.SCHEMA, "source": {"revision": self.revision, "tree": "b" * 40},
            "image": {"id": "sha256:" + "c" * 64, "tag": "openid-pilot:commit-" + self.revision,
                      "sizeBytes": 1024, "platform": "linux/amd64"},
            "files": {}, "productionApproved": False}
        self.seal()

    def seal(self):
        self.data["files"] = {n: {"sha256": bundle.digest(self.root / n),
                                  "bytes": (self.root / n).stat().st_size} for n in bundle.PAYLOADS}
        path = self.root / "manifest.json"
        path.write_text(json.dumps(self.data))
        self.expected = bundle.digest(path)

    def verify(self):
        return bundle.verify(self.root, self.revision, self.expected)

    def test_valid_bundle_is_checked_without_docker(self):
        with patch.object(bundle.subprocess, "check_output") as docker:
            self.assertEqual(self.verify()["image"]["id"], self.data["image"]["id"])
            docker.assert_not_called()

    def test_archive_damage(self):
        path = self.root / "image.tar.gz"
        path.write_bytes(path.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "Payload checksum"):
            self.verify()

    def test_manifest_tampering(self):
        self.data["source"]["revision"] = "d" * 40
        (self.root / "manifest.json").write_text(json.dumps(self.data))
        with self.assertRaisesRegex(ValueError, "Manifest checksum"):
            self.verify()

    def test_wrong_expected_revision(self):
        self.revision = "d" * 40
        with self.assertRaisesRegex(ValueError, "revision mismatch"):
            self.verify()

    def test_short_revision_not_accepted(self):
        self.revision = "abcdef0"
        with self.assertRaisesRegex(ValueError, "full commit"):
            self.verify()

    def test_missing_payload(self):
        (self.root / "image.tar.gz").unlink()
        with self.assertRaisesRegex(ValueError, "Invalid payload"):
            self.verify()

    def test_symlink_payload(self):
        (self.root / "image.tar.gz").rename(self.root / "external")
        (self.root / "image.tar.gz").symlink_to(self.root / "external")
        with self.assertRaisesRegex(ValueError, "Invalid payload"):
            self.verify()

    def test_unsupported_platform(self):
        self.data["image"]["platform"] = "linux/arm64"
        self.seal()
        with self.assertRaisesRegex(ValueError, "platform"):
            self.verify()

    def test_failed_or_incomplete_protocol_evidence(self):
        path = self.root / "protocol-results.json"
        original = path.read_text()
        for kind in ("failure", "missing", "duplicate", "partial"):
            with self.subTest(kind=kind):
                data = json.loads(original)
                if kind == "failure": data["suites"][1]["exitCode"] = 1
                elif kind == "missing": data["suites"].pop()
                elif kind == "duplicate": data["suites"][1] = data["suites"][0]
                else: data["suites"][1]["checks"].pop()
                path.write_text(json.dumps(data))
                self.seal()
                with self.assertRaises(ValueError): self.verify()

    def test_low_disk_never_loads(self):
        daemon = json.dumps({"OSType": "linux", "Architecture": "x86_64", "DockerRootDir": str(self.root)})
        with patch.object(bundle, "run", return_value=daemon), \
                patch.object(bundle.shutil, "disk_usage") as disk, \
                patch.object(bundle.subprocess, "run") as load:
            disk.return_value.free = 1
            with self.assertRaisesRegex(ValueError, "Insufficient"):
                bundle.import_image(self.root, self.verify())
            load.assert_not_called()

    def test_loaded_image_must_match(self):
        daemon = json.dumps({"OSType": "linux", "Architecture": "x86_64", "DockerRootDir": str(self.root)})
        wrong = json.dumps([{"Id": "sha256:" + "d" * 64, "Os": "linux", "Architecture": "amd64"}])
        with patch.object(bundle, "run", side_effect=[daemon, wrong]), \
                patch.object(bundle.shutil, "disk_usage") as disk, \
                patch.object(bundle.subprocess, "run") as load:
            disk.return_value.free = 2**40
            with self.assertRaisesRegex(ValueError, "Loaded image"):
                bundle.import_image(self.root, self.verify())
            self.assertEqual(load.call_args.args[0][:2], ["docker", "load"])


if __name__ == "__main__":
    unittest.main()
