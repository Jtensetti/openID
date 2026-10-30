"""Reject untrusted, damaged or mismatched bundles before changing Docker."""
from datetime import datetime, timezone
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import image_bundle as bundle


def beta_configuration(image):
    paths = {
        "verifier": [("runtime.json", True), ("secrets", True), ("data", False), ("continuity.json", True)],
        "bridge": [("data", False), ("origins.json", True), ("continuity.json", True)],
        "idp": [("data", False), ("federation", False), ("origins.json", True)],
        "sp": [("data", False), ("federation", True), ("origins.json", True)],
        "notice-exporter": [("data", False), ("continuity.json", True)],
    }
    return {"services": {name: {"image": image, "read_only": True, "tmpfs": ["/tmp:size=16m"],
        "volumes": [{"type": "bind", "source": "/private/" + path,
                     "target": "/srv/openid/" + path, "read_only": readonly}
                    for path, readonly in mounts]} for name, mounts in paths.items()}}


def running_containers(config):
    return [{"Config": {"Image": s["image"], "Labels": {"com.docker.compose.service": name}},
             "Image": s["image"], "State": {"Running": True},
             "HostConfig": {"ReadonlyRootfs": s["read_only"], "Tmpfs": {"/tmp": "size=16m"}},
             "Mounts": [{"Type": v["type"], "Destination": v["target"], "RW": not v["read_only"]}
                        for v in s["volumes"]]} for name, s in config["services"].items()]


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
        now = datetime.now(timezone.utc).isoformat()
        self.data = {
            "schema": bundle.SCHEMA, "createdAt": now,
            "source": {"revision": self.revision, "tree": "b" * 40},
            "image": {"id": "sha256:" + "c" * 64, "tag": "openid-pilot:commit-" + self.revision,
                      "sizeBytes": 1024, "platform": "linux/amd64"},
            "files": {}, "productionApproved": False}
        self.assessment = {"format": 1, "complete": True, "passed": True,
                           "checkedAt": now, "imageID": self.data["image"]["id"],
                           "sourceRevision": self.revision, "scannerVersion": "0.76.1",
                           "packageCount": 1, "findingCount": 0, "uniqueAdvisoryCount": 0,
                           "databaseSha256": "f" * 64}
        os_files = {
            "database-metadata.json": {"Version": 2, "UpdatedAt": now, "DownloadedAt": now},
            "os-sbom.cdx.json": {"bomFormat": "CycloneDX", "metadata": {
                "component": {"type": "container", "name": self.data["image"]["id"]}}, "components": [
                {"name": "synthetic", "version": "1", "type": "library"}]},
            "scanner-lock.json": {"version": "0.76.1"},
            "scanner-sbom.json": {"components": [{"name": "scanner"}]},
            "system-packages.tsv": "synthetic\t1\tamd64\tinstalled\n",
            "trivy-os.json": {"SchemaVersion": 2, "CreatedAt": now,
                              "ArtifactType": "container_image", "Metadata": {"ImageID": self.data["image"]["id"],
                              "OS": {"Family": "debian", "Name": "13.7"}},
                              "Trivy": {"Version": "0.76.1"}, "Results": [{"Class": "os-pkgs",
                              "Type": "debian", "Packages": [{"Name": "synthetic", "Version": "1",
                              "Arch": "amd64"}], "Vulnerabilities": []}]},
        }
        for name, value in os_files.items():
            (self.root / ("os-" + name)).write_text(value if isinstance(value, str) else json.dumps(value))
        self.seal_os()
        self.seal()

    def seal_os(self):
        self.assessment["scannerLockSha256"] = bundle.digest(self.root / "os-scanner-lock.json")
        self.assessment["files"] = {name: bundle.digest(self.root / ("os-" + name))
                                     for name in bundle.OS_FILES if name != "assessment.json"}
        (self.root / "os-assessment.json").write_text(json.dumps(self.assessment))

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

    def test_os_evidence_cannot_be_omitted_or_resealed_with_wrong_image(self):
        (self.root / "os-assessment.json").unlink()
        with self.assertRaisesRegex(ValueError, "Invalid payload"):
            self.verify()
        self.assessment["imageID"] = "sha256:" + "d" * 64
        self.seal_os(); self.seal()
        with self.assertRaisesRegex(ValueError, "passing OS assessment"):
            self.verify()

    def test_stale_or_failed_os_audit_blocks_even_when_manifest_is_resealed(self):
        for change in ({"passed": False}, {"complete": False}, {"findingCount": 1},
                       {"checkedAt": "2020-01-01T00:00:00+00:00"}):
            with self.subTest(change=change):
                original = dict(self.assessment)
                self.assessment.update(change)
                self.seal_os(); self.seal()
                with self.assertRaises(ValueError): self.verify()
                self.assessment = original

    def test_os_scan_cannot_hide_finding_with_resealed_manifest(self):
        path = self.root / "os-trivy-os.json"
        scan = json.loads(path.read_text())
        scan["Results"][0]["Vulnerabilities"] = [{"VulnerabilityID": "TEST"}]
        path.write_text(json.dumps(scan)); self.seal_os(); self.seal()
        with self.assertRaisesRegex(ValueError, "scanner report"):
            self.verify()

    def test_os_package_mismatch_and_stale_database_are_rejected(self):
        inventory = self.root / "os-system-packages.tsv"
        inventory.write_text("different\t1\tamd64\tinstalled\n")
        self.seal_os(); self.seal()
        with self.assertRaisesRegex(ValueError, "package inventory"):
            self.verify()
        inventory.write_text("synthetic\t1\tamd64\tinstalled\n")
        metadata = self.root / "os-database-metadata.json"
        data = json.loads(metadata.read_text()); data["UpdatedAt"] = "2020-01-01T00:00:00+00:00"
        metadata.write_text(json.dumps(data)); self.seal_os(); self.seal()
        with self.assertRaisesRegex(ValueError, "database was not current"):
            self.verify()

    def test_os_sbom_must_cover_installed_packages(self):
        path = self.root / "os-os-sbom.cdx.json"
        data = json.loads(path.read_text()); data["components"][0]["version"] = "2"
        path.write_text(json.dumps(data)); self.seal_os(); self.seal()
        with self.assertRaisesRegex(ValueError, "SBOM does not cover"):
            self.verify()
        data["components"][0]["version"] = "1"
        data["metadata"]["component"]["name"] = "sha256:" + "d" * 64
        path.write_text(json.dumps(data)); self.seal_os(); self.seal()
        with self.assertRaisesRegex(ValueError, "SBOM does not cover"):
            self.verify()

    def test_package_refuses_failed_os_before_tag_or_export(self):
        audit = self.root / "audit"
        audit.mkdir()
        for name in bundle.OS_FILES:
            (audit / name).write_bytes((self.root / ("os-" + name)).read_bytes())
        data = json.loads((audit / "assessment.json").read_text())
        data["passed"] = False
        (audit / "assessment.json").write_text(json.dumps(data))
        inspect = json.dumps([{"Os": "linux", "Architecture": "amd64",
                               "Id": self.data["image"]["id"], "Size": 1024}])
        args = SimpleNamespace(protocol=self.root / "protocol-results.json", image="synthetic:ci",
                               os_audit=audit, output=self.root / "export")
        with patch.object(bundle, "run", side_effect=[self.revision, "b" * 40, "", inspect]), \
                patch.object(bundle.subprocess, "run") as docker, \
                self.assertRaisesRegex(ValueError, "passing OS assessment"):
            bundle.package(args)
        docker.assert_not_called()
        self.assertFalse((args.output / "manifest.json").exists())

    def test_beta_running_requires_exact_pinned_image_for_every_service(self):
        image = self.data["image"]["id"]
        containers = running_containers(beta_configuration(image))
        ids = "\n".join(str(i) for i in range(len(containers)))
        with patch.object(bundle, "run", side_effect=[ids, json.dumps(containers)]):
            bundle.check_beta_running(image)
        containers[0]["Config"]["Image"] = "openid-pilot:beta"
        with patch.object(bundle, "run", side_effect=[ids, json.dumps(containers)]), \
                self.assertRaisesRegex(ValueError, "mutable tag"):
            bundle.check_beta_running(image)
        containers[0]["Config"]["Image"] = image
        containers[0]["Image"] = "sha256:" + "d" * 64
        with patch.object(bundle, "run", side_effect=[ids, json.dumps(containers)]), \
                self.assertRaisesRegex(ValueError, "image drift"):
            bundle.check_beta_running(image)
        with patch.object(bundle, "run", side_effect=[ids, json.dumps(containers[:-1])]), \
                self.assertRaisesRegex(ValueError, "service set"):
            bundle.check_beta_running(image)

    def test_compose_rejects_code_mounts_even_read_only_and_other_overlay_forms(self):
        image = self.data["image"]["id"]
        good = beta_configuration(image)
        bundle.check_beta_compose(good, image)
        for target in ("/", "/app", "/app/verification/federation.py", "/usr/local/lib/python3.12"):
            for readonly in (True, False):
                with self.subTest(target=target, readonly=readonly):
                    config = deepcopy(good)
                    config["services"]["bridge"]["volumes"].append(
                        {"type": "bind", "source": "/private/override", "target": target, "read_only": readonly})
                    with self.assertRaisesRegex(ValueError, "code overrides"):
                        bundle.check_beta_compose(config, image)
        for key, value in (("tmpfs", ["/app:size=16m"]), ("configs", [{"source": "code", "target": "/app/code.py"}]),
                           ("secrets", [{"source": "code", "target": "/app/code.py"}]), ("volumes_from", ["other"]),
                           ("build", "."), ("read_only", False), ("image", "openid-pilot:beta")):
            with self.subTest(key=key):
                config = deepcopy(good); config["services"]["bridge"][key] = value
                with self.assertRaises(ValueError): bundle.check_beta_compose(config, image)

    def test_running_check_rejects_code_override_and_writable_configuration(self):
        image = self.data["image"]["id"]
        good = running_containers(beta_configuration(image))
        ids = "\n".join(str(i) for i in range(len(good)))
        for change in ("code", "writable_config", "writable_root", "tmpfs", "missing_mount", "named_volume"):
            with self.subTest(change=change):
                containers = deepcopy(good); c = containers[0]
                if change == "code": c["Mounts"].append({"Type": "bind", "Destination": "/app/verification/probe.py", "RW": False})
                elif change == "writable_config": c["Mounts"][0]["RW"] = True
                elif change == "writable_root": c["HostConfig"]["ReadonlyRootfs"] = False
                elif change == "tmpfs": c["HostConfig"]["Tmpfs"]["/app"] = "size=16m"
                elif change == "missing_mount": c["Mounts"].pop()
                elif change == "named_volume": c["Mounts"][0]["Type"] = "volume"
                with patch.object(bundle, "run", side_effect=[ids, json.dumps(containers)]), self.assertRaises(ValueError):
                    bundle.check_beta_running(image)

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
