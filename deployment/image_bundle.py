"""Package and verify a tested image; never build or deploy on the target host."""
import argparse
from datetime import datetime, timedelta, timezone
import gzip
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def build_module(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).parent/'build'/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

runtime_policy=build_module('runtime_policy')
component_advisories=build_module('component_advisories')

SCHEMA = "openid-image-bundle-v3"
OS_FILES = ("assessment.json", "database-metadata.json", "os-sbom.cdx.json",
            "scanner-lock.json", "scanner-sbom.json", "system-packages.tsv", "trivy-os.json", "runtime-policy.json",
            "runtime-evidence.json", "component-advisories.json", "applicability.json")
PAYLOADS = ("image.tar.gz", "source.tar.gz", "protocol-results.json", "python-packages.json") + tuple(
    "os-" + name for name in OS_FILES)
BETA_MOUNTS = {
    "vault": {"keys": True, "vault-ipc": False},
    "verifier": {"runtime.json": True, "secrets": True, "data": False, "vault-ipc": True, "continuity.json": True},
    "bridge": {"data": False, "origins.json": True, "federation-ipc": False,
               "notice-ipc": False, "vault-ipc": True, "continuity.json": True},
    "idp": {"federation": False, "federation-ipc": True, "origins.json": True},
    "sp": {"federation": True, "federation-ipc": True, "origins.json": True},
    "notice-exporter": {"notice-ipc": True},
}
BETA_USERS = {"vault": "10005:20002", "verifier": "10001:20002",
              "bridge": "10001:20001", "idp": "10002:20001",
              "sp": "10003:20001", "notice-exporter": "10004:20003"}


def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def protocol_passed(path):
    report = json.loads(path.read_text())
    suites = report.get("suites", [])
    require(report.get("schema") == "openid-protocol-evidence-v1"
            and report.get("status") == "PASS" and len(suites) == 2,
            "Complete passing protocol evidence is required")
    for name, count in [("SAML", 5), ("OIDC", 11)]:
        matches = [s for s in suites if s.get("protocol") == name]
        require(len(matches) == 1, "Missing or duplicate protocol suite")
        suite = matches[0]
        checks = suite.get("checks", [])
        require(suite.get("status") == "PASS" and suite.get("exitCode") == 0
                and suite.get("expectedGroups") == count and len(checks) == count
                and all(c.get("result") == "PASS" for c in checks),
                "Incomplete or failing protocol suite")


def instant(value):
    require(isinstance(value, str), "Missing evidence time")
    # Trivy emits nanoseconds while Python's ISO parser accepts microseconds.
    value = re.sub(r"(\.\d{6})\d+", r"\1", value)
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "Evidence time needs a timezone")
    return result


def os_passed(directory, image_id, revision, bundle_created):
    assessment = json.loads((directory / "os-assessment.json").read_text())
    scan = json.loads((directory / "os-trivy-os.json").read_text())
    metadata = json.loads((directory / "os-database-metadata.json").read_text())
    sbom = json.loads((directory / "os-os-sbom.cdx.json").read_text())
    checked = instant(assessment.get("checkedAt"))
    created = instant(bundle_created)
    require(-timedelta(minutes=5) <= created - checked <= timedelta(hours=1),
            "OS assessment is stale or future-dated at packaging")
    require(assessment.get("format") == 3 and assessment.get("complete") is True
            and assessment.get("passed") is True
            and type(assessment.get("findingCount")) is int and assessment["findingCount"] >= 0
            and type(assessment.get("uniqueAdvisoryCount")) is int
            and assessment["uniqueAdvisoryCount"] >= 0
            and type(assessment.get("unresolvedCount")) is int and assessment["unresolvedCount"] == 0
            and assessment.get("imageID") == image_id
            and assessment.get("sourceRevision") == revision,
            "Complete passing OS assessment for this image and revision required")
    require(type(assessment.get("packageCount")) is int and assessment["packageCount"] > 0
            and re.fullmatch(r"[0-9a-f]{64}", assessment.get("databaseSha256", ""))
            and re.fullmatch(r"[0-9a-f]{64}", assessment.get("scannerLockSha256", ""))
            and scan.get("SchemaVersion") == 2
            and scan.get("Metadata", {}).get("ImageID") == image_id
            and scan.get("Metadata", {}).get("OS", {}).get("Family") == "debian"
            and re.fullmatch(r"13(?:\.\d+)?", scan.get("Metadata", {}).get("OS", {}).get("Name", ""))
            and scan.get("Metadata", {}).get("OS", {}).get("EOSL", False) is False
            and scan.get("Trivy", {}).get("Version") == assessment.get("scannerVersion")
            and scan.get("ArtifactType") == "container_image",
            "OS scanner identity or coverage mismatch")
    require(-timedelta(minutes=5) <= checked - instant(scan.get("CreatedAt")) <= timedelta(hours=1),
            "OS scan time does not match assessment")
    results = scan.get("Results")
    require(isinstance(results, list) and len(results) == 1
            and results[0].get("Class") == "os-pkgs"
            and results[0].get("Type") == "debian"
            and len(results[0].get("Packages", [])) == assessment["packageCount"]
            and not results[0].get("ExperimentalModifiedFindings")
            and len(results[0].get("Vulnerabilities", [])) == assessment["findingCount"]
            and len({v.get("VulnerabilityID") for v in results[0].get("Vulnerabilities", [])}) == assessment["uniqueAdvisoryCount"],
            "OS scanner report does not support passing assessment")
    installed = set()
    for line in (directory / "os-system-packages.tsv").read_text().splitlines():
        fields = line.split("\t")
        require(len(fields) == 4 and fields[3] == "installed", "Invalid OS package inventory")
        installed.add(tuple(fields[:3]))
    scanned = set()
    for package in results[0]["Packages"]:
        version = package["Version"] + ("-" + package["Release"] if package.get("Release") else "")
        if package.get("Epoch"):
            version = str(package["Epoch"]) + ":" + version
        scanned.add((package["Name"], version, package["Arch"]))
    require(len(installed) == len(scanned) == assessment["packageCount"] and installed == scanned,
            "OS package inventory differs from scanner report")
    policy=json.loads((directory/'os-runtime-policy.json').read_text())
    require(policy==json.loads(runtime_policy.POLICY.read_text()), 'Applicability policy differs from trusted checkout')
    require(policy['reviewed'] <= datetime.now(timezone.utc).date().isoformat() < policy['reviewBefore'],
            'Applicability review is not currently valid')
    evidence=json.loads((directory/'os-runtime-evidence.json').read_text())
    require(evidence.get('imageID')==image_id and evidence.get('sourceRevision')==revision
            and evidence.get('policySHA256')==digest(runtime_policy.POLICY), 'Applicability image/source mismatch')
    component=json.loads((directory/'os-component-advisories.json').read_text())
    component_advisories.verify_runtime(component,policy)
    require(-timedelta(minutes=5)<=checked-instant(component.get('checkedAt'))<=timedelta(hours=1),
            'Stale supplemental advisory collection')
    for name in ('index','archive'):
        feed=component[name]
        require(feed.get('url','').startswith(component_advisories.BASE)
                and re.fullmatch(r'[a-f0-9]{64}',feed.get('sha256',''))
                and -timedelta(minutes=5)<=checked-instant(feed.get('lastModified'))<=timedelta(hours=24),
                'Stale or incomplete supplemental advisory feed')
    findings=[{'id':v['VulnerabilityID'],'package':v['PkgName'],'version':v['InstalledVersion']}
              for v in results[0].get('Vulnerabilities',[])]
    findings += component_advisories.runtime_findings(component)
    disposition=runtime_policy.decisions(policy,evidence,findings,checked,source_sha=runtime_policy.source_fingerprint())
    require(disposition==json.loads((directory/'os-applicability.json').read_text())
            and all(r['status'] in ('fixed','not_affected') for r in disposition),
            'Unknown, affected or unsupported applicability decision')
    components = sbom.get("components")
    require(sbom.get("bomFormat") == "CycloneDX" and isinstance(components, list)
            and sbom.get("metadata", {}).get("component", {}).get("type") == "container"
            and sbom["metadata"]["component"].get("name") == image_id
            and {(c.get("name"), c.get("version")) for c in components if c.get("type") == "library"}
            == {(name, version) for name, version, _ in installed},
            "OS SBOM does not cover installed packages")
    require(metadata.get("Version") == 2
            and -timedelta(minutes=5) <= checked - instant(metadata.get("UpdatedAt")) <= timedelta(hours=24)
            and -timedelta(minutes=5) <= checked - instant(metadata.get("DownloadedAt")) <= timedelta(hours=1),
            "OS advisory database was not current at scan time")
    files = assessment.get("files")
    require(isinstance(files, dict) and set(files) == set(OS_FILES) - {"assessment.json"},
            "Incomplete OS evidence manifest")
    for name in OS_FILES:
        if name != "assessment.json":
            require(files[name] == digest(directory / ("os-" + name)),
                    "OS evidence hash mismatch: " + name)


def package(args):
    protocol_passed(args.protocol)
    revision = run("git", "rev-parse", "HEAD")
    tree = run("git", "rev-parse", "HEAD^{tree}")
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "Full source revision required")
    require(not run("git", "status", "--porcelain", "--untracked-files=no"),
            "Tracked source files must be clean")
    info = json.loads(run("docker", "image", "inspect", args.image))[0]
    require(info["Os"] == "linux" and info["Architecture"] == "amd64",
            "Only the tested linux/amd64 platform is supported")
    tag = "openid-pilot:commit-" + revision
    audit = args.os_audit
    require(audit.is_dir() and not audit.is_symlink(), "OS audit directory required")
    for name in OS_FILES:
        source = audit / name
        require(source.is_file() and not source.is_symlink(), "Missing OS audit file: " + name)
    created = datetime.now(timezone.utc).isoformat()
    args.output.mkdir(parents=True, exist_ok=False)
    archive = args.output / "image.tar.gz"
    try:
        for name in OS_FILES:
            shutil.copyfile(audit / name, args.output / ("os-" + name))
        os_passed(args.output, info["Id"], revision, created)
        subprocess.run(["docker", "tag", info["Id"], tag], check=True)
        with archive.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as zipped:
            process = subprocess.Popen(["docker", "save", tag], stdout=subprocess.PIPE)
            try:
                shutil.copyfileobj(process.stdout, zipped)
            finally:
                process.stdout.close()
                status = process.wait()
            require(status == 0, "Docker image export failed")
        shutil.copyfile(args.protocol, args.output / "protocol-results.json")
        shutil.copyfile(args.inventory, args.output / "python-packages.json")
        subprocess.run(["git", "archive", "--format=tar.gz", "--output=" + str(args.output / "source.tar.gz"),
                        revision], check=True)
        manifest = {
            "schema": SCHEMA, "createdAt": created,
            "source": {"revision": revision, "tree": tree},
            "builder": {"repository": os.environ.get("GITHUB_REPOSITORY"),
                        "runId": os.environ.get("GITHUB_RUN_ID"),
                        "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
                        "workflowRef": os.environ.get("GITHUB_WORKFLOW_REF"),
                        "runnerImage": os.environ.get("ImageOS"),
                        "runnerVersion": os.environ.get("ImageVersion"),
                        "dockerVersion": run("docker", "version", "--format", "{{.Server.Version}}")},
            "image": {"id": info["Id"], "tag": tag, "platform": "linux/amd64",
                      "sizeBytes": info["Size"]},
            "files": {name: {"sha256": digest(args.output / name),
                             "bytes": (args.output / name).stat().st_size} for name in PAYLOADS},
            "scope": "private beta candidate; full assurance run must also pass",
            "productionApproved": False,
        }
        path = args.output / "manifest.json"
        path.write_text(json.dumps(manifest, indent=2) + "\n")
        checksum = digest(path)
        print(f"Manifest SHA-256: {checksum}\nSource revision: {revision}\nImage ID: {info['Id']}")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
                summary.write(f"\nImage bundle for `{revision}`\n\nManifest SHA-256: `{checksum}`\n\n"
                              f"Image ID: `{info['Id']}`\n\nFull assurance and release review still required.\n")
    except BaseException:
        # Do not leave a failed export looking like a usable bundle.
        (args.output / "manifest.json").unlink(missing_ok=True)
        raise


def verify(directory, expected_revision, expected_manifest):
    require(re.fullmatch(r"[0-9a-f]{40}", expected_revision), "Expected full commit SHA required")
    require(re.fullmatch(r"[0-9a-f]{64}", expected_manifest), "Expected manifest SHA-256 required")
    manifest_path = directory / "manifest.json"
    require(not manifest_path.is_symlink() and manifest_path.is_file(), "Invalid manifest file")
    require(digest(manifest_path) == expected_manifest, "Manifest checksum mismatch")
    data = json.loads(manifest_path.read_text())
    require(data.get("schema") == SCHEMA, "Unsupported manifest schema")
    require(data["source"]["revision"] == expected_revision, "Source revision mismatch")
    require(re.fullmatch(r"[0-9a-f]{40}", data["source"]["tree"]), "Invalid Git tree")
    info = data["image"]
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", info["id"]), "Invalid image ID")
    require(info["tag"] == "openid-pilot:commit-" + expected_revision, "Image tag mismatch")
    require(info["platform"] == "linux/amd64", "Unsupported image platform")
    require(type(info["sizeBytes"]) is int and info["sizeBytes"] > 0, "Invalid image size")
    require(data.get("productionApproved") is False, "Unexpected approval claim")
    require(set(data["files"]) == set(PAYLOADS), "Unexpected bundle payloads")
    for name in PAYLOADS:
        path = directory / name
        require(not path.is_symlink() and path.is_file(), "Invalid payload file")
        entry = data["files"][name]
        require(path.stat().st_size == entry["bytes"] and digest(path) == entry["sha256"],
                "Payload checksum or size mismatch: " + name)
    protocol_passed(directory / "protocol-results.json")
    os_passed(directory, info["id"], expected_revision, data.get("createdAt"))
    return data


def import_image(directory, data):
    daemon = json.loads(run("docker", "info", "--format", "{{json .}}"))
    require(daemon["OSType"] == "linux" and daemon["Architecture"] in ("x86_64", "amd64"),
            "Target daemon must run linux/amd64")
    root = Path(daemon["DockerRootDir"])
    require(root.is_dir(), "Use a local Docker daemon; its storage must be measurable")
    # Allow both unpacking and layer registration, retaining 512 MiB headroom.
    required = 2 * data["image"]["sizeBytes"] + 512 * 1024**2
    require(shutil.disk_usage(root).free >= required, "Insufficient Docker storage; no image was loaded")
    subprocess.run(["docker", "load", "--input", str(directory / "image.tar.gz")], check=True)
    actual = json.loads(run("docker", "image", "inspect", data["image"]["tag"]))[0]
    require(actual["Id"] == data["image"]["id"] and actual["Os"] == "linux"
            and actual["Architecture"] == "amd64", "Loaded image identity or platform mismatch")
    print("Verified image loaded: " + actual["Id"] + "; no service was started or changed")


def check_beta_mounts(service, mounts, readonly_root, tmpfs):
    """Allow only runtime data/config mounts; packaged code must remain visible."""
    require(readonly_root is True, "Beta root filesystem must be read-only")
    expected = {"/srv/openid/" + name: readonly for name, readonly in BETA_MOUNTS[service].items()}
    require(len(mounts) == len(expected) and dict(mounts) == expected,
            "Beta mounts must match the data/config boundary; code overrides are forbidden")
    require(set(tmpfs) <= {"/tmp"}, "Beta tmpfs must not cover packaged code")


def check_beta_compose(config, image_id):
    """Check rendered Compose input without starting Docker or reading private files."""
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", image_id), "Full image ID required")
    services = config.get("services", {})
    require(set(services) == set(BETA_MOUNTS), "Unexpected beta service set")
    for name, service in services.items():
        require(service.get("image") == image_id and "build" not in service,
                "Every beta service must use the verified image without building")
        require(service.get("user") == BETA_USERS[name], "Beta service identity mismatch")
        expected_groups = ["20002", "20003"] if name == "bridge" else []
        require([str(x) for x in service.get("group_add", [])] == expected_groups,
                "Unexpected beta supplementary groups")
        require(not any(service.get(key) for key in ("configs", "secrets", "volumes_from")),
                "Unexpected additional beta mounts")
        require(service.get("environment", {}).get("LOCALDOMAIN", "") == "",
                "DNS search-list mitigation cannot be overridden")
        volumes = service.get("volumes", [])
        require(all(v.get("type") == "bind" and type(v.get("read_only", False)) is bool for v in volumes),
                "Only explicit beta bind mounts are supported")
        check_beta_mounts(name, [(v.get("target"), v.get("read_only", False)) for v in volumes],
                          service.get("read_only"), [v.split(":", 1)[0] for v in service.get("tmpfs", [])])
    print("Verified beta image and mount configuration; no service was changed")


def check_beta_running(image_id):
    """Read Docker state; reject missing, extra or drifted beta containers."""
    ids = run("docker", "container", "ls", "--all", "--filter",
              "label=com.docker.compose.project=openid-beta", "--format", "{{.ID}}").splitlines()
    require(ids, "No beta containers found")
    containers = json.loads(run("docker", "container", "inspect", *ids))
    expected = set(BETA_MOUNTS)
    services = [c.get("Config", {}).get("Labels", {}).get("com.docker.compose.service")
                for c in containers]
    require(len(containers) == len(ids) == len(expected) and set(services) == expected,
            "Beta service set is incomplete, duplicated or unexpected")
    for container in containers:
        require(container.get("State", {}).get("Running") is True
                and container.get("Image") == image_id
                and container.get("Config", {}).get("Image") == image_id,
                "Beta container is stopped, uses a mutable tag or has image drift")
        require([e for e in container["Config"].get("Env", []) if e.startswith("LOCALDOMAIN=")] == ["LOCALDOMAIN="],
                "DNS search-list mitigation missing in running service")
        service = container["Config"]["Labels"]["com.docker.compose.service"]
        require(container["Config"].get("User") == BETA_USERS[service], "Running beta service UID mismatch")
        expected_groups = ["20002", "20003"] if service == "bridge" else []
        require([str(x) for x in container.get("HostConfig", {}).get("GroupAdd") or []] == expected_groups,
                "Running beta supplementary group mismatch")
        mounts = container.get("Mounts", [])
        require(all(m.get("Type") == "bind" and type(m.get("RW")) is bool for m in mounts),
                "Only explicit beta bind mounts are supported")
        host = container.get("HostConfig", {})
        check_beta_mounts(service, [(m.get("Destination"), not m["RW"]) for m in mounts],
                          host.get("ReadonlyRootfs"), host.get("Tmpfs", {}))
    print("Verified running beta image: " + image_id + "; no service was changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    export = sub.add_parser("package")
    export.add_argument("--image", required=True)
    export.add_argument("--protocol", required=True, type=Path)
    export.add_argument("--inventory", required=True, type=Path)
    export.add_argument("--os-audit", required=True, type=Path)
    export.add_argument("--output", required=True, type=Path)
    compose = sub.add_parser("check-beta-compose")
    compose.add_argument("--image-id", required=True)
    for command in ("verify", "import", "check-beta"):
        check = sub.add_parser(command)
        check.add_argument("--directory", required=True, type=Path)
        check.add_argument("--expected-revision", required=True)
        check.add_argument("--expected-manifest-sha256", required=True)
    args = parser.parse_args()
    if args.command == "package":
        package(args)
    elif args.command == "check-beta-compose":
        check_beta_compose(json.load(sys.stdin), args.image_id)
    else:
        data = verify(args.directory, args.expected_revision, args.expected_manifest_sha256)
        if args.command == "import":
            import_image(args.directory, data)
        elif args.command == "check-beta":
            check_beta_running(data["image"]["id"])
        else:
            print("Verified bundle: " + data["image"]["id"])


if __name__ == "__main__":
    main()
