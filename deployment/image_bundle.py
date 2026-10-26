"""Package and verify a tested image; never build or deploy on the target host."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


SCHEMA = "openid-image-bundle-v1"
PAYLOADS = ("image.tar.gz", "source.tar.gz", "protocol-results.json", "python-packages.json")


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
    subprocess.run(["docker", "tag", info["Id"], tag], check=True)
    args.output.mkdir(parents=True, exist_ok=False)
    archive = args.output / "image.tar.gz"
    try:
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
            "schema": SCHEMA, "createdAt": datetime.now(timezone.utc).isoformat(),
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    export = sub.add_parser("package")
    export.add_argument("--image", required=True)
    export.add_argument("--protocol", required=True, type=Path)
    export.add_argument("--inventory", required=True, type=Path)
    export.add_argument("--output", required=True, type=Path)
    for command in ("verify", "import"):
        check = sub.add_parser(command)
        check.add_argument("--directory", required=True, type=Path)
        check.add_argument("--expected-revision", required=True)
        check.add_argument("--expected-manifest-sha256", required=True)
    args = parser.parse_args()
    if args.command == "package":
        package(args)
    else:
        data = verify(args.directory, args.expected_revision, args.expected_manifest_sha256)
        if args.command == "import":
            import_image(args.directory, data)
        else:
            print("Verified bundle: " + data["image"]["id"])


if __name__ == "__main__":
    main()
