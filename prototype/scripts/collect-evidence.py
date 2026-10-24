"""Package version-bound, synthetic test evidence without promoting it to certification."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--kind", choices=("java", "protocol"), required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--job-status", default="success")
args = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
args.output.mkdir(parents=True, exist_ok=True)
def git(*arguments):
    return subprocess.check_output(["git", "-C", str(repo), *arguments], text=True).strip()
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
manifest = {"schema": "openid-assurance-evidence-v1", "kind": args.kind,
            "generatedAt": datetime.now(timezone.utc).isoformat(), "testedRevision": git("rev-parse", "HEAD"),
            "sourceRevision": os.environ.get("SOURCE_REVISION", git("rev-parse", "HEAD")),
            "workingTreeClean": not bool(git("status", "--porcelain")),
            "runUrl": ("https://github.com/" + os.environ["GITHUB_REPOSITORY"] + "/actions/runs/" + os.environ["GITHUB_RUN_ID"]) if "GITHUB_RUN_ID" in os.environ else None,
            "formalApproval": False, "externalConformance": "NOT RUN", "independentAudit": "NOT PERFORMED",
            "jobStatus": args.job_status, "status": "FAILED", "missingOrFailed": []}
failures = manifest["missingOrFailed"]
if args.job_status != "success": failures.append("workflow did not succeed")
for path in ("prototype/dependencies.lock.json", "prototype/package-lock.json", "docs/provningsunderlag.md", "docs/protocol-sources.json", "docs/SOURCES.md"):
    source = repo / path
    if source.is_file():
        target = args.output / "inputs" / path; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, target)
    else: failures.append("missing input: " + path)
if args.kind == "java":
    suites = []
    for source in sorted((repo / "prototype/target/surefire-reports").glob("TEST-*.xml")):
        tree = ET.parse(source); root = tree.getroot()
        cases = [{"class": t.get("classname"), "name": t.get("name"), "seconds": t.get("time"),
                  "result": "FAIL" if t.find("failure") is not None or t.find("error") is not None else "SKIP" if t.find("skipped") is not None else "PASS"}
                 for t in root.findall("testcase")]
        suites.append({"name": root.get("name"), "tests": len(cases), "cases": cases})
        if not cases or any(c["result"] != "PASS" for c in cases): failures.append("not all cases passed: " + root.get("name", "unknown"))
        # Keep case names, timing and failures; omit JVM properties and console dumps.
        for element in list(root):
            if element.tag != "testcase": root.remove(element)
        for case in root.findall("testcase"):
            for element in list(case):
                if element.tag not in ("failure", "error", "skipped"): case.remove(element)
        target = args.output / "junit" / source.name; target.parent.mkdir(exist_ok=True); tree.write(target, encoding="utf-8", xml_declaration=True)
    required = {"lab.FlowTest", "lab.WebAuthnFlowTest", "lab.DocumentSignatureTest", "lab.SigningCeremonyTest", "lab.SigningFlowTest", "lab.idp.SignatureRequestPolicyTest"}
    missing = required - {s["name"] for s in suites}
    if missing: failures.append("missing required test suites: " + ", ".join(sorted(missing)))
    manifest["suites"] = suites
    for name in ("synthetic-signature.zip", "openssl-results.json"):
        source = repo / "prototype/target/signature-fixtures" / name
        if source.is_file(): shutil.copyfile(source, args.output / name)
        else: failures.append("missing signature evidence: " + name)
    openssl = args.output / "openssl-results.json"
    if openssl.is_file():
        result = json.loads(openssl.read_text())
        checks = result.get("checks", [])
        if result.get("status") != "PASS" or {c.get("id") for c in checks} != {f"SIG-OPENSSL-{i:02}" for i in range(1, 7)} or any(c["result"] != "PASS" for c in checks):
            failures.append("OpenSSL checks incomplete or failed")
        archive = args.output / "synthetic-signature.zip"
        if not archive.is_file() or result.get("archiveSha256") != sha(archive):
            failures.append("OpenSSL results belong to a different signature archive")
    jar = repo / "prototype/target/isolated-eid-lab.jar"
    if jar.is_file(): manifest["jarSha256"] = sha(jar)
    else: failures.append("missing packaged JAR")
else:
    source = args.output / "protocol-results.json"
    if source.is_file():
        result = json.loads(source.read_text()); manifest["jarSha256"] = result.get("jarSha256")
        suites = result.get("suites", [])
        if result.get("status") != "PASS" or len(suites) != 2 or {s.get("protocol") for s in suites} != {"SAML", "OIDC"}:
            failures.append("protocol suites incomplete or failed")
        for suite in suites:
            expected = {"SAML": 5, "OIDC": 11}.get(suite.get("protocol"))
            if suite.get("status") != "PASS" or suite.get("exitCode") != 0 or len(suite.get("checks", [])) != expected:
                failures.append("missing or failed protocol checks")
    else: failures.append("missing protocol results")
manifest["status"] = "PASS" if not failures else "FAILED"
manifest["files"] = [{"path": str(p.relative_to(args.output)), "sha256": sha(p)}
                     for p in sorted(args.output.rglob("*")) if p.is_file() and p.name != "manifest.json"]
(args.output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
print(manifest["status"] + ": " + args.kind + " evidence; formal approval is false")
raise SystemExit(1 if failures else 0)
