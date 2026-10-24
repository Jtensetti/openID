"""Run the real synthetic SAML/OIDC processes and preserve partial results on failure."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
report = {"schema": "openid-protocol-evidence-v1", "scope": "synthetic private pilot integration",
          "formalApproval": False, "officialConformanceSuite": False, "suites": []}
jar = Path("/app/prototype/target/isolated-eid-lab.jar")
report["jarSha256"] = hashlib.sha256(jar.read_bytes()).hexdigest()
args.output.parent.mkdir(parents=True, exist_ok=True)
failed = False
for name, expected_groups in [("saml", 5), ("oidc", 11)]:
    started = time.monotonic()
    suite = {"protocol": name.upper(), "startedAt": datetime.now(timezone.utc).isoformat(), "status": "FAILED"}
    try:
        result = subprocess.run([sys.executable, str(Path(__file__).with_name(name + "-negative-test.py"))],
                                capture_output=True, text=True, timeout=360)
        lines = [line for line in result.stdout.splitlines() if line.startswith("PASS ")]
        suite["checks"] = [{"id": f"{name.upper()}-{i:02}", "result": "PASS", "description": line[5:]}
                           for i, line in enumerate(lines, start=1)]
        suite["expectedGroups"] = expected_groups
        suite["exitCode"] = result.returncode
        if result.returncode == 0 and len(lines) == expected_groups:
            suite["status"] = "PASS"
        else:
            # Only generated test identities are used; no pilot data are mounted.
            print(result.stdout[-16000:] + result.stderr[-8000:], file=sys.stderr)
    except subprocess.TimeoutExpired:
        suite["failure"] = "timeout"
    finally:
        suite["durationSeconds"] = round(time.monotonic() - started, 3)
        report["suites"].append(suite)
        failed |= suite["status"] != "PASS"
        report["status"] = "FAILED" if failed or len(report["suites"]) != 2 else "PASS"
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{suite['status']}: {name.upper()} integration evidence", flush=True)
sys.exit(1 if failed else 0)
