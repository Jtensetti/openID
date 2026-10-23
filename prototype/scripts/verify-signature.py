"""Independent OpenSSL implementation checks of a SYNTHETIC fixture, never a production trust decision."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("archive", type=Path)
parser.add_argument("--report", required=True, type=Path)
args = parser.parse_args()
checks = []
report = {"kind": "synthetic-document-signature-openssl", "formalApproval": False,
          "independentAudit": False, "checks": checks, "status": "FAILED"}

def run(command):
    return subprocess.run(command, capture_output=True, timeout=30)

try:
    report["openssl"] = run(["openssl", "version"]).stdout.decode().strip()
    report["archiveSha256"] = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        names = {"document.txt", "document.p7s", "signer.crt", "test-ca.crt", "evidence.json"}
        with zipfile.ZipFile(args.archive) as z:
            assert len(z.infolist()) == 5 and set(z.namelist()) == names
            for name in names:
                assert z.getinfo(name).file_size <= 65536
                (root / name).write_bytes(z.read(name))
        evidence = json.loads((root / "evidence.json").read_text())
        assert evidence["proofing"] == "SIMULATED" and evidence["signer"] == "SYNTHETIC-alice"
        assert hashlib.sha256((root / "document.txt").read_bytes()).hexdigest() == evidence["documentSha256"]
        # This is a test CA supplied by the fixture, not a trust list or a trusted timestamp.
        common = ["openssl", "cms", "-verify", "-verify_retcode", "-binary", "-inform", "DER", "-cades",
                  "-in", str(root / "document.p7s"), "-content", str(root / "document.txt"),
                  "-CAfile", str(root / "test-ca.crt"), "-no-CApath", "-no-CAstore", "-purpose", "any",
                  "-signer", str(root / "actual-signer.crt"), "-out", str(root / "verified.txt")]
        result = run(common)
        assert result.returncode == 0, result.stderr.decode()
        assert (root / "verified.txt").read_bytes() == (root / "document.txt").read_bytes()
        subject = run(["openssl", "x509", "-in", str(root / "actual-signer.crt"), "-noout", "-subject", "-nameopt", "RFC2253"])
        assert subject.returncode == 0 and subject.stdout.decode().strip() == "subject=CN=SYNTHETIC-alice"
        checks.append({"id": "SIG-OPENSSL-01", "result": "PASS", "check": "signature, exact bytes, ESS certificate binding, chain, current time and signer"})
        original = (root / "document.txt").read_bytes()
        for case, changed in [("SIG-OPENSSL-02", original + b"tampered"), ("SIG-OPENSSL-03", original.replace(b"\n", b"\r\n"))]:
            (root / "document.txt").write_bytes(changed)
            assert run(common).returncode != 0
            checks.append({"id": case, "result": "PASS", "check": "changed document rejected"})
        (root / "document.txt").write_bytes(original)
        # A separate, generated CA has the same test-only name but cannot validate this signer.
        generated = run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=SYNTHETIC-ONLY document test CA",
                         "-keyout", str(root / "other.key"), "-out", str(root / "other.crt")])
        assert generated.returncode == 0
        wrong = common.copy(); wrong[wrong.index("-CAfile") + 1] = str(root / "other.crt")
        assert run(wrong).returncode != 0
        checks.append({"id": "SIG-OPENSSL-04", "result": "PASS", "check": "untrusted CA rejected"})
        import time
        assert run(common + ["-attime", str(int(time.time()) + 7200)]).returncode != 0
        checks.append({"id": "SIG-OPENSSL-05", "result": "PASS", "check": "expired certificate rejected"})
        signature = bytearray((root / "document.p7s").read_bytes()); signature[-1] ^= 1
        (root / "document.p7s").write_bytes(signature)
        assert run(common).returncode != 0
        checks.append({"id": "SIG-OPENSSL-06", "result": "PASS", "check": "altered CMS rejected"})
    report["status"] = "PASS"
finally:
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
print("PASS: six OpenSSL signature checks; synthetic CA, no external approval")
