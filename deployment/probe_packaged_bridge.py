"""Exercise the packaged bridge only in a disposable container with empty test storage."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def request(path, audience):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(3)
        client.connect(str(path))
        client.sendall(json.dumps({"operation": "health", "audience": audience}).encode() + b"\n")
        with client.makefile("rb") as stream:
            return json.loads(stream.readline(4097))


def main():
    data = Path("/srv/openid/data")
    if (os.environ.get("OPENID_SYNTHETIC_BRIDGE_PROBE") != "1" or not data.is_dir()
            or data.is_symlink() or any(data.iterdir()) or data.stat().st_mode & 0o077
            or os.getuid() == 0 or os.environ.get("OPENID_CONTINUITY_CONFIG")):
        raise ValueError("Disposable non-root container with empty private test storage required")
    subprocess.run([sys.executable, "-c", "import federation; "
                    "assert federation.__file__ == '/app/verification/federation.py'"],
                   cwd="/app/verification", check=True, timeout=30)
    origins = data / "origins.json"
    origins.write_text(json.dumps({"sp": "https://sp.example.test"}))
    process = subprocess.Popen([sys.executable, "/app/verification/saml_bridge.py"],
        cwd="/app/verification", env={**os.environ, "OPENID_PILOT_ORIGINS": str(origins)})
    path = data / "federation.sock"
    try:
        deadline = time.monotonic() + 30
        while not path.exists():
            if process.poll() is not None or time.monotonic() >= deadline:
                raise AssertionError("Packaged bridge did not start")
            time.sleep(.1)
        if request(path, "https://sp.example.test/sp") != {"ok": True, "result": {"state": "READY"}}:
            raise AssertionError("Packaged bridge health failed")
        if request(path, "https://wrong.example.test/sp") != {"ok": False}:
            raise AssertionError("Packaged bridge accepted another audience")
        process.terminate()
        if process.wait(timeout=10) != 0 or path.exists():
            raise AssertionError("Packaged bridge did not shut down cleanly")
    finally:
        if process.poll() is None:
            process.kill(); process.wait(timeout=10)
    print("PASS: packaged federation import, bridge startup, audience rejection and socket cleanup")


if __name__ == "__main__":
    main()
