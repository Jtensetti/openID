#!/usr/bin/env python3
"""Check the resolved Maven graph and every dependency's SHA-256. Python standard library only.

First run ./mvnw dependency:list -DoutputAbsoluteArtifactFilename=true -DoutputFile=target/dependencies.txt
Updating the committed lock is an explicit reviewable change: python3 scripts/dependencies.py --write
"""
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
entries = []
for line in (root / "target/dependencies.txt").read_text().splitlines():
    parts = line.strip().split(" -- module")[0].split(":")
    scope = next((i for i, p in enumerate(parts) if i >= 4 and p in {"compile", "runtime", "test", "provided", "system"}), None)
    if scope is None:
        continue
    coordinate = ":".join(parts[:scope])
    version = parts[scope - 1]
    if any(c in version for c in "[](),") or "SNAPSHOT" in version or version in {"LATEST", "RELEASE"}:
        raise SystemExit("Unpinned dependency: " + coordinate)
    path = Path(":".join(parts[scope + 1:]).strip())
    entries.append({"coordinate": coordinate, "scope": parts[scope], "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
if not entries:
    raise SystemExit("No resolved dependencies found; refusing an empty lock")
actual = {"format": 1, "dependencies": sorted(entries, key=lambda d: d["coordinate"])}
lock = root / "dependencies.lock.json"
if sys.argv[1:] == ["--write"]:
    lock.write_text(json.dumps(actual, indent=2) + "\n")
elif sys.argv[1:]:
    raise SystemExit("Usage: dependencies.py [--write]")
elif json.loads(lock.read_text()) != actual:
    raise SystemExit("Dependency graph or artifact checksum changed; review before updating the lock")
print(f"Verified {len(entries)} pinned dependency artifacts")
