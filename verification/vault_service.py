"""Isolated service holding the existing SQLite pilot profile key.

It never returns the raw key. This is local separation, not an HSM: a
compromised authorized wallet process could still request decryptions.
"""
import os
from pathlib import Path
import signal
import threading
import sys

from identity import IdentityVault
from ipc_support import LocalService, request


def dispatch(vault, value):
    operation = value.get("operation")
    if operation == "check" and set(value) == {"operation"}:
        vault.key()
        return {"ready": True}
    if operation == "reference" and set(value) == {"operation", "domain", "value"}:
        domain, data = value["domain"], value["value"]
        if not isinstance(domain, str) or not 1 <= len(domain) <= 240:
            raise ValueError("reference domain")
        if not isinstance(data, str) or len(data) > 4096:
            raise ValueError("reference value")
        return vault.reference(domain, data)
    if operation == "crypt" and set(value) == {"operation", "mode", "credential", "person", "value"}:
        mode = value["mode"]
        credential, person = value["credential"], value["person"]
        if mode not in ("seal", "open") or not isinstance(credential, str) or not 1 <= len(credential) <= 128:
            raise ValueError("crypt operation")
        if not isinstance(person, str) or not 1 <= len(person) <= 128:
            raise ValueError("crypt subject")
        if not isinstance(value["value"], dict):
            raise ValueError("crypt payload")
        return vault.crypt(mode, credential, person, value["value"])
    raise ValueError("unsupported vault operation")


def main():
    endpoint = os.environ["OPENID_VAULT_SOCKET"]
    if len(sys.argv) == 2 and sys.argv[1] == "--probe":
        if request(endpoint, {"operation": "check"}) != {"ready": True}:
            raise SystemExit(1)
        return
    if len(sys.argv) != 1:
        raise SystemExit("usage: vault_service.py [--probe]")
    vault = IdentityVault(os.environ["OPENID_VAULT_KEY"], remote_socket="")
    vault.key()
    service = LocalService(endpoint, os.getgid(), lambda data: dispatch(vault, data))
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        stop.wait()
    finally:
        service.close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
