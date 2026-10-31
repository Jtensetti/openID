"""One-time, reversible access-control migration for the TestFlight 112 server.

Usage (as root on the existing beta EC2 instance):
    python3 deployment/beta112_isolation.py prepare
    # Stop only the openid-beta Compose project, not the independent pilot.
    python3 deployment/beta112_isolation.py activate
    # Start new pinned-image Compose candidate. If it fails, stop it and:
    python3 deployment/beta112_isolation.py rollback

Does not copy, inspect, truncate or restore the identity database.
"""
import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess

BETA = Path("/srv/openid-storage/beta")
WALLET_UID = 10001
VAULT_UID = 10005
IDP_UID = 10002
SP_UID = 10003


def assert_admin():
    if os.geteuid() != 0:
        raise RuntimeError("requires administrator access")
    if BETA.is_symlink() or not BETA.is_dir():
        raise RuntimeError("expected beta directory unavailable")


def ensure_directory(path, uid, gid, mode):
    if path.is_symlink():
        raise RuntimeError("symlinked service directory")
    if path.exists():
        if not path.is_dir():
            raise RuntimeError("unexpected service path type")
        # Never change an existing unexpected owner's private files.
        if path.stat().st_uid not in (uid, 0):
            raise RuntimeError("unexpected existing directory owner")
    else:
        path.mkdir(mode=0o700, parents=True)
    os.chown(path, uid, gid)
    os.chmod(path, mode)
    if (path.stat().st_uid, path.stat().st_gid, path.stat().st_mode & 0o7777) != (uid, gid, mode):
        raise RuntimeError("directory permissions not established")


def copy_synthetic_keys(destination, uid):
    source = BETA / "federation"
    if not source.is_dir() or source.is_symlink():
        raise RuntimeError("missing source federation keys")
    marker = source / "SYNTHETIC-LAB-ONLY"
    if marker.read_bytes() != b"Disposable test keys\n":
        raise RuntimeError("not a disposable lab key directory")
    files = ("SYNTHETIC-LAB-ONLY", "tls.p12", "idp.p12", "sp.p12", "tls.crt")
    for name in files:
        origin = source / name
        target = destination / name
        if origin.is_symlink() or not origin.is_file():
            raise RuntimeError("unexpected key-store source")
        if target.exists() or target.is_symlink():
            raise RuntimeError("destination is not empty; refusing to replace certificate files")
        # Deliberately retain exactly the currently deployed test certificates.
        with origin.open("rb") as infile, target.open("xb") as outfile:
            shutil.copyfileobj(infile, outfile)
        os.chown(target, uid, uid)
        os.chmod(target, 0o600)
        if target.stat().st_size != origin.stat().st_size:
            raise RuntimeError("incomplete certificate copy")


def assert_beta_stopped():
    result = subprocess.run(["docker", "ps", "--filter", "label=com.docker.compose.project=openid-beta",
                             "--format", "{{.Names}}"], check=True, capture_output=True, text=True)
    if result.stdout.strip():
        raise RuntimeError("stop openid-beta containers before moving the key")


def key_check(path, uid):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("missing or linked pilot key")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != 64:
        raise RuntimeError("unexpected pilot key format")
    if info.st_uid != uid or info.st_mode & 0o177:
        raise RuntimeError("pilot key permissions")


def prepare():
    assert_admin()
    # Docker resolves private host bind sources as root before mounting them
    # inside individual namespaces. Preserve the beta root's original 0700 mode.
    if BETA.stat().st_mode & 0o077:
        raise RuntimeError("unexpected beta directory permissions")
    for path in (BETA / "ipc", BETA / "vault"):
        if path.is_symlink():
            raise RuntimeError("symlink in isolation parent")
        if not path.exists():
            path.mkdir(mode=0o700, parents=False)
        if not path.is_dir():
            raise RuntimeError("invalid isolation parent directory")
        os.chmod(path, 0o700)
    for path,uid,gid in (
        (BETA / "ipc/federation", WALLET_UID, 20001),
        (BETA / "ipc/notice", WALLET_UID, 20003),
        (BETA / "vault/socket", VAULT_UID, 20002),
    ):
        ensure_directory(path, uid, gid, 0o2710)
    ensure_directory(BETA / "vault/private", VAULT_UID, VAULT_UID, 0o700)
    for path,uid in ((BETA / "federation-idp", IDP_UID), (BETA / "federation-sp", SP_UID)):
        ensure_directory(path, uid, uid, 0o700)
        copy_synthetic_keys(path, uid)
        source_origins = BETA / "origins.json"
        target_origins = path / "origins.json"
        if source_origins.is_symlink() or not source_origins.is_file() or target_origins.exists():
            raise RuntimeError("invalid or already prepared origins configuration")
        with source_origins.open("rb") as source, target_origins.open("xb") as target:
            shutil.copyfileobj(source, target)
        os.chown(target_origins, uid, uid)
        os.chmod(target_origins, 0o600)
    key_check(BETA / "data/wallet.identity-key", WALLET_UID)
    print("Prepared isolated sockets and existing test certificates; wallet and beta are unchanged")


def activate():
    assert_admin()
    assert_beta_stopped()
    source = BETA / "data/wallet.identity-key"
    destination = BETA / "vault/private/wallet.identity-key"
    key_check(source, WALLET_UID)
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("refusing to overwrite another vault key")
    if source.stat().st_dev != destination.parent.stat().st_dev:
        raise RuntimeError("requires an atomic same-filesystem rename")
    source.rename(destination)
    os.chown(destination, VAULT_UID, VAULT_UID)
    os.chmod(destination, 0o600)
    key_check(destination, VAULT_UID)
    print("Existing beta key moved atomically to isolated vault; the SQLite wallet was not changed")


def rollback():
    assert_admin()
    assert_beta_stopped()
    source = BETA / "vault/private/wallet.identity-key"
    destination = BETA / "data/wallet.identity-key"
    key_check(source, VAULT_UID)
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("refusing to overwrite an existing wallet key")
    if source.stat().st_dev != destination.parent.stat().st_dev:
        raise RuntimeError("requires an atomic same-filesystem rename")
    source.rename(destination)
    os.chown(destination, WALLET_UID, WALLET_UID)
    os.chmod(destination, 0o600)
    key_check(destination, WALLET_UID)
    print("Original key location restored; use the previous pinned image and Compose")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "activate", "rollback"])
    option = parser.parse_args()
    globals()[option.action]()
