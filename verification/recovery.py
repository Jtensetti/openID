"""Offline SQLite backup and conservative restore: all restored keys are revoked."""
import json
import hashlib
import hmac
from contextlib import closing
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import time
import tempfile
from identity import IdentityVault, sqlite_key_history
from recovery_binding import (FORMAT, digest, private_parent, read_binding,
                              snapshot_copy, write_binding)


def private_directory(path):
    path = Path(path).absolute()
    if path.exists() or path.is_symlink(): raise ValueError('Destination must not exist')
    path.mkdir(mode=0o700)
    return path


def continuity_required(database):
    """Read the local fail-closed marker without following a replacement symlink."""
    marker = database.with_suffix('.continuity-required')
    try:
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or stream.read(4) != b'v1\n':
            raise ValueError('Invalid continuity requirement marker')
    return True


def save_continuity_requirement(database):
    fd = os.open(database.with_suffix('.continuity-required'), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(b'v1\n'); stream.flush(); os.fsync(stream.fileno())


def sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def backup(wallet, destination):
    return backup_database(wallet.path, destination)


def backup_database(source, destination):
    """Take a SQLite snapshot without opening a Wallet or changing its schema."""
    source = Path(source).absolute()
    if source.is_symlink() or not source.is_file(): raise ValueError('Regular database file required')
    required = continuity_required(source)
    destination = private_directory(destination)
    target = destination/'wallet.sqlite'
    try:
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(source.as_uri()+'?mode=ro', uri=True)) as db, closing(sqlite3.connect(target)) as output:
            db.backup(output)
            if output.execute('PRAGMA integrity_check').fetchone()[0] != 'ok': raise ValueError('Integrity check')
        # Also retain a requirement enabled while the snapshot was being taken.
        if continuity_required(source) or required: save_continuity_requirement(target)
        with target.open('rb') as stream: os.fsync(stream.fileno())
        # The encryption key is deliberately not included in the database backup.
        (destination/'README.txt').write_text('Keep the identity key separately. Restore revokes every credential.\n'
            'Create recovery binding evidence with the key custodian before restore. Preserve its SHA-256\n'
            'outside the backup; restore requires --binding and --binding-sha256 even for keyless backups.\n'
            'Preserve wallet.continuity-required with this database. For a deployed service, restore with\n'
            '--require-continuity and supply independently managed continuity configuration before startup.\n')
        os.chmod(destination/'README.txt', 0o600)
        with (destination/'README.txt').open('rb') as stream: os.fsync(stream.fileno())
        sync_directory(destination)
        sync_directory(destination.parent)
        return target
    except BaseException:
        shutil.rmtree(destination)
        raise


def verify_profiles(db, vault):
    """Bound untrusted backup fields before decoding JSON or invoking cryptography."""
    end = time.monotonic()+120
    db.set_progress_handler(lambda: int(time.monotonic() >= end), 1000)
    try:
        invalid = db.execute('''SELECT 1 FROM profiles WHERE
            typeof(credential)!='text' OR length(credential) NOT BETWEEN 1 AND 128
            OR typeof(person)!='text' OR length(person) NOT BETWEEN 1 AND 128
            OR typeof(sealed)!='text' OR length(CAST(sealed AS BLOB)) NOT BETWEEN 1 AND 131072
            LIMIT 1''').fetchone()
        if invalid: raise ValueError('invalid bounded recovery profile')
        for credential, person, sealed in db.execute('SELECT credential,person,sealed FROM profiles'):
            if time.monotonic() >= end: raise ValueError('profile verification deadline')
            vault.crypt('open', credential, person, json.loads(sealed))
        if time.monotonic() >= end: raise ValueError('profile verification deadline')
    finally:
        db.set_progress_handler(None, 0)


def bind_backup(source, identity_key, expected_key_sha256, output):
    """Key custodian binds a closed backup to an independently inventoried key."""
    if (identity_key is None) != (expected_key_sha256 is None): raise ValueError('key and inventory digest required together')
    source, output = Path(source).absolute(), Path(output).absolute()
    private_parent(output)
    if output.exists() or output.is_symlink(): raise ValueError('binding destination exists')
    required = continuity_required(source)
    with tempfile.TemporaryDirectory(prefix='openid-binding-', dir=output.parent) as temporary:
        captured = Path(temporary)/'wallet.sqlite'
        snapshot = snapshot_copy(source, captured)
        with closing(sqlite3.connect(captured.as_uri()+'?mode=ro', uri=True)) as db:
            if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok': raise ValueError('Integrity check')
            if db.execute("SELECT 1 FROM sqlite_master WHERE type IN ('view','trigger') LIMIT 1").fetchone():
                raise ValueError('unexpected executable database schema')
            if sqlite_key_history(db):
                if identity_key is None: raise ValueError('Separate identity key and inventory required')
                expected_key_sha256 = digest(expected_key_sha256)
                vault = IdentityVault(identity_key); key = vault.key()
                if not hmac.compare_digest(hashlib.sha256(key).hexdigest(), expected_key_sha256):
                    raise ValueError('identity key does not match independent inventory')
                verify_profiles(db, vault)
                if not hmac.compare_digest(vault.key(), key): raise ValueError('identity key changed')
            elif identity_key is not None:
                raise ValueError('unexpected key for backup without key history')
        required = continuity_required(source) or required
        return write_binding(output, {'format': FORMAT, 'backupSHA256': snapshot['sha256'],
            'backupBytes': snapshot['bytes'], 'identityKeySHA256': expected_key_sha256,
            'continuityRequired': required})


def restore(source, destination, identity_key=None, *, require_continuity=False,
            binding=None, binding_sha256=None):
    source = Path(source).absolute()
    if source.is_symlink() or not source.is_file(): raise ValueError('Regular backup file required')
    if binding is None or binding_sha256 is None: raise ValueError('binding and external anchor required')
    evidence = read_binding(binding, binding_sha256)
    required = continuity_required(source) or require_continuity
    required = evidence['continuityRequired'] or required
    destination = private_directory(destination)
    target = destination/'wallet.sqlite'
    try:
        snapshot = snapshot_copy(source, target)
        if (snapshot['bytes'] != evidence['backupBytes']
                or not hmac.compare_digest(snapshot['sha256'], evidence['backupSHA256'])):
            raise ValueError('backup does not match anchored recovery binding')
        with closing(sqlite3.connect(target)) as db:
            if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok': raise ValueError('Integrity check')
            if db.execute("SELECT 1 FROM sqlite_master WHERE type IN ('view','trigger') LIMIT 1").fetchone():
                raise ValueError('unexpected executable database schema')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            # This also upgrades older backups which predate the attempt ledger.
            db.execute('CREATE TABLE IF NOT EXISTS enrollment_quarantine (id INTEGER PRIMARY KEY CHECK(id=1), until_epoch INTEGER NOT NULL CHECK(until_epoch>=0))')
            db.execute('INSERT INTO enrollment_quarantine VALUES(1,?) ON CONFLICT(id) DO UPDATE SET until_epoch=max(enrollment_quarantine.until_epoch,excluded.until_epoch)',
                (int(time.time())+86400,))
            db.execute("INSERT INTO events(credential,kind,time,request) SELECT id,'REVOKED',?,NULL FROM credentials WHERE state!='REVOKED'", (int(time.time()),))
            db.execute("UPDATE credentials SET state='REVOKED'")
            db.execute("UPDATE requests SET state='CANCELLED' WHERE state IN ('PENDING','APPROVED')")
            db.execute("UPDATE federation_requests SET state='CANCELLED' WHERE state IN ('PENDING','APPROVED')")
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='registry_bindings'").fetchone():
                # A backup cannot establish that a registry check is still current.
                db.execute('DELETE FROM registry_bindings')
            key_history = sqlite_key_history(db)
            if key_history != (evidence['identityKeySHA256'] is not None):
                raise ValueError('backup key history does not match binding')
            if not key_history and identity_key is not None:
                raise ValueError('unexpected key for backup without key history')
            db.commit()
        if key_history:
            if identity_key is None: raise ValueError('Separate identity key required')
            key = IdentityVault(identity_key).key()
            if not hmac.compare_digest(hashlib.sha256(key).hexdigest(), evidence['identityKeySHA256']):
                raise ValueError('identity key does not match backup binding')
            fd = os.open(target.with_suffix('.identity-key'), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(key); stream.flush(); os.fsync(stream.fileno())
            # Prove the supplied key opens every profile before making the restore usable.
            vault = IdentityVault(target.with_suffix('.identity-key'))
            with closing(sqlite3.connect(target)) as db:
                verify_profiles(db, vault)
        with target.open('rb') as stream: os.fsync(stream.fileno())
        if required: save_continuity_requirement(target)
        sync_directory(destination)
        sync_directory(destination.parent)
        return target
    except BaseException:
        shutil.rmtree(destination)
        raise


def main():
    import argparse
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='operation', required=True)
    b = sub.add_parser('backup'); b.add_argument('--db', required=True, type=Path); b.add_argument('--destination', required=True, type=Path)
    r = sub.add_parser('restore'); r.add_argument('--backup', required=True, type=Path); r.add_argument('--destination', required=True, type=Path)
    r.add_argument('--identity-key', type=Path)
    r.add_argument('--binding', type=Path)
    r.add_argument('--binding-sha256', help='SHA-256 from independently protected recovery evidence')
    r.add_argument('--require-continuity', action='store_true',
        help='Require independent revocation and notification services even for an older backup')
    k = sub.add_parser('bind')
    k.add_argument('--backup', required=True, type=Path)
    k.add_argument('--identity-key', type=Path)
    k.add_argument('--expected-key-sha256', help='SHA-256 from independent original-key inventory; required with key history')
    k.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.operation == 'backup':
        result = backup_database(args.db, args.destination)
    elif args.operation == 'bind':
        result = bind_backup(args.backup, args.identity_key, args.expected_key_sha256, args.output)
    else: result = restore(args.backup, args.destination, args.identity_key,
        require_continuity=args.require_continuity, binding=args.binding, binding_sha256=args.binding_sha256)
    print(result)


if __name__ == '__main__':
    try: main()
    except Exception:
        import sys
        print('Recovery failed; no sensitive details logged.', file=sys.stderr)
        raise SystemExit(2)
