"""Offline SQLite backup and conservative restore: all restored keys are revoked."""
import json
from contextlib import closing
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import time


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


def restore(source, destination, identity_key=None, *, require_continuity=False):
    source = Path(source).absolute()
    if source.is_symlink() or not source.is_file(): raise ValueError('Regular backup file required')
    required = continuity_required(source) or require_continuity
    destination = private_directory(destination)
    target = destination/'wallet.sqlite'
    try:
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(source.as_uri()+'?mode=ro', uri=True)) as old, closing(sqlite3.connect(target)) as db:
            old.backup(db)
            if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok': raise ValueError('Integrity check')
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
            has_profiles = bool(db.execute('SELECT 1 FROM profiles LIMIT 1').fetchone())
            key_history = has_profiles
            for table in ('persons','document_links','retired_documents','biometric_failures','security_codes'):
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                    key_history = key_history or bool(db.execute('SELECT 1 FROM '+table+' LIMIT 1').fetchone())
            db.commit()
        if key_history:
            if identity_key is None: raise ValueError('Separate identity key required')
            from identity import IdentityVault
            key = IdentityVault(identity_key).key()
            fd = os.open(target.with_suffix('.identity-key'), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(key); stream.flush(); os.fsync(stream.fileno())
            # Prove the supplied key opens every profile before making the restore usable.
            vault = IdentityVault(target.with_suffix('.identity-key'))
            with closing(sqlite3.connect(target)) as db:
                for credential, person, sealed in db.execute('SELECT credential,person,sealed FROM profiles'):
                    vault.crypt('open', credential, person, json.loads(sealed))
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
    r.add_argument('--require-continuity', action='store_true',
        help='Require independent revocation and notification services even for an older backup')
    args = parser.parse_args()
    if args.operation == 'backup':
        result = backup_database(args.db, args.destination)
    else: result = restore(args.backup, args.destination, args.identity_key, require_continuity=args.require_continuity)
    print(result)


if __name__ == '__main__': main()
