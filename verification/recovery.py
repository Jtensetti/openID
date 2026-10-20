"""Offline SQLite backup and conservative restore: all restored keys are revoked."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import time


def private_directory(path):
    path = Path(path).absolute()
    if path.exists() or path.is_symlink(): raise ValueError('Destination must not exist')
    path.mkdir(mode=0o700)
    return path


def backup(wallet, destination):
    destination = private_directory(destination)
    target = destination/'wallet.sqlite'
    try:
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with sqlite3.connect(wallet.path.as_uri()+'?mode=ro', uri=True) as source, sqlite3.connect(target) as output:
            source.backup(output)
            if output.execute('PRAGMA integrity_check').fetchone()[0] != 'ok': raise ValueError('Integrity check')
        with target.open('rb') as stream: os.fsync(stream.fileno())
        # The encryption key is deliberately not included in the database backup.
        (destination/'README.txt').write_text('Keep the identity key separately. Restore revokes every credential.\n')
        os.chmod(destination/'README.txt', 0o600)
        return target
    except BaseException:
        shutil.rmtree(destination)
        raise


def restore(source, destination, identity_key=None):
    source = Path(source).absolute()
    if source.is_symlink() or not source.is_file(): raise ValueError('Regular backup file required')
    destination = private_directory(destination)
    target = destination/'wallet.sqlite'
    try:
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with sqlite3.connect(source.as_uri()+'?mode=ro', uri=True) as old, sqlite3.connect(target) as db:
            old.backup(db)
            if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok': raise ValueError('Integrity check')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            db.execute("INSERT INTO events(credential,kind,time,request) SELECT id,'REVOKED',?,NULL FROM credentials WHERE state!='REVOKED'", (int(time.time()),))
            db.execute("UPDATE credentials SET state='REVOKED'")
            db.execute("UPDATE requests SET state='CANCELLED' WHERE state IN ('PENDING','APPROVED')")
            db.execute("UPDATE federation_requests SET state='CANCELLED' WHERE state IN ('PENDING','APPROVED')")
            has_profiles = bool(db.execute('SELECT 1 FROM profiles LIMIT 1').fetchone())
            db.commit()
        if has_profiles:
            if identity_key is None: raise ValueError('Separate identity key required')
            from identity import IdentityVault
            key = IdentityVault(identity_key).key()
            fd = os.open(target.with_suffix('.identity-key'), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(key); stream.flush(); os.fsync(stream.fileno())
            # Prove the supplied key opens every profile before making the restore usable.
            vault = IdentityVault(target.with_suffix('.identity-key'))
            with sqlite3.connect(target) as db:
                for credential, person, sealed in db.execute('SELECT credential,person,sealed FROM profiles'):
                    vault.crypt('open', credential, person, json.loads(sealed))
        with target.open('rb') as stream: os.fsync(stream.fileno())
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
    args = parser.parse_args()
    if args.operation == 'backup':
        from wallet import Wallet
        if not args.db.is_file(): parser.error('Existing database required')
        result = backup(Wallet(args.db, 'local-operator'), args.destination)
    else: result = restore(args.backup, args.destination, args.identity_key)
    print(result)


if __name__ == '__main__': main()
