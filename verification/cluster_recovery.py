"""Consistent register export and quarantined restore using PostgreSQL COPY."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time

import psycopg
from psycopg import sql
from native import unique_object
from postgres import connection_options
from serve import private_file
from transit import TransitVault


SCHEMA = Path(__file__).parents[1] / 'deployment/cluster/schema.sql'
TABLES = ('credentials', 'persons', 'profiles', 'requests', 'federation_requests',
          'events', 'challenges', 'pairwise_subjects', 'activation_proposals',
          'operator_events', 'maintenance_runs', 'biometric_attempts', 'security_codes', 'enrollment_quarantine',
          'enrollment_policies', 'enrollment_consents', 'credential_consents', 'consent_retention_runs')
MAX_BYTES = 10 * 1024 ** 3
DEADLINE = 1800


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_dir(path):
    path = Path(path).absolute()
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
        raise ValueError('private owned directory required')
    return path


def open_data(directory_fd, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    stream = os.fdopen(fd, 'rb')
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
            or info.st_uid != os.getuid() or info.st_nlink != 1):
        stream.close()
        raise ValueError('private regular backup file required')
    return stream


def options(dsn, local_test):
    value = connection_options(dsn, local_test)
    value['options'] = ('-c search_path=pg_catalog,openid,pg_temp -c statement_timeout=1800000 '
                        '-c lock_timeout=5000 -c idle_in_transaction_session_timeout=30000')
    return value


def check_deadline(deadline):
    if time.monotonic() > deadline:
        raise TimeoutError('recovery time limit')


def backup(dsn, destination, *, local_test=False, max_bytes=MAX_BYTES):
    destination = Path(destination).absolute()
    private_dir(destination.parent)
    destination.mkdir(mode=0o700)
    deadline = time.monotonic() + DEADLINE
    schema_hash = hashlib.sha256(SCHEMA.read_bytes()).hexdigest()
    manifest = {'format': 1, 'schema': schema_hash, 'postgresMajor': 18, 'tables': {}}
    total = 0
    try:
        with psycopg.connect(**options(dsn, local_test)) as db:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            if db.info.server_version // 10000 != 18 or db.execute('SELECT version FROM openid.schema_version').fetchall() != [(4,)]:
                raise ValueError('unsupported register version')
            for table in TABLES:
                digest = hashlib.sha256()
                size = 0
                fd = os.open(destination / (table + '.copy'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream, db.cursor() as cursor:
                    with cursor.copy(sql.SQL('COPY openid.{} TO STDOUT (FORMAT BINARY)').format(sql.Identifier(table))) as copy:
                        for chunk in copy:
                            check_deadline(deadline)
                            size += len(chunk)
                            total += len(chunk)
                            if total > max_bytes:
                                raise ValueError('backup size limit')
                            stream.write(chunk)
                            digest.update(chunk)
                    stream.flush()
                    os.fsync(stream.fileno())
                    manifest['tables'][table] = {'bytes': size, 'rows': cursor.rowcount, 'sha256': digest.hexdigest()}
        fd = os.open(destination / 'manifest.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(manifest, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        sync_directory(destination)
        sync_directory(destination.parent)
        return {'tables': len(TABLES), 'bytes': total}
    except BaseException:
        shutil.rmtree(destination)
        raise


def read_backup(source, stack, deadline, max_bytes):
    source = private_dir(source)
    directory_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    stack.callback(os.close, directory_fd)
    with open_data(directory_fd, 'manifest.json') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError('manifest size')
    manifest = json.loads(raw, object_pairs_hook=unique_object)
    if (set(manifest) != {'format', 'schema', 'postgresMajor', 'tables'}
            or type(manifest['format']) is not int or manifest['format'] != 1
            or type(manifest['postgresMajor']) is not int or manifest['postgresMajor'] != 18
            or manifest['schema'] != hashlib.sha256(SCHEMA.read_bytes()).hexdigest()
            or set(manifest['tables']) != set(TABLES)):
        raise ValueError('backup version or tables')
    streams = {}
    total = 0
    for table in TABLES:
        info = manifest['tables'][table]
        if (set(info) != {'rows', 'bytes', 'sha256'} or type(info['rows']) is not int or info['rows'] < 0
                or type(info['bytes']) is not int or info['bytes'] < 19
                or not isinstance(info['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', info['sha256'])):
            raise ValueError('backup metadata')
        total += info['bytes']
        if total > max_bytes:
            raise ValueError('backup size limit')
        stream = stack.enter_context(open_data(directory_fd, table + '.copy'))
        if os.fstat(stream.fileno()).st_size != info['bytes']:
            raise ValueError('backup size mismatch')
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            check_deadline(deadline)
            digest.update(chunk)
        if digest.hexdigest() != info['sha256']:
            raise ValueError('backup checksum mismatch')
        stream.seek(0)
        streams[table] = stream
    return manifest, streams


def restore(admin_dsn, source, target, vault, *, local_test=False, max_bytes=MAX_BYTES):
    if not re.fullmatch('openid_restore_[a-z0-9_]{1,40}', target):
        raise ValueError('new database name must start with openid_restore_')
    deadline = time.monotonic() + DEADLINE
    with ExitStack() as stack:
        manifest, streams = read_backup(source, stack, deadline, max_bytes)
        admin = stack.enter_context(psycopg.connect(**options(admin_dsn, local_test), autocommit=True))
        if admin.info.server_version // 10000 != 18:
            raise ValueError('PostgreSQL 18 required')
        # CREATE fails on an existing name. Never alter or clean an existing database.
        admin.execute(sql.SQL('CREATE DATABASE {} TEMPLATE template0 ALLOW_CONNECTIONS false').format(sql.Identifier(target)))
        try:
            admin.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(target)))
            admin.execute(sql.SQL('ALTER DATABASE {} ALLOW_CONNECTIONS true').format(sql.Identifier(target)))
            target_options = options(admin_dsn, local_test) | {'dbname': target}
            with psycopg.connect(**target_options) as db:
                db.execute(SCHEMA.read_text(), prepare=False)
                # Schema installation commits itself; data and revocation share the next transaction.
                db.execute('ALTER TABLE openid.credentials DISABLE TRIGGER credential_guard')
                for table in TABLES:
                    stream = streams[table]
                    digest = hashlib.sha256()
                    size = 0
                    with db.cursor() as cursor:
                        with cursor.copy(sql.SQL('COPY openid.{} FROM STDIN (FORMAT BINARY)').format(sql.Identifier(table))) as copy:
                            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                                check_deadline(deadline)
                                size += len(chunk)
                                if size > manifest['tables'][table]['bytes']:
                                    raise ValueError('backup changed during restore')
                                digest.update(chunk)
                                copy.write(chunk)
                        if cursor.rowcount != manifest['tables'][table]['rows'] or digest.hexdigest() != manifest['tables'][table]['sha256']:
                            raise ValueError('backup changed during restore')
                for table in ('events', 'operator_events', 'consent_retention_runs'):
                    db.execute(sql.SQL("SELECT setval(pg_get_serial_sequence(%s,'id'),coalesce(max(id),1),count(*)>0) FROM openid.{}").format(sql.Identifier(table)), ('openid.' + table,))
                db.execute('SELECT openid.revoke_all_after_restore()')
                db.execute('ALTER TABLE openid.credentials ENABLE TRIGGER credential_guard')
                checked = 0
                with db.cursor(name='recovery_profiles') as cursor:
                    cursor.itersize = 100
                    cursor.execute('SELECT credential,person,sealed FROM openid.profiles')
                    for credential, person, sealed in cursor:
                        check_deadline(deadline)
                        vault.crypt('open', credential, person, json.loads(sealed))
                        checked += 1
                if db.execute("SELECT count(*) FROM openid.credentials WHERE state!='REVOKED'").fetchone()[0]:
                    raise ValueError('restore revocation failed')
        finally:
            # Both success and failure leave the new database closed to all connections.
            # Its ACL also blocks service logins if the administrative connection is interrupted.
            admin.execute(sql.SQL('ALTER DATABASE {} ALLOW_CONNECTIONS false').format(sql.Identifier(target)))
    return {'state': 'QUARANTINED', 'profilesChecked': checked}


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='operation', required=True)
    save = sub.add_parser('backup')
    save.add_argument('--database-file', required=True)
    save.add_argument('--destination', required=True)
    recover = sub.add_parser('restore')
    recover.add_argument('--admin-file', required=True)
    recover.add_argument('--backup', required=True)
    recover.add_argument('--target', required=True)
    recover.add_argument('--key-config', required=True)
    args = parser.parse_args()
    if args.operation == 'backup':
        result = backup(private_file(args.database_file).decode().strip(), args.destination)
    else:
        config = json.loads(private_file(args.key_config))
        if set(config) != {'baoAddress', 'baoTokenFile', 'baoCA'}:
            raise ValueError('key configuration')
        vault = TransitVault(config['baoAddress'], config['baoTokenFile'], config['baoCA'])
        result = restore(private_file(args.admin_file).decode().strip(), args.backup, args.target, vault)
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Recovery operation failed. A created restore database remains quarantined.', file=sys.stderr)
        raise SystemExit(2)
