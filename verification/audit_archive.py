"""Private, read-only audit snapshots. An independently retained digest is required.

This exports existing register records, not passport evidence or an issuance attestation.
No key service, biometric model or application writer is needed for offline verification.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import time

TABLES = {
    'credentials': ('id', 'public_key', 'state', 'created', 'expires', 'decision'),
    'profiles': ('credential', 'version', 'verified', 'document_expires'),
    'events': ('id', 'credential', 'kind', 'time', 'request'),
    'activation_proposals': ('id', 'credential', 'profile_version', 'requester', 'decision',
                             'hours', 'created', 'expires', 'approved_by', 'approved_at'),
    'operator_events': ('id', 'actor', 'kind', 'credential', 'proposal', 'time'),
}
MAX_BYTES = 1024 ** 3
MAX_ROWS = 1_000_000
MAX_LINE = 1024 ** 2
DEADLINE = 300


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                       allow_nan=False)+'\n').encode('ascii')


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('duplicate field')
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite number')))


def tables(backend):
    if backend not in ('sqlite', 'postgresql'): raise ValueError('archive backend')
    return tuple(TABLES) if backend == 'postgresql' else tuple(TABLES)[:3]


def limit(value):
    if type(value) is not int or not 1 <= value <= MAX_BYTES: raise ValueError('archive size limit')


def deadline(end):
    if time.monotonic() > end: raise TimeoutError('archive deadline')


def write_file(path, data):
    with path.open('xb') as stream:
        os.chmod(path, 0o600)
        stream.write(data); stream.flush(); os.fsync(stream.fileno())


def write_table(db, backend, name, path, available, end):
    columns = TABLES[name]
    fields = ','.join(columns)
    if backend == 'postgresql':
        if name == 'operator_events':
            fields = fields.rsplit(',', 1)[0]+",to_char(time AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')"
        cursor = db.cursor(name='archive_'+name)
        cursor.itersize = 256
        cursor.execute('SELECT '+fields+' FROM openid.'+name+' ORDER BY 1')
    else:
        cursor = db.execute('SELECT '+fields+' FROM '+name+' ORDER BY 1')
    count = size = 0; digest = hashlib.sha256()
    try:
        with path.open('xb') as stream:
            os.chmod(path, 0o600)
            for row in cursor:
                deadline(end)
                data = encoded(list(row))
                count += 1; size += len(data)
                if count > MAX_ROWS or len(data) > MAX_LINE or size > available:
                    raise ValueError('archive exceeds limit; no partial export')
                stream.write(data); digest.update(data)
            stream.flush(); os.fsync(stream.fileno())
    finally:
        cursor.close()
    return {'columns': list(columns), 'rows': count, 'bytes': size, 'sha256': digest.hexdigest()}


def export_snapshot(source, destination, backend, revision, *, max_bytes=MAX_BYTES):
    limit(max_bytes)
    if not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('full source revision required')
    names = tables(backend); destination = Path(destination).absolute()
    # Claim a new private directory first; a pre-existing destination is never changed.
    destination.mkdir(mode=0o700)
    try:
        end = time.monotonic()+DEADLINE; files = {}; total = 0
        with source as (db, snapshot):
            for name in names:
                deadline(end)
                info = write_table(db, backend, name, destination/(name+'.jsonl'), max_bytes-total, end)
                total += info['bytes']; files[name+'.jsonl'] = info
        # Publish the manifest only after the read transaction completes successfully.
        manifest = encoded({'format': 1, 'backend': backend, 'source_revision': revision,
            'snapshot': snapshot, 'files': files})
        if total+len(manifest) > max_bytes: raise ValueError('archive exceeds limit')
        deadline(end); write_file(destination/'manifest.json', manifest)
        fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
        return {'manifestSha256': hashlib.sha256(manifest).hexdigest(),
                'rows': sum(f['rows'] for f in files.values()), 'bytes': total+len(manifest)}
    except BaseException:
        shutil.rmtree(destination)
        raise


@contextmanager
def sqlite_snapshot(path):
    path = Path(path).absolute()
    if path.is_symlink() or not path.is_file(): raise ValueError('existing database required')
    db = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, timeout=3, isolation_level=None)
    try:
        end = time.monotonic()+DEADLINE
        db.set_progress_handler(lambda: int(time.monotonic() > end), 1000)
        db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
        db.execute('SELECT count(*) FROM credentials').fetchone()  # establish the snapshot
        yield db, {'database_schema': None, 'read_at': datetime.now(timezone.utc).isoformat()}
        db.execute('COMMIT')
    finally:
        db.close()


@contextmanager
def postgres_snapshot(dsn, *, local_test=False):
    import psycopg
    from postgres import connection_options
    with psycopg.connect(**connection_options(dsn, local_test)) as db:
        db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        version, read_at = db.execute('SELECT version, transaction_timestamp() FROM openid.schema_version').fetchone()
        if version != 2: raise ValueError('archive requires schema 2')
        yield db, {'database_schema': version, 'read_at': read_at.isoformat()}


def private_open(name, directory):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError('private regular archive file required')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd); raise


def verify(source, expected_digest, *, max_bytes=MAX_BYTES):
    limit(max_bytes)
    if not isinstance(expected_digest, str) or not re.fullmatch('[a-f0-9]{64}', expected_digest):
        raise ValueError('independently retained manifest digest required')
    directory = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if os.fstat(directory).st_mode & 0o077: raise ValueError('private archive directory required')
        with private_open('manifest.json', directory) as stream: raw = stream.read(65537)
        if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != expected_digest:
            raise ValueError('manifest does not match trusted digest')
        manifest = decode(raw)
        if (type(manifest) is not dict or set(manifest) != {'format','backend','source_revision','snapshot','files'}
                or type(manifest['format']) is not int or manifest['format'] != 1
                or not isinstance(manifest['source_revision'], str)
                or not re.fullmatch('[a-f0-9]{40}', manifest['source_revision'])):
            raise ValueError('archive manifest format')
        names = tables(manifest['backend'])
        snapshot = manifest['snapshot']
        if (type(snapshot) is not dict or set(snapshot) != {'database_schema','read_at'}
                or (snapshot['database_schema'] is not None if manifest['backend'] == 'sqlite'
                    else type(snapshot['database_schema']) is not int or snapshot['database_schema'] != 2)
                or not isinstance(snapshot['read_at'], str)
                or datetime.fromisoformat(snapshot['read_at']).utcoffset() != timezone.utc.utcoffset(None)):
            raise ValueError('archive snapshot description')
        if (type(manifest['files']) is not dict or set(manifest['files']) != {n+'.jsonl' for n in names}
                or set(os.listdir(directory)) != set(manifest['files']) | {'manifest.json'}):
            raise ValueError('archive file inventory')
        total = len(raw); rows = 0; end = time.monotonic()+DEADLINE
        for name in names:
            info = manifest['files'][name+'.jsonl']
            if (type(info) is not dict or set(info) != {'columns','rows','bytes','sha256'}
                    or info['columns'] != list(TABLES[name]) or type(info['rows']) is not int
                    or not 0 <= info['rows'] <= MAX_ROWS or type(info['bytes']) is not int
                    or not 0 <= info['bytes'] <= max_bytes
                    or not isinstance(info['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', info['sha256'])):
                raise ValueError('archive table description')
            digest = hashlib.sha256(); count = size = 0
            with private_open(name+'.jsonl', directory) as stream:
                while True:
                    deadline(end); line = stream.readline(MAX_LINE+1)
                    if not line: break
                    count += 1; size += len(line)
                    if len(line) > MAX_LINE or total+size > max_bytes or count > info['rows']:
                        raise ValueError('archive limit')
                    row = decode(line)
                    if (type(row) is not list or len(row) != len(TABLES[name])
                            or any(v is not None and type(v) not in (int, str) for v in row)):
                        raise ValueError('archive row format')
                    digest.update(line)
            if size != info['bytes'] or count != info['rows'] or digest.hexdigest() != info['sha256']:
                raise ValueError('archive content mismatch')
            total += size; rows += count
        if total > max_bytes: raise ValueError('archive limit')
        return {'state': 'VERIFIED', 'rows': rows, 'bytes': total, 'manifestSha256': expected_digest}
    finally:
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    export = commands.add_parser('export')
    source = export.add_mutually_exclusive_group(required=True)
    source.add_argument('--sqlite', type=Path); source.add_argument('--postgres-file', type=Path)
    export.add_argument('--destination', required=True, type=Path)
    export.add_argument('--revision', required=True)
    check = commands.add_parser('verify'); check.add_argument('--source', required=True, type=Path)
    check.add_argument('--manifest-sha256', required=True)
    for command in (export, check): command.add_argument('--max-bytes', type=int, default=MAX_BYTES)
    args = parser.parse_args()
    if args.operation == 'verify':
        result = verify(args.source, args.manifest_sha256, max_bytes=args.max_bytes)
    else:
        backend = 'sqlite' if args.sqlite else 'postgresql'
        if args.sqlite: snapshot = sqlite_snapshot(args.sqlite)
        else:
            directory = os.open(args.postgres_file.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                with private_open(args.postgres_file.name, directory) as stream: raw = stream.read(65537)
            finally:
                os.close(directory)
            if len(raw) > 65536: raise ValueError('connection file size')
            snapshot = postgres_snapshot(raw.decode('utf-8').strip())
        result = export_snapshot(snapshot, args.destination, backend, args.revision, max_bytes=args.max_bytes)
    print(json.dumps(result))


if __name__ == '__main__':
    try: main()
    except Exception:
        print('Archive operation failed. Check private inputs, limits and trusted digest.', file=sys.stderr)
        raise SystemExit(2)
