"""Explicit, bounded SQLite retention. Never removes revocation or audit evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time

from audit_archive import decode


TABLES = {'profiles': 'credential', 'security_codes': 'credential',
          'requests': 'id', 'federation_requests': 'id'}


def policy(value):
    if (not isinstance(value, dict)
            or set(value) != {'version', 'reference', 'profileDays', 'authenticationRequestDays'}
            or type(value['version']) is not int or value['version'] != 1
            or not isinstance(value['reference'], str)
            or not re.fullmatch('[A-Za-z0-9_-]{8,96}', value['reference'])
            or any(type(value[k]) is not int or not 1 <= value[k] <= 3650
                   for k in ('profileDays', 'authenticationRequestDays'))):
        raise ValueError('explicit retention policy required')
    return dict(value)


def read_policy(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022
                or info.st_uid not in (0, os.geteuid())):
            raise ValueError('protected regular policy file required')
        raw = stream.read(4097)
    if len(raw) > 4096: raise ValueError('policy file too large')
    return policy(decode(raw))


def database_identity(path):
    parent = path.parent.lstat()
    info = path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o077
            or parent.st_uid != os.geteuid() or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1 or info.st_mode & 0o177 or info.st_uid != os.geteuid()):
        raise ValueError('existing private database required')
    return (parent.st_dev, parent.st_ino, info.st_dev, info.st_ino)


def authorize(action, table, column, database, source):
    # Triggers/views may not turn a bounded cleanup into other writes.
    if source is not None: return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_DELETE:
        return sqlite3.SQLITE_OK if database == 'main' and table in TABLES else sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_INSERT:
        return sqlite3.SQLITE_OK if database == 'main' and table in ('retention_runs', 'profile_evidence') else sqlite3.SQLITE_DENY
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION,
                  sqlite3.SQLITE_TRANSACTION):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def maintain(path, config, *, apply=False, batch=100, clock=time.time):
    config = policy(config)
    if type(apply) is not bool or type(batch) is not int or not 1 <= batch <= 1000:
        raise ValueError('mode or batch')
    now = int(clock())
    if not 0 <= now <= 253402300799: raise ValueError('clock')
    path = Path(path).absolute()
    identity = database_identity(path)
    db = sqlite3.connect(path.as_uri()+('?mode=rw' if apply else '?mode=ro'),
                         uri=True, isolation_level=None, timeout=3)
    end = time.monotonic()+10
    try:
        if database_identity(path) != identity: raise ValueError('database replaced')
        db.set_progress_handler(lambda: int(time.monotonic() >= end), 1000)
        db.execute('PRAGMA foreign_keys=ON')
        if db.execute('PRAGMA foreign_keys').fetchone()[0] != 1:
            raise ValueError('foreign key protection unavailable')
        if apply:
            db.execute('PRAGMA synchronous=EXTRA')
            if db.execute('PRAGMA synchronous').fetchone()[0] != 3:
                raise ValueError('durability protection unavailable')
            db.execute('PRAGMA secure_delete=ON')
            if db.execute('PRAGMA secure_delete').fetchone()[0] != 1:
                raise ValueError('secure deletion unavailable')
        else:
            db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN IMMEDIATE' if apply else 'BEGIN')
        required = set(TABLES) | {'credentials', 'retention_runs', 'profile_evidence'}
        available = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not required <= available: raise ValueError('current wallet schema required')
        db.set_authorizer(authorize)
        selected, more = {}, {}
        for table, key in TABLES.items():
            if table in ('profiles', 'security_codes'):
                sql = f'''SELECT p.{key} FROM {table} p JOIN credentials c ON c.id=p.credential
                    WHERE c.state IN ('PENDING_REVIEW','ACTIVE','REVOKED')
                    AND typeof(c.created)='integer' AND c.created>=0 AND c.created<=?
                    AND ((c.expires IS NULL AND c.state IN ('PENDING_REVIEW','REVOKED'))
                         OR (typeof(c.expires)='integer' AND c.expires>=c.created))
                    AND coalesce(c.expires,c.created+86400)<? ORDER BY p.{key} LIMIT ?'''
                args = (now, now-config['profileDays']*86400, batch+1)
            else:
                signing = 'AND sign_message IS NULL' if table == 'federation_requests' else ''
                sql = f'''SELECT {key} FROM {table} WHERE typeof(created)='integer'
                    AND created>=0 AND created<=? AND typeof(expires)='integer' AND expires>=created
                    AND expires<? {signing} ORDER BY {key} LIMIT ?'''
                args = (now, now-config['authenticationRequestDays']*86400, batch+1)
            found = [r[0] for r in db.execute(sql, args)]
            selected[table], more[table] = found[:batch], len(found) > batch
        counts = {t: len(ids) for t, ids in selected.items()}
        digest = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        result = {'mode': 'apply' if apply else 'plan', 'time': now,
                  'policyReference': config['reference'], 'policySHA256': digest,
                  'batchPerTable': batch, 'selected': counts, 'moreEligible': more}
        if apply:
            # Preserve exactly the non-content profile fields used by audit export.
            # Conflicting evidence stops the entire batch; it is never overwritten.
            db.executemany('''INSERT INTO profile_evidence
                SELECT credential,version,verified,document_expires,? FROM profiles WHERE credential=?''',
                [(now, ident) for ident in selected['profiles']])
            for table, ids in selected.items():
                removed = db.executemany(f'DELETE FROM {table} WHERE {TABLES[table]}=?',
                                        [(ident,) for ident in ids]).rowcount
                if removed != len(ids): raise ValueError('retention count mismatch')
            entry = db.execute('''INSERT INTO retention_runs
                (time,policy_ref,policy_sha256,profile_days,request_days,counts)
                VALUES(?,?,?,?,?,?)''', (now, config['reference'], digest, config['profileDays'],
                    config['authenticationRequestDays'], json.dumps(counts, sort_keys=True, separators=(',', ':'))))
            result['journalId'] = entry.lastrowid
        if time.monotonic() >= end or database_identity(path) != identity:
            raise ValueError('retention deadline or database identity')
        db.execute('COMMIT')
        return result
    finally:
        try:
            db.set_progress_handler(None, 0)
            if db.in_transaction: db.execute('ROLLBACK')
        finally:
            db.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('plan', 'apply'))
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--batch', type=int, default=100)
    args = parser.parse_args()
    print(json.dumps(maintain(args.db, read_policy(args.policy),
        apply=args.action == 'apply', batch=args.batch), sort_keys=True))


if __name__ == '__main__':
    try: main()
    except Exception:
        print('Retention failed; no sensitive details logged.', file=sys.stderr)
        raise SystemExit(2)
