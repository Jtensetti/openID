"""Shared registry. Schema installation and activation use separate database roles."""
from contextlib import contextmanager, nullcontext
import json
import logging
import secrets
import time
import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg_pool import ConnectionPool, PoolTimeout, TooManyRequests
from wallet import Wallet, device_crypto, identifier


class RegistryUnavailable(RuntimeError):
    pass


class Row(dict):
    def __getitem__(self, key):
        return list(self.values())[key] if isinstance(key, int) else super().__getitem__(key)


def row_factory(cursor):
    names = [column.name for column in cursor.description] if cursor.description else []
    return lambda values: Row(zip(names, values))


class Database:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, query, parameters=()):
        # Only application-owned SQL reaches this adapter, never request text.
        return self.connection.execute(query.replace('?', '%s'), parameters)


def connection_options(dsn, local_test=False):
    options = conninfo_to_dict(dsn)
    if options.get('sslmode') != 'verify-full' and not (local_test and options.get('host') in ('127.0.0.1', 'localhost')):
        raise ValueError('PostgreSQL requires sslmode=verify-full')
    if not options.get('host') or not options.get('user') or not options.get('dbname'):
        raise ValueError('Explicit database host, user and name required')
    # Caller-supplied options must not override the schema, deadlines or primary requirement.
    options.update(connect_timeout=3, target_session_attrs='read-write', application_name='openid',
        options='-c search_path=openid,pg_catalog -c statement_timeout=5000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=10000')
    return options


class PostgresWallet(Wallet):
    def __init__(self, dsn, origin, vault, crypto=device_crypto, *, local_test=False, pool_size=8):
        if type(pool_size) is not int or not 1 <= pool_size <= 16: raise ValueError('pool size')
        self.origin, self.vault, self.crypto = origin, vault, crypto
        self.clock = time.time
        self.lock = nullcontext()
        # libpq failures can contain server/user addresses. Our boundary emits only fixed errors.
        logging.getLogger('psycopg.pool').setLevel(logging.CRITICAL)
        self.pool = ConnectionPool('', kwargs={**connection_options(dsn, local_test),
            'autocommit': True, 'row_factory': row_factory}, min_size=1, max_size=pool_size,
            timeout=3, max_waiting=16, max_lifetime=300, max_idle=60, reconnect_timeout=5,
            check=ConnectionPool.check_connection, open=True)
        try:
            self.pool.wait(timeout=5)
            self.health()
        except BaseException:
            self.pool.close()
            raise RegistryUnavailable('registry unavailable') from None

    @contextmanager
    def transaction(self):
        try:
            with self.pool.connection() as connection, connection.transaction():
                yield Database(connection)
        except (psycopg.Error, PoolTimeout, TooManyRequests):
            # No automatic mutation retry: an interrupted commit has an uncertain outcome.
            raise RegistryUnavailable('registry unavailable') from None

    def close(self):
        self.pool.close()

    def health(self):
        with self.transaction() as db:
            if db.execute('SELECT version FROM schema_version').fetchone()[0] != 1:
                raise RegistryUnavailable('schema unavailable')
        self.vault.key()

    def credential(self, db, ident):
        row = db.execute('SELECT * FROM credentials WHERE id=? FOR UPDATE', (identifier(ident),)).fetchone()
        if row is None: raise ValueError('credential unavailable')
        return row

    def activate(self, *args, **kwargs):
        raise ValueError('activation requires two separate operator accounts')

    def store_challenge(self, db, challenge, raw, payload, expires, federation):
        ident = payload['credentialId']
        db.execute('DELETE FROM challenges WHERE credential=? AND expires<=?', (ident, self.clock()))
        if db.execute('SELECT count(*) FROM challenges WHERE credential=?', (ident,)).fetchone()[0] >= 16:
            raise ValueError('too many challenges')
        db.execute('INSERT INTO challenges VALUES(?,?,?,?,?)',
            (challenge, ident, raw.decode(), expires, federation))

    def take_challenge(self, challenge):
        # Committed independently so wrong signatures, process death and rollback cannot restore it.
        with self.transaction() as db:
            row = db.execute('DELETE FROM challenges WHERE id=? RETURNING *', (challenge,)).fetchone()
        if row is None: return None
        return {'payload': row['payload'].encode(), 'data': json.loads(row['payload']),
            'expires': row['expires'], 'federation': row['federation']}

    def federation_start(self, binding, audience):
        # Serialize this small global quota transaction, not all authentication operations.
        with self.pool.connection() as connection, connection.transaction():
            connection.execute('SELECT pg_advisory_xact_lock(73621)')
            # Reuse the same connection through a tiny scoped store; no process-global override.
            proxy = object.__new__(PostgresWallet)
            proxy.__dict__ = self.__dict__.copy()
            @contextmanager
            def current(): yield Database(connection)
            proxy.transaction = current
            return Wallet.federation_start(proxy, binding, audience)

    def federation_subject(self, db, audience, person):
        if not isinstance(audience, str) or not 1 <= len(audience) <= 512: raise ValueError('audience')
        db.execute('INSERT INTO pairwise_subjects VALUES(?,?,?) ON CONFLICT(person,audience) DO NOTHING',
            (person, audience, secrets.token_hex(32)))
        return db.execute('SELECT subject FROM pairwise_subjects WHERE person=? AND audience=?', (person, audience)).fetchone()[0]
