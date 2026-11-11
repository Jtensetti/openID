"""Separate PostgreSQL/AWS capability for irreversible revocation and issuance.

The controller cannot create an operator approval or provision an ENABLED key.
Each advance performs at most one remote revocation, outside database locks.
Transport retries reuse the intent and deterministic notification event identity.
"""
import argparse
import json
import logging
from pathlib import Path
import signal
import sys
import threading
import time

from psycopg_pool import ConnectionPool
from postgres import connection_options
from revocation import RevocationAuthority, configured_authority
from wallet import identifier


class PostgresContinuity:
    def __init__(self, dsn, authority, *, local_test=False):
        self.authority = authority
        self.reference = getattr(authority, 'reference', None)
        if not self.reference:
            raise ValueError('pinned authority required')
        logging.getLogger('psycopg.pool').setLevel(logging.CRITICAL)
        self.pool = ConnectionPool('', kwargs={**connection_options(dsn, local_test), 'autocommit': True},
            min_size=1, max_size=4, timeout=3, max_waiting=8, reconnect_timeout=5, open=True)
        try:
            self.pool.wait(timeout=5)
            with self.pool.connection() as db:
                if db.execute('SELECT authority FROM openid.continuity_config WHERE id=1').fetchone() != (self.reference,):
                    raise ValueError('continuity authority mismatch')
        except BaseException:
            self.pool.close()
            raise ValueError('continuity controller unavailable') from None

    def close(self):
        self.pool.close()

    def request(self, operation, credential):
        if operation == 'revoke':
            self.revoke(credential)
            return 'REVOKED'
        if operation != 'status':
            raise ValueError('unsupported authority operation')
        return self.authority.request('status', credential)

    def assert_allowed(self, credential):
        self.authority.assert_allowed(credential)

    def revoke(self, credential, *, intent=None):
        identifier(credential)
        # This survives any following DB rollback, timeout or ambiguous commit.
        self.authority.revoke(credential)
        with self.pool.connection() as db, db.transaction():
            db.execute('SELECT openid.confirm_external_revocation(%s,%s)',
                       (credential, self.reference))
        if intent is not None:
            # An expired/changed intent must not roll back the global receipt.
            with self.pool.connection() as db, db.transaction():
                db.execute('SELECT openid.confirm_intent_revocation(%s,%s,%s)',
                           (intent, credential, self.reference))

    def advance(self, intent):
        identifier(intent)
        with self.pool.connection() as db, db.transaction():
            snapshot = db.execute('SELECT openid.activation_snapshot(%s)', (intent,)).fetchone()[0]
        if snapshot['completed']:
            # Historical completion, not a promise that the key is still active.
            return {'completed': True, 'changed': False}
        for credential in snapshot['previous']:
            if credential not in snapshot['confirmed']:
                self.revoke(credential, intent=intent)
                return {'completed': False, 'changed': False}
        self.authority.assert_allowed(snapshot['credential'])
        with self.pool.connection() as db, db.transaction():
            changed = db.execute('SELECT openid.complete_activation(%s,%s,%s)',
                                (intent, self.reference, snapshot['previous'])).fetchone()[0]
        return {'completed': True, 'changed': changed}

    def complete(self, intent):
        # Operator convenience; the service handles one bounded step per request.
        deadline = time.monotonic()+300
        for _ in range(1001):
            if time.monotonic() >= deadline:
                break
            result = self.advance(intent)
            if result['completed']:
                return result
        raise ValueError('activation incomplete; resume the same intent')


def dispatch(controller, payload):
    if payload == {'operation': 'health'}:
        with controller.pool.connection() as db:
            if db.execute('SELECT authority FROM openid.continuity_config WHERE id=1').fetchone() != (controller.reference,):
                raise ValueError('continuity authority mismatch')
        return {'state': 'READY'}
    if set(payload) == {'operation', 'credential'} and payload['operation'] in {'status', 'revoke'}:
        state = controller.request(payload['operation'], payload['credential'])
        return {'credential': payload['credential'], 'state': state}
    if set(payload) == {'operation', 'intent'} and payload['operation'] == 'advance':
        return controller.advance(payload['intent'])
    raise ValueError('unsupported continuity operation')


class ControllerClient(RevocationAuthority):
    def __init__(self, path, reference):
        from ipc_support import request
        if not isinstance(path, str) or not Path(path).is_absolute():
            raise ValueError('absolute controller socket required')
        self.path = path
        super().__init__(lambda payload: request(path, payload), reference=reference)

    def advance(self, intent):
        from ipc_support import request
        identifier(intent)
        return request(self.path, {'operation': 'advance', 'intent': intent})


def client(path, reference):
    return ControllerClient(path, reference)


def configured_client(path):
    import re
    from serve import private_file
    from native import unique_object
    if not Path(path).is_absolute():
        raise ValueError('absolute controller configuration required')
    config = json.loads(private_file(path), object_pairs_hook=unique_object)
    if (type(config) is not dict or set(config) != {'version', 'socket', 'authority'}
            or type(config['version']) is not int or config['version'] != 1
            or not isinstance(config['authority'], str) or not re.fullmatch(
                r'arn:aws:lambda:eu-north-1:[0-9]{12}:function:[A-Za-z0-9_-]{1,64}', config['authority'])):
        raise ValueError('pinned controller configuration required')
    return client(config['socket'], config['authority'])


def run():
    from ipc_support import LocalService
    from serve import private_file
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    config = json.loads(private_file(args.config))
    if set(config) != {'databaseFile', 'continuityConfig', 'socket', 'socketGroup'}:
        raise ValueError('controller configuration')
    if any(not isinstance(config[k], str) or not Path(config[k]).is_absolute()
           for k in ('databaseFile', 'continuityConfig', 'socket')):
        raise ValueError('absolute controller paths required')
    if type(config['socketGroup']) is not int or config['socketGroup'] < 1:
        raise ValueError('explicit socket group required')
    # One SDK attempt, a short fixed deadline; no AWS credentials in callers.
    from aws_client import runtime_client
    authority, options = configured_authority(config['continuityConfig'],
        client_factory=lambda: runtime_client('lambda', read_timeout=3))
    if options.get('testBeta', False):
        raise ValueError('fresh issuer authority required')
    controller = PostgresContinuity(private_file(config['databaseFile']).decode().strip(), authority)
    service = None
    stop = threading.Event()
    for name in (signal.SIGTERM, signal.SIGINT):
        signal.signal(name, lambda *_: stop.set())
    try:
        service = LocalService(config['socket'], config['socketGroup'], lambda data: dispatch(controller, data))
        thread = threading.Thread(target=service.serve_forever, daemon=True)
        thread.start()
        stop.wait()
    finally:
        if service is not None:
            service.close()
        controller.close()


def main():
    try:
        run()
    except Exception:
        print('Continuity controller unavailable; no private details logged.', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
