"""CI-only generated Wallet fixture across the old and new SQLite runtimes.

No real identity, network, device or production data is used. The old runtime
is confined to fixture creation; signature verification is covered separately
by test_wallet against the actual new image.
"""
import argparse
import base64
import json
from pathlib import Path
import sqlite3
from wallet import Wallet
from recovery import backup, restore

ORIGIN = 'https://generated.example.invalid'


def require_rejection(operation):
    try:
        operation()
    except ValueError:
        return
    raise AssertionError('a revoked credential was accepted')


def seed(root):
    root = root.resolve()
    if any(root.iterdir()):
        raise ValueError('fixture destination must be empty')
    wallet = Wallet(root/'live'/'wallet.sqlite', ORIGIN, crypto=lambda *args, **kwargs: None)
    ident = wallet.enroll(base64.b64encode(b'generated-migration-test-key').decode())['id']
    wallet.activate(ident, 'GENERATED-MIGRATION-REVIEW')
    request = wallet.start_request(ident)
    snapshot = backup(wallet, root/'backup')
    wallet.revoke(ident)
    # Assert that the fixture really distinguishes live revocation from an older backup.
    with sqlite3.connect(snapshot) as db:
        assert db.execute('SELECT state FROM credentials WHERE id=?', (ident,)).fetchone() == ('ACTIVE',)
        assert db.execute('SELECT state FROM requests WHERE id=?', (request['id'],)).fetchone() == ('PENDING',)
    (root/'fixture.json').write_text(json.dumps({'sqlite': sqlite3.sqlite_version,
                                               'credential': ident, 'request': request['id']}))
    (root/'fixture.json').chmod(0o600)
    print('Created generated Wallet and stale backup with SQLite ' + sqlite3.sqlite_version)


def check(root):
    root = root.resolve()
    state = json.loads((root/'fixture.json').read_text())
    assert state['sqlite'] == '3.40.1', 'fixture was not made by the previous runtime'
    ident = state['credential']
    current = Wallet(root/'live'/'wallet.sqlite', ORIGIN)
    with current.transaction() as db:
        assert current.credential(db, ident)['state'] == 'REVOKED'
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    require_rejection(lambda: current.activate(ident, 'GENERATED-REACTIVATION'))
    require_rejection(lambda: current.start_request(ident))
    target = restore(root/'backup'/'wallet.sqlite', root/'restored')
    recovered = Wallet(target, ORIGIN)
    with recovered.transaction() as db:
        assert recovered.credential(db, ident)['state'] == 'REVOKED'
        assert db.execute('SELECT state FROM requests WHERE id=?', (state['request'],)).fetchone() == ('CANCELLED',)
        assert db.execute('SELECT kind FROM events WHERE credential=? ORDER BY rowid DESC LIMIT 1', (ident,)).fetchone()[0] == 'REVOKED'
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    require_rejection(lambda: recovered.activate(ident, 'GENERATED-REACTIVATION'))
    require_rejection(lambda: recovered.start_request(ident))
    report = {'format': 1, 'generatedDataOnly': True, 'sourceSQLite': state['sqlite'],
              'targetSQLite': sqlite3.sqlite_version, 'passed': True,
              'checks': ['live database readable without losing revocation',
                         'stale backup restored with revoked credential and cancelled request',
                         'revocation event and database integrity preserved',
                         'live and restored credentials cannot be reactivated or start requests'],
              'limits': ['Synthetic unencrypted profile fixture, not a production restore drill.',
                         'Signature and encrypted-profile recovery are covered by separate packaged-image tests.']}
    (root/'sqlite-transition.json').write_text(json.dumps(report, indent=2) + '\n')
    (root/'sqlite-transition.json').chmod(0o600)
    print('PASS: SQLite ' + state['sqlite'] + ' -> ' + sqlite3.sqlite_version + ' Wallet transition')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['seed', 'check'])
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    expected = '3.40.1' if args.mode == 'seed' else '3.46.1'
    if sqlite3.sqlite_version != expected:
        raise SystemExit('unexpected SQLite version for transition test')
    (seed if args.mode == 'seed' else check)(args.directory)
