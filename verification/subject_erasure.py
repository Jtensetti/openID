"""Bounded, decision-driven local erasure. No network or automatic legal decision.

All mutable categories are explicit. Revocation references and shared journals
remain for separately justified handling; external copies are never declared erased.
"""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys
import time

from audit_archive import decode, encoded
from erasure_policy import (MAX_ROWS, TABLES, decision, digest,
    read_ledger, sha256, validate_journal)
from sqlite_retention import database_identity

MAX_BYTES = 8 * 1024 * 1024
DEADLINE = 30
ERASE = {'profiles': ('registry_bindings', 'profiles'), 'securityCodes': ('security_codes',),
         'authentication': ('requests', 'challenges'), 'signatures': (),
         'consents': ('credential_consents', 'enrollment_consents', 'enrollment_policies'),
         'contacts': ('revocation_codes', 'test_beta_revocation_codes', 'notice_outbox', 'notice_contacts'),
         'lifecycle': ('events', 'activation_proposals', 'operator_events', 'profile_evidence', 'registry_evidence')}
ORDER = ('registry_bindings', 'profiles', 'security_codes', 'requests', 'challenges', 'federation_requests',
         'credential_consents', 'enrollment_consents', 'enrollment_policies',
         'revocation_codes', 'test_beta_revocation_codes', 'notice_outbox', 'notice_contacts', 'events',
         'activation_proposals', 'operator_events', 'profile_evidence', 'registry_evidence')
KEYS = {'enrollment_policies': 'digest', 'notice_outbox': 'event',
        'registry_evidence': 'reference',
        **{t: 'credential' for t in ('registry_bindings', 'profiles', 'security_codes', 'credential_consents',
            'notice_contacts', 'revocation_codes', 'test_beta_revocation_codes', 'profile_evidence')},
        **{t: 'id' for t in ('requests', 'challenges', 'federation_requests',
            'enrollment_consents', 'events', 'activation_proposals', 'operator_events')}}


class Context:
    def __init__(self, db, backend, columns, end):
        self.db, self.backend, self.columns, self.end = db, backend, columns, end
        self.rows, self.bytes, self.data = MAX_ROWS, MAX_BYTES, {}

    def execute(self, query, args=()):
        if time.monotonic() >= self.end: raise TimeoutError('erasure deadline')
        return self.db.execute(query.replace('?', '%s') if self.backend == 'postgresql' else query, args)

    def table(self, name):
        if name not in self.columns: raise ValueError('unmapped erasure table')
        return ('openid.' if self.backend == 'postgresql' else 'main.')+name

    def select(self, table, field=None, values=()):
        if table not in self.columns: return []
        if field is not None and not values: return []
        if field is not None and field not in self.columns[table].split(): raise ValueError('selection field')
        where = '' if field is None else ' WHERE '+field+' IN ('+','.join('?' for _ in values)+')'
        args = ([] if field is None else sorted(values))+[self.rows+1]
        if self.backend == 'postgresql':
            # Bound individual allocations before psycopg materializes a row.
            sql = ('SELECT CASE WHEN octet_length(row_to_json(r)::text)<=? THEN row_to_json(r)::text '
                   'ELSE NULL END FROM (SELECT * FROM '+self.table(table)+where+' ORDER BY 1 LIMIT ?) r')
            with self.db.cursor(name='openid_erasure_rows') as cursor:
                cursor.itersize = 1
                cursor.execute(sql.replace('?', '%s'), [MAX_BYTES]+args)
                rows = []
                for (raw,) in cursor:
                    if raw is None: raise ValueError('oversized erasure row')
                    rows.append(self.bound(decode(raw)))
        else:
            rows = [self.bound(dict(r)) for r in self.execute(
                'SELECT * FROM '+self.table(table)+where+' ORDER BY 1 LIMIT ?', args)]
        return sorted(rows, key=encoded)

    def bound(self, row):
        self.rows -= 1; self.bytes -= len(encoded(row))
        if self.rows < 0 or self.bytes < 0 or time.monotonic() >= self.end:
            raise ValueError('erasure scope limit; no partial operation')
        return row

    def get(self, table, field=None, values=()):
        self.data[table] = self.select(table, field, values)
        return self.data[table]


def scope(ctx, config, *, replay=False):
    ids = set(config['case']['credentials'])
    credentials = ctx.get('credentials', 'id', ids)
    consents = ctx.get('enrollment_consents', 'subject', ids)
    blocks = ctx.get('erasure_subjects', 'credential', ids)
    known = {r['id'] for r in credentials} | {r['subject'] for r in consents} | {r['credential'] for r in blocks}
    if not replay and known != ids: raise ValueError('case key has no retained evidence')
    if any(r['state'] != 'REVOKED' for r in credentials):
        raise ValueError('revoke all selected credentials before erasure')
    profiles = ctx.get('profiles', 'credential', ids)
    if ctx.backend == 'postgresql':
        links = ctx.get('credential_persons', 'credential', ids)
        linked = {r['credential']: r['person'] for r in links}
        if any(linked.get(r['credential']) != r['person'] for r in profiles):
            raise ValueError('profile person linkage mismatch')
        people = set(linked.values())
        if len(people) > 1: raise ValueError('case crosses registered persons')
        related = ctx.select('credential_persons', 'person', people)
        if {r['credential'] for r in related} - ids: raise ValueError('case omits related registrations')
        persons = ctx.get('persons', 'id', people)
        if {r['id'] for r in persons} != people: raise ValueError('missing person linkage')
        ctx.get('pairwise_subjects', 'person', people)
        ctx.get('biometric_attempts', 'document_tag', {r['document_tag'] for r in persons})
        unlinked = known - set(linked)
    else:
        mappings = ctx.get('profile_documents', 'credential', ids)
        tags = {r['document_tag'] for r in mappings}
        aliases = ctx.select('document_links', 'document_tag', tags)
        persons = ctx.select('persons', 'document_tag', tags)
        owners = {r['document_tag']: r['person'] for r in aliases}
        people = {owners.get(r['document_tag'], r['id']) for r in persons} | {r['person'] for r in profiles}
        if len(people) > 1: raise ValueError('case crosses registered persons')
        persons = ctx.get('persons', 'id', people)
        if {r['id'] for r in persons} != people: raise ValueError('missing person linkage')
        aliases = ctx.get('document_links', 'person', people)
        tags |= {r['document_tag'] for r in persons+aliases}
        ctx.get('persons', 'document_tag', tags)
        related = ctx.select('profile_documents', 'document_tag', tags)
        related += ctx.select('profiles', 'person', people)
        if {r['credential'] for r in related} - ids: raise ValueError('case omits related registrations')
        for table in ('retired_documents', 'biometric_failures'): ctx.get(table, 'document_tag', tags)
        replacements = ctx.select('registry_replacements', 'previous', ids)+ctx.select('registry_replacements', 'replacement', ids)
        if any({r['previous'], r['replacement']} - ids for r in replacements): raise ValueError('case omits replacement keys')
        ctx.data['registry_replacements'] = list({r['previous']: r for r in replacements}.values())
        unlinked = known - {r['credential'] for r in mappings if r['document_tag'] in tags}
    # A handler can resolve a single orphaned key, but the program cannot prove
    # that several unlinked keys belong to the same person.
    if unlinked and len(known) > 1: raise ValueError('unlinked keys require separate verified cases')
    for table in ('security_codes', 'requests', 'challenges', 'federation_requests', 'events',
                  'activation_proposals', 'operator_events', 'profile_evidence',
                  'credential_consents', 'notice_contacts', 'notice_outbox', 'revocation_codes', 'test_beta_revocation_codes'):
        ctx.get(table, 'credential', ids)
    for table in ('test_beta_policy', 'test_beta_deadline'): ctx.get(table)
    for table in ('registry_bindings', 'registry_evidence'): ctx.get(table, 'credential', ids)
    receipts = {r['id']: r['subject'] for r in consents}
    for row in ctx.select('credential_consents', 'receipt', set(receipts)):
        if row['credential'] != receipts[row['receipt']]: raise ValueError('foreign consent binding')
    if any(receipts.get(r['receipt']) != r['credential'] for r in ctx.data['credential_consents']):
        raise ValueError('missing consent binding')
    policies = {r['policy_digest'] for r in consents}
    ctx.get('enrollment_policies', 'digest', policies)
    other_consents = ctx.select('enrollment_consents', 'policy_digest', policies)
    shared_policies = {r['policy_digest'] for r in other_consents if r['subject'] not in ids}
    for table in ('retention_runs', 'consent_retention_runs', 'erasure_runs'):
        ctx.get(table)
    # The journal is itself validated, including records outside this case.
    for row in ctx.data['erasure_runs']:
        validate_journal(tuple(row[k] for k in ('id', 'time', 'decision', 'plan_sha256', 'counts')))
    journals = {r['id']: decode(r['decision']) for r in ctx.data['erasure_runs']}
    for row in blocks:
        if row['first_decision'] not in journals or row['credential'] not in journals[row['first_decision']]['case']['credentials']:
            raise ValueError('erasure key block has no matching decision')
    return shared_policies, sorted(unlinked)


def plan(ctx, config, *, replay=False):
    shared, unlinked = scope(ctx, config, replay=replay)
    selected = {t: [] for t in ORDER if t in ctx.columns}
    for category, tables in ERASE.items():
        if config['categories'][category]['action'] == 'erase':
            for table in tables:
                if table in selected: selected[table] = list(ctx.data[table])
    if 'enrollment_policies' in selected:
        selected['enrollment_policies'] = [r for r in selected['enrollment_policies'] if r['digest'] not in shared]
    for row in ctx.data['federation_requests']:
        category = 'authentication' if row['sign_message'] is None else 'signatures'
        if config['categories'][category]['action'] == 'erase': selected['federation_requests'].append(row)
    counts = {t: len(rows) for t, rows in selected.items()}
    document = {'format': 1, 'backend': ctx.backend, 'decisionSHA256': sha256(config),
                'selectionSHA256': sha256(ctx.data), 'delete': counts,
                'retained': {t: len(rows)-counts.get(t, 0) for t, rows in ctx.data.items()},
                'unlinkedKeysForHandlerReview': unlinked,
                'status': 'HANDLER_REVIEW_REQUIRED',
                'notCovered': ['Other keys with lost links; unassigned global records',
                    'DynamoDB, SES, queues, mailboxes, relying parties and their copies',
                    'Backups, snapshots, previous exports, devices and process memory',
                    'Physical storage/WAL/filesystem snapshots and key destruction'],
                'protected': ['securityReferences', 'sharedJournals']}
    document['planSHA256'] = sha256(document)
    return document, selected


def apply_in_transaction(ctx, config, *, expected=None, replay=False, approved=None, clock=time.time):
    config = decision(config, now=None if replay else int(clock()))
    prepared, selected = plan(ctx, config, replay=replay)
    if not replay and digest(expected) != prepared['planSHA256']: raise ValueError('erasure plan changed')
    ident = sha256(config)
    if approved is None or not ({r['id'] for r in ctx.data['erasure_runs']} | {ident}) <= set(approved):
        raise ValueError('detached ledger omits recorded decisions')
    now = int(clock())
    overdue = [k for k, r in config['categories'].items()
               if r['action'] == 'retain' and r['reviewBy'] <= now]
    old = [r for r in ctx.data['erasure_runs'] if r['id'] == ident]
    if old:
        if any(prepared['delete'].values()): raise ValueError('erased content reappeared after recorded decision')
        if set(config['case']['credentials']) - {v['credential'] for v in ctx.data['erasure_subjects']}:
            raise ValueError('erasure key block missing')
        return dict(prepared, status='ALREADY_APPLIED', journalId=ident, retentionReviewRequired=overdue)
    for table in ORDER:
        for row in selected.get(table, ()):
            result = ctx.execute('DELETE FROM '+ctx.table(table)+' WHERE '+KEYS[table]+'=?', (row[KEYS[table]],))
            if result.rowcount != 1: raise ValueError('erasure count mismatch')
    row = (ident, now, encoded(config).decode(), prepared['planSHA256'], encoded(prepared['delete']).decode())
    validate_journal(row)
    ctx.execute('INSERT INTO '+ctx.table('erasure_runs')+' VALUES(?,?,?,?,?)', row)
    for key in config['case']['credentials']:
        ctx.execute('INSERT INTO '+ctx.table('erasure_subjects')+' VALUES(?,?) ON CONFLICT(credential) DO NOTHING', (key, ident))
    return dict(prepared, status='LOCAL_DECISION_APPLIED', journalId=ident,
                retentionReviewRequired=overdue)


def authorize(action, table, column, database, source):
    if source is not None: return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_DELETE:
        return sqlite3.SQLITE_OK if database == 'main' and table in TABLES else sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_INSERT:
        return sqlite3.SQLITE_OK if database == 'main' and table in ('erasure_runs', 'erasure_subjects') else sqlite3.SQLITE_DENY
    if action in (sqlite3.SQLITE_READ, sqlite3.SQLITE_SELECT, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_TRANSACTION):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def sqlite_case(path, config, *, apply=False, expected=None, ledger_value=None, replay=False, clock=time.time):
    from subject_access import COLUMNS, schema
    config = decision(config, now=None if replay else int(clock()))
    if type(apply) is not bool or type(replay) is not bool: raise ValueError('erasure mode')
    if apply:
        from erasure_policy import ledger
        approved = ledger(ledger_value, now=int(clock()))
        if sha256(config) not in {sha256(v) for v in approved['decisions']}: raise ValueError('decision missing from detached ledger')
    path = Path(path).absolute(); identity = database_identity(path)
    db = sqlite3.connect(path.as_uri()+('?mode=rw' if apply else '?mode=ro'),
                         uri=True, isolation_level=None, timeout=3)
    db.row_factory = sqlite3.Row; end = time.monotonic()+DEADLINE
    try:
        if database_identity(path) != identity: raise ValueError('database replaced')
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_BYTES)
        db.set_progress_handler(lambda: int(time.monotonic() >= end), 1000)
        db.execute('PRAGMA foreign_keys=ON')
        if db.execute('PRAGMA foreign_keys').fetchone()[0] != 1: raise ValueError('foreign key enforcement')
        if apply:
            db.execute('PRAGMA synchronous=EXTRA'); db.execute('PRAGMA secure_delete=ON')
            if db.execute('PRAGMA synchronous').fetchone()[0] != 3 or db.execute('PRAGMA secure_delete').fetchone()[0] != 1:
                raise ValueError('durability or logical deletion protection')
        else: db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN IMMEDIATE' if apply else 'BEGIN')
        present = schema(db)
        if not {'erasure_runs', 'erasure_subjects'} <= present: raise ValueError('current erasure schema required')
        db.set_authorizer(authorize)
        ctx = Context(db, 'sqlite', {t: COLUMNS[t] for t in present}, end)
        result = apply_in_transaction(ctx, config, expected=expected, replay=replay,
            approved={sha256(v) for v in approved['decisions']}, clock=clock) if apply else plan(ctx, config)[0]
        if database_identity(path) != identity or time.monotonic() >= end: raise ValueError('database identity or deadline')
        db.execute('COMMIT'); return result
    finally:
        db.set_progress_handler(None, 0)
        if db.in_transaction: db.execute('ROLLBACK')
        db.close()


def postgres_case(dsn, config, *, apply=False, expected=None, ledger_value=None, local_test=False):
    import psycopg
    from postgres import connection_options
    from postgres_subject_access import COLUMNS, schema
    from erasure_policy import ledger
    if type(apply) is not bool: raise ValueError('erasure mode')
    end = time.monotonic()+DEADLINE
    with psycopg.connect(**connection_options(dsn, local_test)) as db:
        # In apply mode, take write-conflicting locks BEFORE the data snapshot.
        # READ COMMITTED then observes all writers which completed before the locks.
        db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED' if apply else
                   'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        db.execute("SET LOCAL TIME ZONE 'UTC'")
        if apply:
            owner = db.execute("SELECT pg_has_role(current_user,'openid_owner','USAGE') AND has_schema_privilege(current_user,'openid','CREATE')").fetchone()[0]
            if not owner: raise ValueError('controlled register owner required for erasure')
            db.execute('LOCK TABLE '+','.join('openid.'+t for t in sorted(COLUMNS))+' IN SHARE ROW EXCLUSIVE MODE')
        schema(db, reader=not apply)
        now = int(db.execute('SELECT extract(epoch FROM clock_timestamp())').fetchone()[0])
        config = decision(config, now=now)
        ctx = Context(db, 'postgresql', COLUMNS, end)
        if not apply: return plan(ctx, config)[0]
        approved = ledger(ledger_value, now=now)
        return apply_in_transaction(ctx, config, expected=expected,
            approved={sha256(v) for v in approved['decisions']}, clock=lambda: now)


def replay_in_transaction(db, backend, ledger_value, *, end=None, clock=time.time):
    """Replay every detached decision while an isolated restore still owns its transaction."""
    from erasure_policy import ledger
    approved = ledger(ledger_value, now=int(clock())); hashes = {sha256(v) for v in approved['decisions']}
    end = time.monotonic()+DEADLINE if end is None else end
    if backend == 'sqlite':
        from subject_access import COLUMNS, schema
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_BYTES)
        db.set_progress_handler(lambda: int(time.monotonic() >= end), 1000)
        present = schema(db); columns = {t: COLUMNS[t] for t in present}
        db.set_authorizer(authorize)
    elif backend == 'postgresql':
        from postgres_subject_access import COLUMNS, schema
        schema(db, reader=False); columns = COLUMNS
    else: raise ValueError('erasure backend')
    if not {'erasure_runs', 'erasure_subjects'} <= set(columns): raise ValueError('erasure replay schema required')
    check = Context(db, backend, columns, end)
    recorded = check.select('erasure_runs')
    if {r['id'] for r in recorded} - hashes: raise ValueError('detached ledger omits recorded decisions')
    for row in recorded: validate_journal(tuple(row[k] for k in ('id', 'time', 'decision', 'plan_sha256', 'counts')))
    recorded_cases = {r['id']: decode(r['decision']) for r in recorded}
    for row in check.select('erasure_subjects'):
        if row['first_decision'] not in recorded_cases or row['credential'] not in recorded_cases[row['first_decision']]['case']['credentials']:
            raise ValueError('erasure key block has no matching decision')
    results = []
    for config in approved['decisions']:
        result = apply_in_transaction(Context(db, backend, columns, end), config,
            replay=True, approved=hashes, clock=clock)
        results.append({'journalId': sha256(config), 'status': result['status'],
                        'retentionReviewRequired': result.get('retentionReviewRequired', [])})
    return results


def write_result(path, value):
    from recovery_binding import private_parent
    path = Path(path).absolute(); private_parent(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(encoded(value)); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def main():
    from erasure_policy import MAX_DECISION
    from recovery_binding import private_input
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('plan', 'apply'))
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--sqlite', type=Path)
    source.add_argument('--database-file', type=Path)
    parser.add_argument('--decision', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected-plan-sha256')
    parser.add_argument('--ledger', type=Path)
    parser.add_argument('--ledger-sha256')
    args = parser.parse_args()
    with private_input(args.decision, MAX_DECISION) as stream: config = decision(decode(stream.read(MAX_DECISION+1)))
    apply = args.action == 'apply'
    approved = read_ledger(args.ledger, args.ledger_sha256) if apply else None
    if apply: digest(args.expected_plan_sha256)
    # Preflight the output before any mutation. A commit followed by filesystem
    # failure is still an uncertain response; the transactional journal is authoritative.
    from recovery_binding import private_parent
    private_parent(args.output)
    if args.output.exists() or args.output.is_symlink(): raise FileExistsError('new output required')
    if args.sqlite:
        result = sqlite_case(args.sqlite, config, apply=apply, expected=args.expected_plan_sha256, ledger_value=approved)
    else:
        with private_input(args.database_file, 8192) as stream: dsn = stream.read(8193).decode().strip()
        result = postgres_case(dsn, config, apply=apply, expected=args.expected_plan_sha256, ledger_value=approved)
    write_result(args.output, result)
    print(json.dumps({k: result[k] for k in ('status', 'planSHA256', 'delete')}))


if __name__ == '__main__':
    try: main()
    except Exception:
        print('Rights operation failed; inspect the private journal before retrying. No sensitive details logged.', file=sys.stderr)
        raise SystemExit(2)
