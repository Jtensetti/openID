"""Bounded, read-only PostgreSQL rights-case extraction for a human handler.

No grants, migrations, new keys, notifications or application write operations.
Use existing private read credentials and separately authorized Transit access.
"""
import argparse
from datetime import timezone
import json
from pathlib import Path
import sys
import time

import psycopg
from postgres import connection_options
from subject_access import (COLUMNS as SQLITE_COLUMNS, EXCLUDED as SQLITE_EXCLUDED,
    MAX_BYTES, MAX_ROWS, DEADLINE, case_record, decode, private_input, read_case,
    prepare_output, write_output, review_evidence, exception_entry)
from transit import TransitVault

COLUMNS = {name: SQLITE_COLUMNS[name] for name in (
    'credentials', 'persons', 'profiles', 'requests', 'federation_requests',
    'events', 'security_codes', 'enrollment_quarantine', 'enrollment_policies',
    'enrollment_consents', 'credential_consents', 'consent_retention_runs')}
COLUMNS.update({
    'schema_version': 'version',
    'credential_persons': 'credential person',
    'challenges': 'id credential payload expires federation',
    'pairwise_subjects': 'person audience subject',
    'activation_proposals': 'id credential profile_version requester decision hours created expires approved_by approved_at',
    'operator_events': 'id actor kind credential proposal time',
    'maintenance_runs': 'id completed_at removed',
    'biometric_attempts': 'document_tag times',
})
EXCLUDED = {k: v for k, v in SQLITE_EXCLUDED.items() if k in COLUMNS}
EXCLUDED['challenges'] = ['payload']


def schema(db):
    db.execute('LOCK TABLE '+','.join('openid.'+t for t in sorted(COLUMNS))+' IN ACCESS SHARE MODE')
    # pg_catalog also reveals objects/columns hidden by insufficient SELECT grants.
    found = db.execute("""SELECT c.relname,c.relkind,c.relrowsecurity,c.relforcerowsecurity,
        a.attname,a.attgenerated FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
        WHERE n.nspname='openid' AND c.relkind IN ('r','p','v','m','f')
        ORDER BY c.relname,a.attnum LIMIT 256""").fetchall()
    actual = {}
    for table, kind, rls, force_rls, column, generated in found:
        if kind != 'r' or rls or force_rls or generated or table not in COLUMNS:
            raise ValueError('unmapped or filtered register schema')
        actual.setdefault(table, set()).add(column)
    if len(found) == 256 or actual != {t: set(c.split()) for t, c in COLUMNS.items()}:
        raise ValueError('unmapped or incomplete register columns')
    if db.execute('SELECT version FROM openid.schema_version').fetchall() != [(6,)]:
        raise ValueError('case extraction requires schema 6')
    roles = db.execute("""SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,
        has_schema_privilege(current_user,'openid','CREATE')
        FROM pg_catalog.pg_roles WHERE rolname=current_user""").fetchone()
    if roles is None or any(roles): raise ValueError('non-administrative reader required')
    for table in COLUMNS:
        if db.execute("""SELECT has_table_privilege(current_user,%s,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
                      OR has_any_column_privilege(current_user,%s,'INSERT,UPDATE,REFERENCES')""",
                      ('openid.'+table, 'openid.'+table)).fetchone()[0]:
            raise ValueError('read-only register account required')
    if db.execute("""SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='openid' AND p.prosecdef
        AND has_function_privilege(current_user,p.oid,'EXECUTE'))""").fetchone()[0]:
        raise ValueError('reader must not execute register mutation functions')


def select(db, table, field, values, budget, end):
    if field is not None and not values: return []
    if len(values) > MAX_ROWS: raise ValueError('selection size')
    excluded = set(EXCLUDED.get(table, ()))
    if table == 'enrollment_consents': excluded.remove('proof')
    fields = [c for c in COLUMNS[table].split() if c not in excluded]
    if field is not None and field not in COLUMNS[table].split(): raise ValueError('selection field')
    where = '' if field is None else ' WHERE '+field+' = ANY(%s)'
    parameters = [] if field is None else [sorted(values)]
    # Server-side cursor plus JSON-size guard bounds client memory, including a
    # malformed oversized text field. Identifiers are code-owned, values are bound.
    query = ('SELECT CASE WHEN octet_length(row_to_json(r)::text)<=%s '
             'THEN row_to_json(r)::text ELSE NULL END FROM (SELECT '+','.join(fields)+
             ' FROM openid.'+table+where+' ORDER BY 1 LIMIT %s) r')
    rows = []
    with db.cursor(name='openid_rights_case') as cursor:
        cursor.itersize = 1
        cursor.execute(query, [MAX_BYTES]+parameters+[budget[0]+1])
        for (raw,) in cursor:
            if time.monotonic() >= end: raise TimeoutError('case deadline')
            if raw is None: raise ValueError('oversized register row')
            budget[0] -= 1; budget[1] -= len(raw.encode())
            if budget[0] < 0 or budget[1] < 0: raise ValueError('case limit; no partial extraction')
            rows.append(decode(raw))
    return rows


def collect(db, case, vault, end):
    schema(db); ids = set(case['credentials']); budget = [MAX_ROWS, MAX_BYTES]; data = {}
    def get(table, field, values):
        data[table] = select(db, table, field, values, budget, end)
        return data[table]
    credentials = get('credentials', 'id', ids)
    consents = get('enrollment_consents', 'subject', ids)
    if {r['id'] for r in credentials} | {r['subject'] for r in consents} != ids:
        raise ValueError('case key has no retained registration or consent evidence')
    profiles = get('profiles', 'credential', ids)
    links = get('credential_persons', 'credential', ids)
    linked = {r['credential']: r['person'] for r in links}
    if any(linked.get(r['credential']) != r['person'] for r in profiles):
        raise ValueError('profile person linkage mismatch')
    people = set(linked.values())
    if len(people) > 1: raise ValueError('case crosses registered persons')
    related = select(db, 'credential_persons', 'person', people, budget, end)
    if {r['credential'] for r in related} - ids:
        raise ValueError('case omits related registrations; review scope')
    persons = get('persons', 'id', people)
    if {r['id'] for r in persons} != people: raise ValueError('missing person linkage')
    get('pairwise_subjects', 'person', people)
    get('biometric_attempts', 'document_tag', {r['document_tag'] for r in persons})
    for table in ('requests', 'federation_requests', 'events', 'challenges', 'security_codes',
                  'activation_proposals', 'operator_events', 'credential_consents'):
        get(table, 'credential', ids)
    get('enrollment_policies', 'digest', {r['policy_digest'] for r in consents})
    review_evidence(data, vault, end)
    receipts = {r['id'] for r in consents}
    data['consent_retention_runs'] = []
    for row in select(db, 'consent_retention_runs', None, (), budget, end):
        entry = exception_entry(row, receipts)
        if entry: data['consent_retention_runs'].append(entry)
    return data, sorted(ids - set(linked))


def export_case(dsn, destination, case, revision, *, vault, local_test=False, max_bytes=MAX_BYTES):
    case = case_record(case); destination = prepare_output(destination, revision, max_bytes)
    end = time.monotonic()+DEADLINE
    options = connection_options(dsn, local_test)
    options['application_name'] = 'openid-subject-access'
    with psycopg.connect(**options) as db:
        db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        db.execute("SET LOCAL TIME ZONE 'UTC'")
        read_at = db.execute('SELECT transaction_timestamp()').fetchone()[0]
        data, unlinked = collect(db, case, vault, end)
        if time.monotonic() >= end: raise TimeoutError('case deadline')
    return write_output(destination, {'format': 1, 'backend': 'postgresql',
        'case': case, 'sourceRevision': revision, 'databaseSchema': 6,
        'readAt': read_at.astimezone(timezone.utc).isoformat(), 'status': 'HANDLER_REVIEW_REQUIRED',
        'records': data, 'credentialsWithoutRetainedPersonLink': unlinked,
        'securityFieldsForSeparateReview': EXCLUDED,
        'notCovered': ['Other device keys and legacy person links lost before schema-6 migration',
            'DynamoDB, SES, queues and mailboxes', 'Relying parties and their sessions/files',
            'Backups, snapshots, archives and earlier exports', 'Device-local records and current process memory',
            'Shared aggregate maintenance journals, unassigned requests/events and global quarantine'],
        'limits': 'Case references are operator assertions, not authentication proof. Unlinked keys require manual investigation; absence of a profile is not evidence of a complete search. Review operator identifiers, third-party text and disclosure decisions before secure delivery. No deletion or revocation performed.'}, max_bytes)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    args = parser.parse_args()
    config = decode(private_input(args.config))
    if type(config) is not dict or set(config) != {'databaseFile','baoAddress','baoTokenFile','baoCA'}:
        raise ValueError('private reader configuration required')
    for field in ('databaseFile', 'baoTokenFile', 'baoCA'):
        if field == 'baoCA' and config[field] is None: continue
        if not isinstance(config[field], str) or not Path(config[field]).is_absolute():
            raise ValueError('absolute private configuration paths required')
    dsn = private_input(config['databaseFile']).decode().strip()
    private_input(config['baoTokenFile'])
    vault = TransitVault(config['baoAddress'], config['baoTokenFile'], config['baoCA'])
    print(json.dumps(export_case(dsn, args.destination, read_case(args.case), args.revision, vault=vault)))


if __name__ == '__main__':
    try: main()
    except Exception:
        print('Private case extraction failed; no sensitive details logged.', file=sys.stderr)
        raise SystemExit(2)
