"""Private, read-only SQLite case extraction for a human rights handler.

This is not a complete access response, an identity check, or a deletion tool.
No network, notification, key creation, application writer or schema migration.
"""
import argparse
import base64
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

from audit_archive import decode, encoded, sqlite_format
from enrollment_policy import EnrollmentPolicy
from identity import IdentityVault
from sqlite_retention import database_identity


# Every stored column is mapped, including deliberately excluded security fields.
# Unknown tables/columns fail closed so a schema change cannot silently disappear.
COLUMNS = {
    'credentials': 'id public_key state created expires decision subject',
    'profiles': 'credential person version sealed verified document_expires',
    'profile_evidence': 'credential version verified document_expires purged',
    'persons': 'id document_tag',
    'document_links': 'document_tag person',
    'retired_documents': 'document_tag',
    'profile_documents': 'credential document_tag',
    'biometric_failures': 'document_tag time',
    'requests': 'id credential secret_hash state created expires code',
    'federation_requests': 'id credential secret_hash state created expires code binding audience sign_message level',
    'events': 'id credential kind time request',
    'security_codes': 'credential hash failures locked updated',
    'enrollment_policies': 'digest record',
    'enrollment_consents': 'id subject policy_digest accepted proof withdrawn',
    'credential_consents': 'credential receipt',
    'retention_runs': 'id time policy_ref policy_sha256 profile_days request_days counts',
    'consent_retention_runs': 'id time policy policy_sha256 counts',
    'enrollment_quarantine': 'id until_epoch',
    'notice_contacts': 'credential contact_version evidence',
    'notice_outbox': 'event credential contact_version kind created status attempts accepted_reference',
    'revocation_codes': 'credential sealed contact_version evidence',
    'erasure_runs': 'id time decision plan_sha256 counts',
    'erasure_subjects': 'credential first_decision',
    'registry_bindings': 'credential person_tag sealed',
    'registry_evidence': 'reference credential',
    'registry_replacements': 'previous replacement',
}
OPTIONAL = {'notice_contacts', 'notice_outbox', 'revocation_codes'}
REGISTRY = {'registry_bindings', 'registry_evidence', 'registry_replacements'}
LATER = {'retention_runs', 'profile_evidence', 'enrollment_policies',
         'enrollment_consents', 'credential_consents', 'consent_retention_runs',
         'erasure_runs', 'erasure_subjects'} | REGISTRY
EXCLUDED = {
    'requests': ['secret_hash', 'code'],
    'federation_requests': ['secret_hash', 'code'],
    'security_codes': ['hash'],
    'revocation_codes': ['sealed'],
    'enrollment_consents': ['proof'],
}
MAX_BYTES = 4 * 1024 * 1024
MAX_ROWS = 10000
DEADLINE = 30


def case_record(value):
    if (type(value) is not dict or set(value) != {'version', 'reference', 'identityCheck', 'credentials'}
            or type(value['version']) is not int or value['version'] != 1
            or any(not isinstance(value[k], str) or not re.fullmatch('[A-Za-z0-9_-]{8,96}', value[k])
                   for k in ('reference', 'identityCheck'))
            or type(value['credentials']) is not list or not 1 <= len(value['credentials']) <= 64
            or any(not isinstance(v, str) or not re.fullmatch('[a-f0-9]{64}', v) for v in value['credentials'])
            or len(set(value['credentials'])) != len(value['credentials'])):
        raise ValueError('explicit private case and unique device-key digests required')
    return dict(value, credentials=sorted(value['credentials']))


def private_input(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                or info.st_nlink != 1 or info.st_uid != os.geteuid()):
            raise ValueError('private owned case file required')
        raw = stream.read(8193)
    if len(raw) > 8192: raise ValueError('case size')
    return raw


def read_case(path):
    return case_record(decode(private_input(path)))


def select(db, table, field, values, budget):
    if not values: return []
    if len(values) > MAX_ROWS: raise ValueError('selection size')
    excluded = set(EXCLUDED.get(table, ()))
    # Read proof only to extract the recorded choice; never emit its raw nonce/assertion.
    if table == 'enrollment_consents': excluded.remove('proof')
    fields = [c for c in COLUMNS[table].split() if c not in excluded]
    marks = ','.join('?' for _ in values)
    rows = []
    cursor = db.execute(
        f'SELECT {",".join(fields)} FROM {table} WHERE {field} IN ({marks}) ORDER BY 1 LIMIT ?',
        (*sorted(values), budget[0]+1))
    for row in cursor:
        value = dict(row)
        budget[0] -= 1; budget[1] -= len(encoded(value))
        if budget[0] < 0 or budget[1] < 0: raise ValueError('case limit; no partial extraction')
        rows.append(value)
    return rows


def schema(db):
    found = dict(db.execute("SELECT name,type FROM sqlite_master WHERE type IN ('table','view') AND name NOT GLOB 'sqlite_*'"))
    if (set(found) - set(COLUMNS) or set(COLUMNS) - OPTIONAL - LATER - set(found)
            or any(kind != 'table' for kind in found.values())
            or (set(found) & OPTIONAL and not OPTIONAL <= set(found))
            or (set(found) & REGISTRY and not REGISTRY <= set(found))):
        raise ValueError('unmapped or incomplete wallet schema')
    sqlite_format(db)  # Accept supported historical groups, reject partial migrations.
    for table in found:
        columns = list(db.execute('PRAGMA table_xinfo('+table+')'))
        if (any(r['hidden'] for r in columns)
                or {r['name'] for r in columns} != set(COLUMNS[table].split())):
            raise ValueError('unmapped wallet columns')
    return set(found)


def review_evidence(data, vault, end):
    consents = data['enrollment_consents']
    for row in consents:
        proof = decode(row.pop('proof'))
        payload = decode(base64.b64decode(proof['payload'], validate=True))
        choice = payload['acceptance']
        if (payload['receipt'] != row['id'] or type(choice) is not dict
                or set(choice) != {'policyDigest', 'termsAccepted', 'biometricsAccepted'}
                or choice['policyDigest'] != row['policy_digest']
                or choice['termsAccepted'] is not True or choice['biometricsAccepted'] is not True):
            raise ValueError('recorded consent choice binding')
        row['recordedAcceptance'] = choice
    receipt_subjects = {r['id']: r['subject'] for r in consents}
    if any(receipt_subjects.get(r['receipt']) != r['credential'] for r in data['credential_consents']):
        raise ValueError('credential consent binding mismatch')
    policies = data['enrollment_policies']
    if {r['digest'] for r in policies} != {r['policy_digest'] for r in consents}:
        raise ValueError('missing consent information')
    for row in data['profiles']:
        value = vault.crypt('open', row['credential'], row['person'], decode(row.pop('sealed')))
        if type(value) is not dict: raise ValueError('profile representation')
        row['data'] = value
        if time.monotonic() >= end: raise TimeoutError('case deadline')
    profiles = {r['credential']: r for r in data['profiles']}
    for row in data.get('registry_bindings', ()):
        sealed = row.pop('sealed')
        profile = profiles.get(row['credential'])
        if profile is None:
            row['encryptedContentRequiresSeparateReview'] = True
        else:
            row['data'] = vault.crypt('open', 'registry:'+row['credential'], profile['person'], decode(sealed))
            if type(row['data']) is not dict: raise ValueError('registry binding representation')
        if time.monotonic() >= end: raise TimeoutError('case deadline')
    for row in policies:
        record = decode(row['record'])
        historical = EnrollmentPolicy(record, clock=lambda: record['notice']['notBefore'])
        if historical.digest != row['digest']:
            raise ValueError('consent information integrity')
        row['record'] = record


def exception_entry(row, receipts):
    from consent_retention import validate_journal
    validate_journal(tuple(row[k] for k in ('id', 'time', 'policy', 'policy_sha256', 'counts')))
    record = decode(row['policy']); own = sorted(receipts & set(record['protectedReceipts']))
    if own:
        return {'id': row['id'], 'time': row['time'], 'policySHA256': row['policy_sha256'],
                'reference': record['reference'], 'protectedReceipts': own}


def collect(db, case, vault, end):
    present = schema(db); ids = set(case['credentials']); budget = [MAX_ROWS, MAX_BYTES]
    data = {}
    def get(table, field, values):
        if table not in present:
            data[table] = []
            return []
        rows = select(db, table, field, values, budget)
        data[table] = rows
        if time.monotonic() >= end: raise TimeoutError('case deadline')
        return rows
    credentials = get('credentials', 'id', ids)
    consents = get('enrollment_consents', 'subject', ids)
    erased = get('erasure_subjects', 'credential', ids)
    if {r['id'] for r in credentials} | {r['subject'] for r in consents} | {r['credential'] for r in erased} != ids:
        raise ValueError('case key has no retained registration or consent evidence')
    profiles = get('profiles', 'credential', ids)
    mappings = get('profile_documents', 'credential', ids)
    tags = {r['document_tag'] for r in mappings}
    links = select(db, 'document_links', 'document_tag', tags, budget)
    people = select(db, 'persons', 'document_tag', tags, budget)
    linked = {r['document_tag']: r['person'] for r in links}
    owners = {linked.get(r['document_tag'], r['id']) for r in people} | {r['person'] for r in profiles}
    if len(owners) > 1: raise ValueError('case crosses registered persons')
    people = get('persons', 'id', owners)
    links = get('document_links', 'person', owners)
    tags |= {r['document_tag'] for r in people+links}
    # A replacement passport retains an alias row in persons; include that mapped data too.
    get('persons', 'document_tag', tags)
    # Retained document mappings still reveal related registrations after profile purge.
    related = {r['credential'] for r in select(db, 'profile_documents', 'document_tag', tags, budget)}
    related |= {r['credential'] for r in select(db, 'profiles', 'person', owners, budget)}
    if related - ids: raise ValueError('case omits related registrations; review scope')
    for table in ('profile_evidence', 'requests', 'federation_requests', 'events', 'security_codes', 'credential_consents'):
        get(table, 'credential', ids)
    for table in ('retired_documents', 'biometric_failures'):
        get(table, 'document_tag', tags)
    for table in sorted(OPTIONAL & present): get(table, 'credential', ids)
    for table in ('registry_bindings', 'registry_evidence'): get(table, 'credential', ids)
    replacements = select(db, 'registry_replacements', 'previous', ids, budget) if 'registry_replacements' in present else []
    replacements += select(db, 'registry_replacements', 'replacement', ids, budget) if 'registry_replacements' in present else []
    if any({r['previous'], r['replacement']} - ids for r in replacements): raise ValueError('case omits replacement keys')
    data['registry_replacements'] = list({r['previous']: r for r in replacements}.values())
    receipts = {r['id'] for r in consents}
    get('enrollment_policies', 'digest', {r['policy_digest'] for r in consents})
    review_evidence(data, vault, end)
    # The journal can contain exception IDs for several people. Keep only this case's IDs.
    data['consent_retention_runs'] = []
    journal = db.execute('SELECT id,time,policy,policy_sha256,counts FROM consent_retention_runs ORDER BY id LIMIT ?',
                        (MAX_ROWS+1,)) if 'consent_retention_runs' in present else ()
    for row in journal:
        budget[0] -= 1
        budget[1] -= len(row['policy'].encode())
        if budget[0] < 0 or budget[1] < 0: raise ValueError('case journal limit')
        entry = exception_entry(row, receipts)
        if entry: data['consent_retention_runs'].append(entry)
    data['erasure_runs'] = []
    if 'erasure_runs' in present:
        from erasure_policy import case_entry
        for row in db.execute('SELECT * FROM erasure_runs ORDER BY id LIMIT ?', (MAX_ROWS+1,)):
            budget[0] -= 1; budget[1] -= len(row['decision'].encode())
            if budget[0] < 0 or budget[1] < 0: raise ValueError('case erasure journal limit')
            entry = case_entry(row, ids)
            if entry: data['erasure_runs'].append(entry)
    return data, sorted(set(COLUMNS) - present)


def prepare_output(destination, revision, max_bytes):
    if not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{40}', revision): raise ValueError('source revision')
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BYTES: raise ValueError('output size limit')
    destination = Path(destination).absolute()
    parent = destination.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o077 or parent.st_uid != os.geteuid()):
        raise ValueError('private owned destination parent required')
    if destination.exists() or destination.is_symlink(): raise FileExistsError('new destination required')
    return destination


def export_case(path, destination, case, revision, *, vault=None, max_bytes=MAX_BYTES):
    case = case_record(case)
    destination = prepare_output(destination, revision, max_bytes)
    path = Path(path).absolute(); identity = database_identity(path)
    end = time.monotonic()+DEADLINE
    db = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, isolation_level=None, timeout=3)
    try:
        db.row_factory = sqlite3.Row
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_BYTES)
        db.set_progress_handler(lambda: int(time.monotonic() >= end), 1000)
        db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA trusted_schema=OFF'); db.execute('BEGIN')
        if database_identity(path) != identity: raise ValueError('database replaced')
        data, absent = collect(db, case, vault or IdentityVault(path.with_suffix('.identity-key')), end)
        if database_identity(path) != identity or time.monotonic() >= end: raise ValueError('case boundary changed')
        db.execute('COMMIT')
    finally:
        db.close()
    return write_output(destination, {'format': 1, 'backend': 'sqlite', 'case': case, 'sourceRevision': revision,
        'readAt': datetime.now(timezone.utc).isoformat(), 'status': 'HANDLER_REVIEW_REQUIRED',
        'records': data, 'tablesAbsentFromSource': absent, 'securityFieldsForSeparateReview': EXCLUDED,
        'notCovered': ['Other device keys not linked in this database', 'DynamoDB, SES, queues and mailboxes',
            'Relying parties and their sessions/files', 'Backups, snapshots, archives and earlier exports',
            'Device-local records and current process memory', 'Shared aggregate retention journals and global quarantine'],
        'limits': 'Case references are operator assertions, not authentication proof. This is not a complete rights response. Review third-party text and disclosure decisions before secure delivery. No deletion or revocation performed.'}, max_bytes)


def write_output(destination, document, max_bytes):
    payload = encoded(document)
    if len(payload) > max_bytes: raise ValueError('case size; no partial extraction')
    destination.mkdir(mode=0o700)
    try:
        fd = os.open(destination/'case.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    except BaseException:
        shutil.rmtree(destination); raise
    return {'sha256': hashlib.sha256(payload).hexdigest(), 'bytes': len(payload), 'reviewRequired': True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    args = parser.parse_args()
    print(json.dumps(export_case(args.db, args.destination, read_case(args.case), args.revision)))


if __name__ == '__main__':
    try: main()
    except Exception:
        print('Private case extraction failed; no sensitive details logged.', file=sys.stderr)
        raise SystemExit(2)
