"""Explicit rights decisions and detached recovery instructions, never legal approval.

The caller supplies a current digest from the decision custodian outside the
backup. Hash agreement proves content integrity, not authority or freshness.
"""
import hashlib
import os
from pathlib import Path
import re
import time

from audit_archive import decode, encoded
from recovery_binding import private_input, private_parent


FORMAT = 'openid-erasure-decision-v1'
LEDGER_FORMAT = 'openid-erasure-ledger-v1'
CATEGORIES = ('profiles', 'securityCodes', 'authentication', 'signatures',
              'consents', 'contacts', 'lifecycle', 'securityReferences', 'sharedJournals')
PROTECTED = {'securityReferences', 'sharedJournals'}
MAX_DECISION = 32768
MAX_LEDGER = 4 * 1024 * 1024
MAX_CASES = 128
MAX_ROWS = 10000
TABLES = {'profiles', 'security_codes', 'requests', 'federation_requests', 'challenges',
          'credential_consents', 'enrollment_consents', 'enrollment_policies',
          'notice_contacts', 'notice_outbox', 'revocation_codes', 'profile_evidence',
          'events', 'activation_proposals', 'operator_events'}
TABLES |= {'registry_bindings', 'registry_evidence', 'test_beta_revocation_codes'}


def reference(value):
    if not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9_-]{8,96}', value):
        raise ValueError('non-personal decision reference required')
    return value


def sha256(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def digest(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
        raise ValueError('trusted SHA-256 digest required')
    return value


def epoch(value):
    if type(value) is not int or not 0 <= value <= 253402300799:
        raise ValueError('decision timestamp')
    return value


def decision(value, *, now=None):
    from subject_access import case_record
    if (type(value) is not dict or set(value) != {'format', 'case', 'decisionReference',
            'holdReviewReference', 'decidedAt', 'categories', 'copies'} or value['format'] != FORMAT):
        raise ValueError('explicit erasure decision required')
    case = case_record(value['case'])
    reference(value['decisionReference']); reference(value['holdReviewReference']); epoch(value['decidedAt'])
    if type(value['categories']) is not dict or set(value['categories']) != set(CATEGORIES):
        raise ValueError('every data category requires a decision')
    for category, rule in value['categories'].items():
        if type(rule) is not dict or rule.get('action') not in ('erase', 'retain'):
            raise ValueError('category decision')
        fields = {'action', 'reasonReference'} | ({'reviewBy'} if rule['action'] == 'retain' else set())
        if set(rule) != fields: raise ValueError('category decision fields')
        reference(rule['reasonReference'])
        if rule['action'] == 'retain':
            if epoch(rule['reviewBy']) <= value['decidedAt']: raise ValueError('retention review date')
            if now is not None and rule['reviewBy'] <= epoch(now):
                raise ValueError('retention decision requires review')
        elif category in PROTECTED:
            raise ValueError('revocation references and shared evidence require separate handling')
    if type(value['copies']) is not dict or set(value['copies']) != {'inventoryReference',
            'restoreReference', 'recipientReference'}:
        raise ValueError('copy and recipient handling references required')
    for v in value['copies'].values(): reference(v)
    if now is not None and value['decidedAt'] > epoch(now): raise ValueError('future decision')
    result = dict(value, case=case)
    if len(encoded(result)) > MAX_DECISION: raise ValueError('decision size')
    return decode(encoded(result))


def ledger(value, *, now=None):
    if (type(value) is not dict or set(value) != {'format', 'authorityReference', 'reviewedAt', 'decisions'}
            or value['format'] != LEDGER_FORMAT or type(value['decisions']) is not list
            or len(value['decisions']) > MAX_CASES):
        raise ValueError('bounded current erasure ledger required')
    reference(value['authorityReference']); epoch(value['reviewedAt'])
    if now is not None and value['reviewedAt'] > epoch(now): raise ValueError('future ledger')
    # Old erasure decisions remain instructions after a retained category's
    # review date. Replay must not resurrect erased content when review is due.
    cases = [decision(v) for v in value['decisions']]
    if (len({sha256(v) for v in cases}) != len(cases)
            or len({v['decisionReference'] for v in cases}) != len(cases)
            or any(v['decidedAt'] > value['reviewedAt'] for v in cases)):
        raise ValueError('duplicate or unreviewed decisions')
    result = dict(value, decisions=sorted(cases, key=lambda v: (v['decidedAt'], sha256(v))))
    if len(encoded(result)) > MAX_LEDGER: raise ValueError('ledger size')
    return result


def read_ledger(path, expected, *, now=None):
    import hmac
    with private_input(path, MAX_LEDGER) as stream: raw = stream.read(MAX_LEDGER+1)
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), digest(expected)):
        raise ValueError('erasure ledger does not match external anchor')
    return ledger(decode(raw), now=int(time.time()) if now is None else now)


def write_ledger(path, value):
    """Serialize supplied decisions; never infer an empty ledger from a backup."""
    data = encoded(ledger(value)); path = Path(path).absolute(); private_parent(path)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    return hashlib.sha256(data).hexdigest()


def install_sqlite(db):
    db.execute('''CREATE TABLE IF NOT EXISTS erasure_runs (
        id TEXT PRIMARY KEY, time INTEGER NOT NULL, decision TEXT NOT NULL,
        plan_sha256 TEXT NOT NULL, counts TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS erasure_subjects (
        credential TEXT PRIMARY KEY, first_decision TEXT NOT NULL REFERENCES erasure_runs(id))''')


def validate_journal(row):
    ident, at, raw, plan, counts = row
    digest(ident); epoch(at); digest(plan)
    if not isinstance(raw, str) or len(raw.encode()) > MAX_DECISION or not isinstance(counts, str):
        raise ValueError('erasure journal')
    config = decision(decode(raw))
    if raw != encoded(config).decode() or sha256(config) != ident or at < config['decidedAt']:
        raise ValueError('erasure journal decision binding')
    values = decode(counts)
    if (type(values) is not dict or set(values) - TABLES
            or any(type(v) is not int or not 0 <= v <= MAX_ROWS for v in values.values())
            or sum(values.values()) > MAX_ROWS):
        raise ValueError('erasure journal counts')
    return config


def case_entry(row, ids):
    config = validate_journal(tuple(row[k] for k in ('id', 'time', 'decision', 'plan_sha256', 'counts')))
    own = sorted(set(config['case']['credentials']) & set(ids))
    if not own: return None
    # An old case can refer to other keys. Never disclose those through a partial selection.
    return {'id': row['id'], 'time': row['time'], 'decisionReference': config['decisionReference'],
            'credentials': own, 'planSHA256': row['plan_sha256'],
            'categories': config['categories'], 'countsRequireSeparateReview': True}
