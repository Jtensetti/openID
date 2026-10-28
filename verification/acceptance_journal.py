"""Minimal private enrollment acceptance evidence shared by both registry backends.

Receipts precede identity proofing, so subject is a device-key digest, not yet a
verified person. Bind only in the same transaction as successful enrollment.
The caller verifies App Attest before writing; evidence is not an independent
attestation of legal validity, human understanding or identity.
"""
import base64
import hashlib
import json
import re

from enrollment_policy import EnrollmentPolicy, canonical, HEX, unique_object


def install_sqlite(db):
    db.execute('''CREATE TABLE IF NOT EXISTS enrollment_policies (
        digest TEXT PRIMARY KEY, record TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS enrollment_consents (
        id TEXT PRIMARY KEY, subject TEXT NOT NULL,
        policy_digest TEXT NOT NULL REFERENCES enrollment_policies(digest),
        accepted INTEGER NOT NULL, proof TEXT NOT NULL, withdrawn INTEGER)''')
    db.execute('CREATE INDEX IF NOT EXISTS consent_subject ON enrollment_consents(subject,accepted)')
    db.execute('''CREATE TABLE IF NOT EXISTS credential_consents (
        credential TEXT PRIMARY KEY REFERENCES credentials(id),
        receipt TEXT UNIQUE NOT NULL REFERENCES enrollment_consents(id))''')


def subject(public_key):
    if not isinstance(public_key, str) or not 1 <= len(public_key) <= 256:
        raise ValueError('device public key size')
    return hashlib.sha256(base64.b64decode(public_key, validate=True)).hexdigest()


def identifier(value):
    if not isinstance(value, str) or not HEX.fullmatch(value): raise ValueError('acceptance identifier')
    return value


def epoch(value):
    if type(value) is not int or not 0 <= value <= 253402300799: raise ValueError('acceptance time')
    return value


def store(db, receipt, public_key, policy, proof, now):
    """Called after a verified, consumed App Attest assertion, before passport processing."""
    identifier(receipt); who = subject(public_key); epoch(now)
    if not isinstance(policy, EnrollmentPolicy): raise ValueError('enrollment policy required')
    EnrollmentPolicy(policy.archived(), clock=lambda: now)
    if (not isinstance(proof, dict) or set(proof) != {'payload', 'assertion', 'appPublicKey'}
            or any(not isinstance(v, str) or not v for v in proof.values())
            or len(canonical(proof)) > 16384):
        raise ValueError('bounded acceptance proof required')
    # The signed payload contains only this session's notice choice and key, never passport data.
    raw = base64.b64decode(proof['payload'], validate=True)
    if len(raw) > 4096: raise ValueError('acceptance payload size')
    value = json.loads(raw, object_pairs_hook=unique_object)
    if (not isinstance(value, dict) or set(value) != {'id', 'nonce', 'devicePublicKey', 'acceptance', 'receipt'}
            or value['receipt'] != receipt
            or value['devicePublicKey'] != public_key
            or any(not isinstance(value[k], str) or not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', value[k]) for k in ('id', 'nonce'))):
        raise ValueError('acceptance payload binding')
    policy.acceptance(value['acceptance'])
    if db.execute('SELECT 1 FROM credentials WHERE id=?', (who,)).fetchone():
        raise ValueError('registered key cannot start new enrollment')
    record = canonical(policy.archived()).decode('ascii')
    db.execute('INSERT INTO enrollment_policies(digest,record) VALUES(?,?) ON CONFLICT(digest) DO NOTHING',
               (policy.digest, record))
    if db.execute('SELECT record FROM enrollment_policies WHERE digest=?', (policy.digest,)).fetchone()[0] != record:
        raise ValueError('enrollment policy archive mismatch')
    db.execute('INSERT INTO enrollment_consents(id,subject,policy_digest,accepted,proof,withdrawn) VALUES(?,?,?,?,?,NULL)',
               (receipt, who, policy.digest, now, canonical(proof).decode('ascii')))


def require_pending(db, receipt, public_key, now):
    identifier(receipt); epoch(now)
    lock(db, receipt)
    row = db.execute('''SELECT c.subject,c.policy_digest,c.accepted,c.withdrawn,p.record
        FROM enrollment_consents c JOIN enrollment_policies p ON p.digest=c.policy_digest WHERE c.id=?''', (receipt,)).fetchone()
    if (row is None or row[0] != subject(public_key) or row[3] is not None
            or not row[2] <= now < row[2]+300
            or db.execute('SELECT 1 FROM credential_consents WHERE receipt=?', (receipt,)).fetchone()):
        raise ValueError('current unused acceptance required')
    policy = EnrollmentPolicy(json.loads(row[4], object_pairs_hook=unique_object), clock=lambda: now)
    if policy.digest != row[1]: raise ValueError('acceptance policy integrity')


def lock(db, receipt):
    # SQLite's BEGIN IMMEDIATE already serializes writers. PostgreSQL must lock
    # this row before both binding and withdrawal, including separate replicas.
    if hasattr(db, 'connection'):
        db.execute('SELECT id FROM enrollment_consents WHERE id=? FOR UPDATE', (receipt,)).fetchone()


def bind(db, credential, receipt, public_key, now):
    if identifier(credential) != subject(public_key): raise ValueError('acceptance credential binding')
    require_pending(db, receipt, public_key, now)
    db.execute('INSERT INTO credential_consents(credential,receipt) VALUES(?,?)', (credential, receipt))


def withdraw(db, receipt, now):
    """Caller has authenticated the session or matching device. Idempotent, never reopens consent."""
    identifier(receipt); epoch(now)
    lock(db, receipt)
    row = db.execute('SELECT accepted FROM enrollment_consents WHERE id=?', (receipt,)).fetchone()
    if row is None or row[0] > now: raise ValueError('acceptance unavailable')
    db.execute('UPDATE enrollment_consents SET withdrawn=? WHERE id=? AND withdrawn IS NULL', (now, receipt))
