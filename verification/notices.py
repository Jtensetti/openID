"""Transactional notification outbox; addresses and secrets stay outside it.

The operator must establish a separately verified contact version first.
An accepted transport submission is not proof of inbox delivery.
"""
import hashlib
import re


def reference(value):
    if not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9_-]{16,128}', value):
        raise ValueError('non-personal contact evidence reference required')
    return value


def install(db):
    db.execute('''CREATE TABLE IF NOT EXISTS notice_contacts (
        credential TEXT PRIMARY KEY REFERENCES credentials(id),
        contact_version TEXT NOT NULL, evidence TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS notice_outbox (
        event TEXT PRIMARY KEY, credential TEXT NOT NULL REFERENCES credentials(id),
        contact_version TEXT NOT NULL, kind TEXT NOT NULL, created INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING', attempts INTEGER NOT NULL DEFAULT 0,
        accepted_reference TEXT)''')
    db.execute('''CREATE TABLE IF NOT EXISTS revocation_codes (
        credential TEXT PRIMARY KEY REFERENCES credentials(id),
        sealed TEXT NOT NULL, contact_version TEXT NOT NULL, evidence TEXT NOT NULL)''')


def bind_contact(db, credential, contact_version, evidence):
    """Operator-only: INSERT deliberately forbids silently redirecting notices."""
    db.execute('INSERT INTO notice_contacts VALUES(?,?,?)',
               (credential, reference(contact_version), reference(evidence)))


def activation(db, credential, created):
    contact = db.execute('SELECT contact_version FROM notice_contacts WHERE credential=?',
                         (credential,)).fetchone()
    if contact is None: raise ValueError('separately verified contact required')
    # An ID can be activated once. Stable event identity makes retries deduplicable.
    event = hashlib.sha256(('activation:v1:'+credential).encode()).hexdigest()
    db.execute('''INSERT INTO notice_outbox(event,credential,contact_version,kind,created)
                  VALUES(?,?,?,?,?)''', (event, credential, contact[0], 'ACTIVATED_V1', created))


def submit(db, send, limit=10):
    """Called inside the wallet's serialized transaction by a private exporter.

send publishes to the durable independent delivery queue, not directly to SES.
A crash after send but before commit can repeat submission with the SAME ID.
The consumer must deduplicate that ID and handle ambiguous SES delivery.
"""
    if type(limit) is not int or not 1 <= limit <= 10: raise ValueError('batch size')
    rows = db.execute("SELECT * FROM notice_outbox WHERE status='PENDING' AND attempts<5 ORDER BY created,event LIMIT ?",
                      (limit,)).fetchall()
    for row in rows:
        db.execute('UPDATE notice_outbox SET attempts=attempts+1 WHERE event=?', (row['event'],))
        try:
            receipt = reference(send({'event': row['event'], 'contactVersion': row['contact_version'],
                                      'kind': row['kind'], 'created': row['created']}))
        except Exception:
            # Persist only the failure count, never private provider response text.
            continue
        db.execute("UPDATE notice_outbox SET status='QUEUED',accepted_reference=? WHERE event=?",
                   (receipt, row['event']))
