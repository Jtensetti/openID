"""Private pilot device credentials. No federation, civil identity claims or automatic issuance.

Only a verified capture can create PENDING_REVIEW. A separate, local operator
decision is required for ACTIVE. All device mutations are signed one-shot
operations; permanent revocation and RP consumption are serialized in SQLite.
"""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import threading
import time

ROOT = Path(__file__).parent
RP_NAME = 'openID lokal testtjänst'
PURPOSE = 'Logga in i den lokala testtjänsten'

def device_crypto(operation, **data):
    result = subprocess.run(['node', str(ROOT/'device-signature.mjs')],
        input=json.dumps({'operation': operation, **data}).encode(), stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=10, check=False)
    if result.returncode or json.loads(result.stdout).get('valid') is not True:
        raise ValueError('device signature rejected')

def identifier(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
        raise ValueError('identifier')
    return value

class Wallet:
    def __init__(self, path, origin, clock=time.time, crypto=device_crypto):
        self.path, self.origin, self.clock, self.crypto = Path(path), origin, clock, crypto
        if self.path.is_symlink() or self.path.parent.is_symlink(): raise ValueError('database symlink')
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.parent.stat().st_mode & 0o077: raise ValueError('database directory must be private (0700)')
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if self.path.stat().st_mode & 0o077: raise ValueError('database must be private (0600)')
        self.lock = threading.RLock()
        self.challenges = {}
        with self.transaction() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS credentials (
                    id TEXT PRIMARY KEY, public_key TEXT UNIQUE NOT NULL,
                    state TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER,
                    decision TEXT, subject TEXT NOT NULL UNIQUE);
                CREATE TABLE IF NOT EXISTS requests (
                    id TEXT PRIMARY KEY, credential TEXT NOT NULL REFERENCES credentials(id),
                    secret_hash TEXT NOT NULL, state TEXT NOT NULL, created INTEGER NOT NULL,
                    expires INTEGER NOT NULL, code TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY, credential TEXT NOT NULL REFERENCES credentials(id),
                    kind TEXT NOT NULL, time INTEGER NOT NULL, request TEXT);
            ''')

    @contextmanager
    def transaction(self):
        with self.lock:
            db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA secure_delete=ON')
            db.execute('BEGIN IMMEDIATE')
            try:
                yield db
                if db.in_transaction: db.execute('COMMIT')
            except BaseException:
                if db.in_transaction: db.execute('ROLLBACK')
                raise
            finally: db.close()

    def event(self, db, credential, kind, request=None):
        db.execute('INSERT INTO events(credential,kind,time,request) VALUES(?,?,?,?)',
            (credential, kind, int(self.clock()), request))

    def credential(self, db, ident):
        row = db.execute('SELECT * FROM credentials WHERE id=?', (identifier(ident),)).fetchone()
        if row is None: raise ValueError('credential unavailable')
        return row

    def state(self, row):
        if row['state'] == 'ACTIVE' and row['expires'] <= self.clock(): return 'EXPIRED'
        return row['state']

    def active(self, db, ident):
        row = self.credential(db, ident)
        if self.state(row) != 'ACTIVE': raise ValueError('credential inactive')
        return row

    def enroll(self, public_key):
        if not isinstance(public_key, str) or len(public_key) > 256: raise ValueError('key size')
        der = base64.b64decode(public_key, validate=True)
        self.crypto('validate', publicKey=public_key)
        ident = hashlib.sha256(der).hexdigest()
        with self.transaction() as db:
            if db.execute('SELECT 1 FROM credentials WHERE id=?', (ident,)).fetchone():
                raise ValueError('key already enrolled')
            db.execute('INSERT INTO credentials VALUES(?,?,?,?,?,?,?)',
                (ident, public_key, 'PENDING_REVIEW', int(self.clock()), None, None, secrets.token_hex(32)))
            self.event(db, ident, 'CAPTURE_VERIFIED')
        return {'id': ident, 'state': 'PENDING_REVIEW'}

    def activate(self, ident, decision, hours=24):
        # Local operator-only call, deliberately absent from the HTTP router.
        if not isinstance(decision, str) or not re.fullmatch('[A-Za-z0-9_-]{8,80}', decision):
            raise ValueError('non-personal decision reference required')
        if type(hours) is not int or not 1 <= hours <= 72: raise ValueError('pilot validity')
        with self.transaction() as db:
            row = self.credential(db, ident)
            if row['state'] != 'PENDING_REVIEW' or self.clock()-row['created'] > 86400:
                raise ValueError('new proofing required')
            db.execute('UPDATE credentials SET state=?,expires=?,decision=? WHERE id=?',
                ('ACTIVE', int(self.clock())+hours*3600, decision, ident))
            self.event(db, ident, 'ACTIVATED')

    def revoke(self, ident):
        with self.transaction() as db: self._revoke(db, ident)

    def _revoke(self, db, ident):
        row = self.credential(db, ident)
        if row['state'] != 'REVOKED':
            db.execute('UPDATE credentials SET state=? WHERE id=?', ('REVOKED', ident))
            db.execute("UPDATE requests SET state='CANCELLED' WHERE credential=? AND state IN ('PENDING','APPROVED')", (ident,))
            self.event(db, ident, 'REVOKED')

    def start_request(self, ident):
        # Fixed local RP: caller cannot supply a name, domain, purpose or callback.
        with self.transaction() as db:
            self.active(db, ident)
            count = db.execute("SELECT count(*) FROM requests WHERE credential=? AND state='PENDING' AND expires>?",
                (ident, self.clock())).fetchone()[0]
            if count >= 5: raise ValueError('too many requests')
            request, secret = secrets.token_hex(32), secrets.token_urlsafe(32)
            expiry = int(self.clock())+120
            code = f'{secrets.randbelow(1000000):06d}'
            db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?)',
                (request, ident, hashlib.sha256(secret.encode()).hexdigest(), 'PENDING', int(self.clock()), expiry, code))
            self.event(db, ident, 'REQUESTED', request)
            return {'id': request, 'secret': secret, 'expiresAt': expiry, 'code': code, 'relyingParty': RP_NAME}

    def consume_result(self, request, secret):
        identifier(request)
        if not isinstance(secret, str) or not 32 <= len(secret) <= 64: raise ValueError('secret')
        with self.transaction() as db:
            row = db.execute('SELECT * FROM requests WHERE id=?', (request,)).fetchone()
            if row is None or not secrets.compare_digest(row['secret_hash'], hashlib.sha256(secret.encode()).hexdigest()):
                raise ValueError('RP binding')
            credential = self.active(db, row['credential']) # Recheck even AFTER approval.
            if row['expires'] <= self.clock(): raise ValueError('expired request')
            if row['state'] == 'PENDING': return {'state': 'PENDING'}
            if row['state'] != 'APPROVED': raise ValueError('no unconsumed approval')
            db.execute("UPDATE requests SET state='CONSUMED' WHERE id=?", (request,))
            self.event(db, row['credential'], 'AUTHENTICATED', request)
            return {'state': 'AUTHENTICATED', 'subject': credential['subject'],
                'audience': 'openid-local-demo', 'assurance': 'PRIVATE_PILOT', 'requestId': request}

    def cancel_request(self, request, secret):
        """Only the RP holding this request's secret can cancel an unconsumed login."""
        identifier(request)
        if not isinstance(secret, str) or not 32 <= len(secret) <= 64: raise ValueError('secret')
        with self.transaction() as db:
            row = db.execute('SELECT * FROM requests WHERE id=?', (request,)).fetchone()
            if row is None or not secrets.compare_digest(row['secret_hash'], hashlib.sha256(secret.encode()).hexdigest()):
                raise ValueError('RP binding')
            changed = db.execute("UPDATE requests SET state='CANCELLED' WHERE id=? AND state IN ('PENDING','APPROVED')", (request,)).rowcount
            if changed: self.event(db, row['credential'], 'CANCELLED', request)

    def check_session(self, ident, subject):
        """Every protected RP read checks current credential state, including after approval."""
        with self.transaction() as db:
            row = self.active(db, ident)
            if not isinstance(subject, str) or not secrets.compare_digest(row['subject'], subject):
                raise ValueError('subject binding')
            return row['expires']

    def challenge(self, request):
        if not isinstance(request, dict) or set(request) != {'credentialId', 'action', 'requestId'}: raise ValueError('fields')
        ident, action, req = identifier(request['credentialId']), request['action'], request['requestId']
        if action not in ('snapshot', 'approve', 'reject', 'revoke'): raise ValueError('action')
        if action in ('approve', 'reject'): identifier(req)
        elif req is not None: raise ValueError('unexpected request')
        with self.transaction() as db:
            self.credential(db, ident)
            target = None
            if req is not None:
                self.active(db, ident)
                target = db.execute("SELECT * FROM requests WHERE id=? AND credential=? AND state='PENDING' AND expires>?",
                    (req, ident, self.clock())).fetchone()
                if target is None: raise ValueError('request unavailable')
            self.challenges = {k:v for k,v in self.challenges.items() if v['expires'] > self.clock()}
            if len(self.challenges) >= 128: raise ValueError('too many challenges')
            challenge = secrets.token_hex(32)
            expires = int(self.clock())+60
            payload = {'version': 1, 'origin': self.origin, 'credentialId': ident, 'action': action,
                'requestId': req, 'challengeId': challenge, 'expiresAt': expires,
                'relyingParty': RP_NAME if target is not None else None,
                'purpose': PURPOSE if target is not None else None, 'code': target['code'] if target is not None else None}
            raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
            self.challenges[challenge] = {'payload': raw, 'data': payload, 'expires': expires}
            return {'id': challenge, 'signingInput': base64.b64encode(raw).decode()}

    def execute(self, request):
        if not isinstance(request, dict) or set(request) != {'challengeId', 'signature'}: raise ValueError('fields')
        challenge = identifier(request['challengeId'])
        with self.lock:
            pending = self.challenges.pop(challenge, None) # Consume before every failure.
            if pending is None or pending['expires'] <= self.clock(): raise ValueError('challenge unavailable')
            signature = request['signature']
            if not isinstance(signature, str) or len(signature) > 160: raise ValueError('signature size')
            base64.b64decode(signature, validate=True)
            payload = pending['data']; ident = payload['credentialId']; action = payload['action']
            with self.transaction() as db:
                row = self.credential(db, ident)
                self.crypto('verify', publicKey=row['public_key'], payload=base64.b64encode(pending['payload']).decode(), signature=signature)
                if action in ('approve', 'reject'):
                    self.active(db, ident)
                    changed = db.execute("UPDATE requests SET state=? WHERE id=? AND credential=? AND state='PENDING' AND expires>?",
                        ('APPROVED' if action == 'approve' else 'REJECTED', payload['requestId'], ident, self.clock())).rowcount
                    if changed != 1: raise ValueError('request unavailable')
                    self.event(db, ident, 'APPROVED' if action == 'approve' else 'REJECTED', payload['requestId'])
                elif action == 'revoke': self._revoke(db, ident)
                return self.snapshot(db, ident)

    def snapshot(self, db, ident):
        row = self.credential(db, ident); state = self.state(row)
        requests = []
        if state == 'ACTIVE':
            requests = [{'id': r['id'], 'relyingParty': RP_NAME, 'purpose': PURPOSE, 'code': r['code'], 'expiresAt': r['expires']}
                for r in db.execute("SELECT * FROM requests WHERE credential=? AND state='PENDING' AND expires>? ORDER BY created DESC LIMIT 5", (ident, self.clock()))]
        events = [{'id': str(e['id']), 'kind': e['kind'], 'time': e['time']}
            for e in db.execute('SELECT * FROM events WHERE credential=? ORDER BY id DESC LIMIT 50', (ident,))]
        return {'credentialId': ident, 'state': state, 'createdAt': row['created'], 'expiresAt': row['expires'],
            'requests': requests, 'events': events, 'environment': 'PRIVATE_PILOT', 'legalIdentityIssued': False}
