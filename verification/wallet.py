"""Device credentials, signed operations and revocation in SQLite."""
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
from datetime import date, datetime, timedelta, timezone
from identity import IdentityVault, VerifiedDocument

ROOT = Path(__file__).parent
RP_NAME = 'openID lokal testtjänst'
PURPOSE = 'Logga in i den lokala testtjänsten'
FEDERATION_RP = 'openID kontotjänst'
FEDERATION_PURPOSE = 'Logga in och dela namn, födelsedatum enligt passet och passfoto'
SIGN_PURPOSE = 'Skriv under och dela namn, födelsedatum enligt passet och passfoto'
SIGN_MESSAGE_LIMIT = 400
BIOMETRIC_ATTEMPTS = 5          # analyses, including success and worker errors, per passport ...
BIOMETRIC_WINDOW = 24 * 3600    # ... within this many seconds

SECURITY_CODE_ATTEMPTS = 5      # wrong security codes in a row before the code is locked for good

class SecurityCodeError(ValueError):
    """A security code decision that is safe to show the holder: PIN_REQUIRED, PIN_INCORRECT, PIN_LOCKED, PIN_WEAK."""
    def __init__(self, code, remaining=None):
        if code not in ('PIN_REQUIRED', 'PIN_INCORRECT', 'PIN_LOCKED', 'PIN_WEAK'): raise ValueError('code')
        super().__init__(code)
        self.code, self.remaining = code, remaining

def security_code(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9]{6}', value): raise ValueError('security code format')
    return value

def weak_security_code(code, birth_mrz=None):
    """Codes a thief tries first: one digit, runs, repeated patterns and the passport birth date."""
    digits = [int(c) for c in code]
    steps = {digits[i+1]-digits[i] for i in range(5)}
    if len(set(digits)) <= 2 or steps in ({1}, {-1}): return True
    if code[:3] == code[3:] or code[:2] == code[2:4] == code[4:]: return True
    if birth_mrz and re.fullmatch('[0-9]{6}', birth_mrz):
        yy, mm, dd = birth_mrz[:2], birth_mrz[2:4], birth_mrz[4:]
        if code in (yy+mm+dd, dd+mm+yy, mm+dd+yy): return True
    return False

class BiometricAttemptLimit(ValueError):
    """The persistent analysis budget is exhausted. Safe to tell the holder."""

def sign_message(value):
    """Plain text the holder reads in full before a separate signing approval."""
    if value is None: return None
    if not isinstance(value, str) or value != value.strip() or not 1 <= len(value) <= SIGN_MESSAGE_LIMIT:
        raise ValueError('sign message')
    if any(ord(c) < 32 and c != '\n' or 127 <= ord(c) < 160 or c in '\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\ufeff' for c in value):
        raise ValueError('sign message characters')
    if value.count('\n') > 12: raise ValueError('sign message lines')
    return value

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
    def __init__(self, path, origin, clock=time.time, crypto=device_crypto, vault_runner=None, revocation=None, notifications=False):
        self.path, self.origin, self.clock, self.crypto = Path(path).absolute(), origin, clock, crypto
        self.revocation = revocation
        self.notifications = notifications
        if self.path.is_symlink() or self.path.parent.is_symlink(): raise ValueError('database symlink')
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.parent.stat().st_mode & 0o077: raise ValueError('database directory must be private (0700)')
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if self.path.stat().st_mode & 0o077: raise ValueError('database must be private (0600)')
        marker = self.path.with_suffix('.continuity-required')
        if marker.exists() or marker.is_symlink():
            if marker.is_symlink() or not marker.is_file() or marker.read_bytes() != b'v1\n':
                raise ValueError('invalid continuity migration marker')
            if self.revocation is None or not self.notifications:
                raise ValueError('migrated wallet requires independent revocation and notices')
        elif self.revocation is not None and self.notifications:
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(b'v1\n'); stream.flush(); os.fsync(stream.fileno())
            directory_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
        self.lock = threading.RLock()
        self.challenges = {}
        self.document_links_enabled = True  # SQLite pilot; PostgreSQL has a separate schema/approval path.
        self.vault = IdentityVault(self.path.with_suffix('.identity-key'), runner=vault_runner)
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
                CREATE TABLE IF NOT EXISTS persons (
                    id TEXT PRIMARY KEY, document_tag TEXT UNIQUE NOT NULL);
                CREATE TABLE IF NOT EXISTS profiles (
                    credential TEXT PRIMARY KEY REFERENCES credentials(id),
                    person TEXT NOT NULL REFERENCES persons(id), version TEXT UNIQUE NOT NULL,
                    sealed TEXT NOT NULL, verified INTEGER NOT NULL, document_expires INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS document_links (
                    document_tag TEXT PRIMARY KEY, person TEXT NOT NULL REFERENCES persons(id));
                CREATE TABLE IF NOT EXISTS retired_documents (document_tag TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS profile_documents (
                    credential TEXT PRIMARY KEY REFERENCES credentials(id), document_tag TEXT NOT NULL);
                INSERT OR IGNORE INTO profile_documents
                    SELECT profiles.credential,persons.document_tag FROM profiles
                    JOIN persons ON persons.id=profiles.person;
                CREATE TABLE IF NOT EXISTS federation_requests (
                    id TEXT PRIMARY KEY, credential TEXT REFERENCES credentials(id),
                    secret_hash TEXT NOT NULL, state TEXT NOT NULL, created INTEGER NOT NULL,
                    expires INTEGER NOT NULL, code TEXT NOT NULL, binding TEXT NOT NULL,
                    audience TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS request_pending ON requests(credential,state,expires);
                CREATE INDEX IF NOT EXISTS event_recent ON events(credential,id DESC);
                CREATE INDEX IF NOT EXISTS profile_person ON profiles(person);
                CREATE INDEX IF NOT EXISTS federation_pending ON federation_requests(state,expires);
            ''')
            db.execute('CREATE TABLE IF NOT EXISTS biometric_failures (document_tag TEXT NOT NULL, time INTEGER NOT NULL)')
            # Security code: HMAC with the separate identity key; the database alone does not reveal the 6 digits.
            db.execute('''CREATE TABLE IF NOT EXISTS security_codes (credential TEXT PRIMARY KEY REFERENCES credentials(id),
                hash TEXT NOT NULL, failures INTEGER NOT NULL, locked INTEGER NOT NULL, updated INTEGER NOT NULL)''')
            db.execute('CREATE INDEX IF NOT EXISTS biometric_failure_document ON biometric_failures(document_tag,time)')
            columns = {row['name'] for row in db.execute('PRAGMA table_info(federation_requests)')}
            if 'sign_message' not in columns:
                db.execute('ALTER TABLE federation_requests ADD COLUMN sign_message TEXT')
            if 'level' not in columns:
                db.execute('ALTER TABLE federation_requests ADD COLUMN level TEXT')
            if self.notifications:
                from notices import install
                install(db)

    @contextmanager
    def transaction(self):
        with self.lock:
            db = sqlite3.connect(self.path.as_uri()+'?mode=rw', uri=True, timeout=10, isolation_level=None)
            try:
                db.row_factory = sqlite3.Row
                db.execute('PRAGMA foreign_keys=ON')
                db.execute('PRAGMA synchronous=FULL')
                db.execute('PRAGMA secure_delete=ON')
                db.execute('BEGIN IMMEDIATE')
                yield db
                if db.in_transaction: db.execute('COMMIT')
            except BaseException:
                if db.in_transaction: db.execute('ROLLBACK')
                raise
            finally: db.close()

    def health(self):
        # Readiness must not wait behind a writer or create a missing database.
        if not self.path.is_file() or self.path.is_symlink(): raise ValueError('database unavailable')
        with sqlite3.connect(self.path.as_uri()+'?mode=ro', uri=True, timeout=0.1) as db:
            if (db.execute('SELECT 1 FROM profiles LIMIT 1').fetchone()
                    or db.execute('SELECT 1 FROM biometric_failures LIMIT 1').fetchone()): self.vault.key()
            db.execute('SELECT 1 FROM credentials LIMIT 1').fetchone()

    def event(self, db, credential, kind, request=None):
        db.execute('INSERT INTO events(credential,kind,time,request) VALUES(?,?,?,?)',
            (credential, kind, int(self.clock()), request))

    def credential(self, db, ident):
        row = db.execute('SELECT * FROM credentials WHERE id=?', (identifier(ident),)).fetchone()
        if row is None: raise ValueError('credential unavailable')
        return row

    def state(self, row):
        if row['state'] == 'ACTIVE' and row['expires'] <= self.clock(): return 'EXPIRED'
        if row['state'] == 'ACTIVE' and getattr(self, 'revocation', None) is not None:
            remote = self.revocation.request('status', row['id'])
            if remote == 'REVOKED': return 'REVOKED'
            if remote != 'ENABLED': raise ValueError('credential not registered at revocation authority')
        return row['state']

    def active(self, db, ident):
        row = self.credential(db, ident)
        if self.state(row) != 'ACTIVE': raise ValueError('credential inactive')
        return row

    def enroll(self, public_key, document=None):
        if not isinstance(public_key, str) or len(public_key) > 256: raise ValueError('key size')
        der = base64.b64decode(public_key, validate=True)
        self.crypto('validate', publicKey=public_key)
        ident = hashlib.sha256(der).hexdigest()
        with self.transaction() as db:
            if db.execute('SELECT 1 FROM credentials WHERE id=?', (ident,)).fetchone():
                raise ValueError('key already enrolled')
            db.execute('INSERT INTO credentials VALUES(?,?,?,?,?,?,?)',
                (ident, public_key, 'PENDING_REVIEW', int(self.clock()), None, None, secrets.token_hex(32)))
            if document is not None:
                if not isinstance(document, VerifiedDocument): raise ValueError('verified document required')
                expiry = int(datetime.combine(date.fromisoformat(document.identity['documentExpires']) + timedelta(days=1),
                    datetime.min.time(), timezone.utc).timestamp())
                if expiry <= self.clock(): raise ValueError('expired document')
                history = db.execute('SELECT 1 FROM profiles LIMIT 1').fetchone()
                if getattr(self, 'document_links_enabled', False):
                    history = history or db.execute('SELECT 1 FROM biometric_failures LIMIT 1').fetchone()
                self.vault.key(create=not history)
                tag = self.vault.document_tag(document)
                if getattr(self, 'document_links_enabled', False) and db.execute(
                        'SELECT 1 FROM retired_documents WHERE document_tag=?', (tag,)).fetchone():
                    raise ValueError('replaced document cannot be reused')
                db.execute('INSERT INTO persons VALUES(?,?) ON CONFLICT(document_tag) DO NOTHING',
                    (secrets.token_hex(32), tag))
                person_id = db.execute('SELECT id FROM persons WHERE document_tag=?', (tag,)).fetchone()['id']
                if getattr(self, 'document_links_enabled', False):
                    linked = db.execute('SELECT person FROM document_links WHERE document_tag=?', (tag,)).fetchone()
                    if linked is not None: person_id = linked['person']
                sealed = self.vault.crypt('seal', ident, person_id, document.profile())
                db.execute('INSERT INTO profiles VALUES(?,?,?,?,?,?)',
                    (ident, person_id, secrets.token_hex(32), json.dumps(sealed), int(self.clock()), expiry))
                if getattr(self, 'document_links_enabled', False):
                    db.execute('INSERT INTO profile_documents VALUES(?,?)', (ident, tag))
            self.event(db, ident, 'CAPTURE_VERIFIED')
        return {'id': ident, 'state': 'PENDING_REVIEW'}

    def activate(self, ident, decision, hours=24):
        # Operator-only; not exposed over HTTP.
        with self.transaction() as db:
            self._activate(db, ident, decision, hours)

    def _activate(self, db, ident, decision, hours=24):
        # Also used within the atomic, registry-checked document replacement transaction.
        if type(self) is not Wallet: raise ValueError('activation requires backend approval')
        if not isinstance(decision, str) or not re.fullmatch('[A-Za-z0-9_-]{8,80}', decision):
            raise ValueError('non-personal decision reference required')
        if type(hours) is not int or not 1 <= hours <= 72: raise ValueError('pilot validity')
        row = self.credential(db, ident)
        if row['state'] != 'PENDING_REVIEW' or self.clock()-row['created'] > 86400:
            raise ValueError('new proofing required')
        if self.revocation is not None: self.revocation.assert_allowed(ident)
        expires = int(self.clock())+hours*3600
        profile = db.execute('SELECT * FROM profiles WHERE credential=?', (ident,)).fetchone()
        if profile is not None:
            if db.execute('''SELECT 1 FROM retired_documents r JOIN profile_documents p
                             ON r.document_tag=p.document_tag WHERE p.credential=?''', (ident,)).fetchone():
                raise ValueError('replaced document cannot be reused')
            self.vault.crypt('open', ident, profile['person'], json.loads(profile['sealed']))
            expires = min(expires, profile['document_expires'])
            if expires <= self.clock(): raise ValueError('expired document')
            for old in db.execute('SELECT credential FROM profiles WHERE person=? AND credential!=?', (profile['person'], ident)):
                self._revoke(db, old['credential'])
        db.execute('UPDATE credentials SET state=?,expires=?,decision=? WHERE id=?',
            ('ACTIVE', expires, decision, ident))
        self.event(db, ident, 'ACTIVATED')
        if self.notifications:
            from notices import activation
            activation(db, ident, int(self.clock()))

    def revoke(self, ident):
        with self.transaction() as db: self._revoke(db, ident)

    def _revoke(self, db, ident):
        row = self.credential(db, ident)
        # Persist remotely first: a local rollback may deny service but must never
        # undo a revocation. Repeating this call is safe, including after restore.
        if getattr(self, 'revocation', None) is not None: self.revocation.revoke(ident)
        if row['state'] != 'REVOKED':
            db.execute('UPDATE credentials SET state=? WHERE id=?', ('REVOKED', ident))
            db.execute("UPDATE requests SET state='CANCELLED' WHERE credential=? AND state IN ('PENDING','APPROVED')", (ident,))
            db.execute("UPDATE federation_requests SET state='CANCELLED' WHERE credential=? AND state IN ('PENDING','APPROVED')", (ident,))
            self.event(db, ident, 'REVOKED')

    def biometric_attempt(self, document):
        """Commit one attempt BEFORE inference. Never refund on errors, success or process death.

        BEGIN IMMEDIATE serializes independent Wallet objects/processes as well as threads.
        Keep the original table name so upgrading an existing pilot preserves its spent budget.
        """
        if not isinstance(document, VerifiedDocument): raise ValueError('verified document required')
        with self.transaction() as db:
            self.vault.key(create=not (db.execute('SELECT 1 FROM profiles LIMIT 1').fetchone()
                or db.execute('SELECT 1 FROM biometric_failures LIMIT 1').fetchone()))
            tag = self.vault.document_tag(document)
            db.execute('DELETE FROM biometric_failures WHERE time<=?', (int(self.clock())-BIOMETRIC_WINDOW,))
            used = db.execute('SELECT count(*) FROM biometric_failures WHERE document_tag=?', (tag,)).fetchone()[0]
            if used >= BIOMETRIC_ATTEMPTS:
                raise BiometricAttemptLimit('biometric attempt limit')
            db.execute('INSERT INTO biometric_failures VALUES(?,?)', (tag, int(self.clock())))
        return BIOMETRIC_ATTEMPTS-used-1

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
            if db.execute("UPDATE requests SET state='CONSUMED' WHERE id=? AND state='APPROVED'", (request,)).rowcount != 1:
                raise ValueError('no unconsumed approval')
            self.event(db, row['credential'], 'AUTHENTICATED', request)
            return {'state': 'AUTHENTICATED', 'subject': credential['subject'],
                'audience': 'openid-local-demo', 'assurance': 'PRIVATE_PILOT', 'requestId': request}

    def cancel_request(self, request, secret):
        identifier(request)
        if not isinstance(secret, str) or not 32 <= len(secret) <= 64: raise ValueError('secret')
        with self.transaction() as db:
            row = db.execute('SELECT * FROM requests WHERE id=?', (request,)).fetchone()
            if row is None or not secrets.compare_digest(row['secret_hash'], hashlib.sha256(secret.encode()).hexdigest()):
                raise ValueError('RP binding')
            changed = db.execute("UPDATE requests SET state='CANCELLED' WHERE id=? AND state IN ('PENDING','APPROVED')", (request,)).rowcount
            if changed: self.event(db, row['credential'], 'CANCELLED', request)

    def check_session(self, ident, subject):
        with self.transaction() as db:
            row = self.active(db, ident)
            if not isinstance(subject, str) or not secrets.compare_digest(row['subject'], subject):
                raise ValueError('subject binding')
            return row['expires']

    def challenge(self, request):
        if not isinstance(request, dict) or set(request) != {'credentialId', 'action', 'requestId'}: raise ValueError('fields')
        ident, action, req = identifier(request['credentialId']), request['action'], request['requestId']
        if action not in ('snapshot', 'inspect', 'approve', 'sign', 'reject', 'revoke', 'set-pin'): raise ValueError('action')
        if action == 'set-pin' and not getattr(self, 'security_codes_supported', True): raise ValueError('security codes unavailable')
        if action in ('inspect', 'approve', 'sign', 'reject'): identifier(req)
        elif req is not None: raise ValueError('unexpected request')
        with self.transaction() as db:
            self.credential(db, ident)
            if action == 'set-pin': self.verified_profile(db, ident)
            target = None; federation = False
            if req is not None:
                self.active(db, ident)
                target = db.execute("SELECT * FROM requests WHERE id=? AND credential=? AND state='PENDING' AND expires>?",
                    (req, ident, self.clock())).fetchone()
                if target is None:
                    self.verified_profile(db, ident)
                    target = db.execute("SELECT * FROM federation_requests WHERE id=? AND credential IS NULL AND state='PENDING' AND expires>?",
                        (req, self.clock())).fetchone()
                    federation = True
                if target is None: raise ValueError('request unavailable')
            signing = federation and self.federation_sign_message(target) is not None
            # A signing request needs the separate signing action; login approval cannot sign.
            if (action == 'approve' and signing) or (action == 'sign' and not signing): raise ValueError('action')
            challenge = secrets.token_hex(32)
            expires = int(self.clock())+60
            payload = {'version': 1, 'origin': self.origin, 'credentialId': ident, 'action': action,
                'requestId': req, 'challengeId': challenge, 'expiresAt': expires,
                'relyingParty': (FEDERATION_RP if federation else RP_NAME) if target is not None and action != 'inspect' else None,
                'purpose': ((SIGN_PURPOSE if signing else FEDERATION_PURPOSE) if federation else PURPOSE) if target is not None and action != 'inspect' else None,
                'code': target['code'] if target is not None and action != 'inspect' else None}
            if signing and action != 'inspect': payload['signMessage'] = self.federation_sign_message(target)
            # The holder's signed consent names the verification the service asked for.
            if federation and self.federation_level(target) == 'pin' and action != 'inspect': payload['verification'] = 'pin'
            raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
            self.store_challenge(db, challenge, raw, payload, expires, federation)
            return {'id': challenge, 'signingInput': base64.b64encode(raw).decode()}

    def store_challenge(self, db, challenge, raw, payload, expires, federation):
        self.challenges = {k:v for k,v in self.challenges.items() if v['expires'] > self.clock()}
        if len(self.challenges) >= 128: raise ValueError('too many challenges')
        self.challenges[challenge] = {'payload': raw, 'data': payload, 'expires': expires, 'federation': federation}

    def take_challenge(self, challenge):
        return self.challenges.pop(challenge, None)

    def execute(self, request):
        if (not isinstance(request, dict) or not {'challengeId', 'signature'} <= set(request)
                or set(request) - {'challengeId', 'signature', 'pin', 'newPin'}): raise ValueError('fields')
        challenge = identifier(request['challengeId'])
        failure = None
        with self.lock:
            pending = self.take_challenge(challenge) # Consume before every failure.
            if pending is None or pending['expires'] <= self.clock(): raise ValueError('challenge unavailable')
            if pending['data']['origin'] != self.origin: raise ValueError('origin binding')
            signature = request['signature']
            if not isinstance(signature, str) or len(signature) > 160: raise ValueError('signature size')
            base64.b64decode(signature, validate=True)
            payload = pending['data']; ident = payload['credentialId']; action = payload['action']
            with self.transaction() as db:
                row = self.credential(db, ident)
                if pending['expires'] <= self.clock(): raise ValueError('challenge unavailable')
                self.crypto('verify', publicKey=row['public_key'], payload=base64.b64encode(pending['payload']).decode(), signature=signature)
                if action in ('approve', 'sign', 'reject'):
                    self.active(db, ident)
                    decision = 'REJECTED' if action == 'reject' else 'APPROVED'
                    level = None
                    if pending['federation']:
                        self.verified_profile(db, ident)
                        target = db.execute('SELECT * FROM federation_requests WHERE id=?', (payload['requestId'],)).fetchone()
                        # The signed text must be the stored text; the request cannot change after display.
                        if target is None or self.federation_sign_message(target) != payload.get('signMessage'):
                            raise ValueError('request unavailable')
                        level = self.federation_level(target)
                        if (level == 'pin') != (payload.get('verification') == 'pin'): raise ValueError('verification binding')
                    if 'newPin' in request or ('pin' in request and (level != 'pin' or decision != 'APPROVED')): raise ValueError('fields')
                    # Rejecting never needs the code; approving a code-level request always does.
                    if level == 'pin' and decision == 'APPROVED': failure = self.verify_security_code(db, ident, request.get('pin'))
                    if failure is None:
                        if pending['federation']:
                            changed = db.execute("UPDATE federation_requests SET state=?,credential=? WHERE id=? AND credential IS NULL AND state='PENDING' AND expires>?",
                                (decision, ident, payload['requestId'], self.clock())).rowcount
                        else:
                            if action == 'sign': raise ValueError('action')
                            changed = db.execute("UPDATE requests SET state=? WHERE id=? AND credential=? AND state='PENDING' AND expires>?",
                                (decision, payload['requestId'], ident, self.clock())).rowcount
                        if changed != 1: raise ValueError('request unavailable')
                        self.event(db, ident, {'approve': 'APPROVED', 'sign': 'SIGNED', 'reject': 'REJECTED'}[action], payload['requestId'])
                elif action == 'set-pin':
                    failure = self.set_security_code(db, ident, request.get('pin'), request.get('newPin'))
                elif 'pin' in request or 'newPin' in request: raise ValueError('fields')
                elif action == 'revoke': self._revoke(db, ident)
                # Commit a refused code without another key-service call: an outage
                # while opening the snapshot must not roll back a counted failure.
                snapshot = self.snapshot(db, ident) if failure is None else None
                if action == 'inspect':
                    self.active(db, ident)
                    if pending['federation']:
                        self.verified_profile(db, ident)
                        target = db.execute("SELECT * FROM federation_requests WHERE id=? AND credential IS NULL AND state='PENDING' AND expires>?",
                            (payload['requestId'], self.clock())).fetchone()
                        if target is None: raise ValueError('request unavailable')
                        snapshot['requests'] = [self.federation_description(target)] + snapshot['requests'][:4]
            # Raised only after commit: a wrong code is counted even though the decision is refused.
            if failure is not None: raise failure
            return snapshot

    def verify_security_code(self, db, ident, pin):
        """None when correct; otherwise the error to raise after the failure count is committed."""
        row = db.execute('SELECT * FROM security_codes WHERE credential=?', (ident,)).fetchone()
        if row is None: return SecurityCodeError('PIN_REQUIRED')
        if row['locked']: return SecurityCodeError('PIN_LOCKED', 0)
        if pin is None: return SecurityCodeError('PIN_REQUIRED', SECURITY_CODE_ATTEMPTS-row['failures'])
        expected = self.vault.reference('security-code-v1:'+ident, security_code(pin))
        if secrets.compare_digest(row['hash'], expected):
            if row['failures']: db.execute('UPDATE security_codes SET failures=0 WHERE credential=?', (ident,))
            return None
        failures = row['failures']+1; locked = failures >= SECURITY_CODE_ATTEMPTS
        db.execute('UPDATE security_codes SET failures=?,locked=?,updated=? WHERE credential=?', (failures, int(locked), int(self.clock()), ident))
        self.event(db, ident, 'SECURITY_CODE_LOCKED' if locked else 'SECURITY_CODE_FAILED')
        return SecurityCodeError('PIN_LOCKED' if locked else 'PIN_INCORRECT', SECURITY_CODE_ATTEMPTS-failures)

    def set_security_code(self, db, ident, current, new):
        """Choose a code, or change it with the current one. A locked code is only replaced by re-registration."""
        self.active(db, ident)
        new = security_code(new)
        row = db.execute('SELECT * FROM security_codes WHERE credential=?', (ident,)).fetchone()
        if row is not None:
            failure = self.verify_security_code(db, ident, current)
            if failure is not None: return failure
        elif current is not None: raise ValueError('fields')
        profile = self.verified_profile(db, ident)
        birth = self.vault.crypt('open', ident, profile['person'], json.loads(profile['sealed'])).get('birthDateMrz')
        if weak_security_code(new, birth): raise SecurityCodeError('PIN_WEAK')
        db.execute('INSERT INTO security_codes VALUES(?,?,0,0,?) ON CONFLICT(credential) DO UPDATE SET hash=excluded.hash,failures=0,locked=0,updated=excluded.updated',
            (ident, self.vault.reference('security-code-v1:'+ident, new), int(self.clock())))
        self.event(db, ident, 'SECURITY_CODE_SET')
        return None

    def snapshot(self, db, ident):
        row = self.credential(db, ident); state = self.state(row)
        requests = []
        if state == 'ACTIVE':
            requests = [{'id': r['id'], 'relyingParty': RP_NAME, 'purpose': PURPOSE, 'code': r['code'], 'expiresAt': r['expires']}
                for r in db.execute("SELECT * FROM requests WHERE credential=? AND state='PENDING' AND expires>? ORDER BY created DESC LIMIT 5", (ident, self.clock()))]
        events = [{'id': str(e['id']), 'kind': e['kind'], 'time': e['time']}
            for e in db.execute('SELECT * FROM events WHERE credential=? ORDER BY id DESC LIMIT 50', (ident,))]
        profile = db.execute('SELECT * FROM profiles WHERE credential=?', (ident,)).fetchone()
        identity = None
        if profile is not None and state in ('ACTIVE', 'PENDING_REVIEW'):
            identity = self.vault.crypt('open', ident, profile['person'], json.loads(profile['sealed']))
        revocation_code = None
        if getattr(self, 'notifications', False) and state in ('ACTIVE', 'PENDING_REVIEW'):
            code = db.execute('''SELECT r.sealed FROM revocation_codes r JOIN notice_contacts n
                ON r.credential=n.credential AND r.contact_version=n.contact_version
                WHERE r.credential=?''', (ident,)).fetchone()
            if code is not None:
                value = self.vault.crypt('open', ident, 'revocation-token-v1', json.loads(code['sealed']))
                token = value.get('token')
                if not isinstance(token, str) or not re.fullmatch('[A-Za-z0-9_-]{43}', token):
                    raise ValueError('invalid revocation proof')
                revocation_code = ident+'.'+token
        code = None
        if getattr(self, 'security_codes_supported', True):
            stored = self.security_code_status(db, ident)
            code = {'set': stored is not None, 'locked': bool(stored and stored['locked']),
                'attemptsRemaining': SECURITY_CODE_ATTEMPTS-(stored['failures'] if stored else 0)}
        return {'credentialId': ident, 'state': state, 'createdAt': row['created'], 'expiresAt': row['expires'], 'identity': identity,
            'requests': requests, 'events': events, 'environment': 'PRIVATE_PILOT', 'legalIdentityIssued': False,
            'revocationCode': revocation_code, 'securityCode': code}

    def security_code_status(self, db, ident):
        return db.execute('SELECT failures,locked FROM security_codes WHERE credential=?', (ident,)).fetchone()

    def verified_profile(self, db, ident):
        self.active(db, ident)
        profile = db.execute('SELECT * FROM profiles WHERE credential=?', (ident,)).fetchone()
        if profile is None or profile['document_expires'] <= self.clock(): raise ValueError('verified identity required')
        return profile

    @staticmethod
    def federation_sign_message(row):
        return row['sign_message'] if 'sign_message' in row.keys() else None

    @staticmethod
    def federation_level(row):
        return row['level'] if 'level' in row.keys() else None

    @classmethod
    def federation_description(cls, row):
        message = cls.federation_sign_message(row)
        description = {'id': row['id'], 'relyingParty': FEDERATION_RP, 'purpose': SIGN_PURPOSE if message is not None else FEDERATION_PURPOSE,
            'code': row['code'], 'expiresAt': row['expires']}
        if message is not None: description['signMessage'] = message
        if cls.federation_level(row) == 'pin': description['verification'] = 'pin'
        return description

    def federation_start(self, binding, audience, message=None, level=None):
        if not isinstance(binding, str) or not re.fullmatch('[A-Za-z0-9_-]{1,200}', binding): raise ValueError('binding')
        message = sign_message(message)
        if message is not None and not getattr(self, 'federated_signing', True): raise ValueError('signing unavailable')
        if level not in (None, 'pin') or (level == 'pin' and not getattr(self, 'security_codes_supported', True)): raise ValueError('verification level')
        with self.transaction() as db:
            self.lock_federation_quota(db)
            if db.execute("SELECT count(*) FROM federation_requests WHERE state='PENDING' AND expires>?", (self.clock(),)).fetchone()[0] >= 32:
                raise ValueError('too many requests')
            ident, secret = secrets.token_hex(32), secrets.token_urlsafe(32)
            expires = int(self.clock())+120
            values = (ident, hashlib.sha256(secret.encode()).hexdigest(), 'PENDING', int(self.clock()), expires,
                 f'{secrets.randbelow(1000000):06d}', binding, audience)
            if message is None and level is None:
                db.execute('INSERT INTO federation_requests(id,credential,secret_hash,state,created,expires,code,binding,audience) VALUES(?,NULL,?,?,?,?,?,?,?)', values)
            else:
                db.execute('INSERT INTO federation_requests(id,credential,secret_hash,state,created,expires,code,binding,audience,sign_message,level) VALUES(?,NULL,?,?,?,?,?,?,?,?,?)', values+(message, level))
            row = db.execute('SELECT * FROM federation_requests WHERE id=?', (ident,)).fetchone()
            return self.federation_description(row) | {'secret': secret}

    def lock_federation_quota(self, db):
        pass # SQLite's write transaction already serializes this quota.

    def federation_result(self, operation, request, secret, binding, audience):
        identifier(request)
        if not isinstance(secret, str) or not 32 <= len(secret) <= 64: raise ValueError('secret')
        with self.transaction() as db:
            row = db.execute('SELECT * FROM federation_requests WHERE id=?', (request,)).fetchone()
            if (row is None or row['binding'] != binding or row['audience'] != audience or
                not secrets.compare_digest(row['secret_hash'], hashlib.sha256(secret.encode()).hexdigest())):
                raise ValueError('federation binding')
            if operation == 'cancel':
                db.execute("UPDATE federation_requests SET state='CANCELLED' WHERE id=? AND state IN ('PENDING','APPROVED')", (request,))
                return {'state': 'CANCELLED'}
            if row['expires'] <= self.clock():
                if operation == 'poll': return {'state': 'EXPIRED'}
                raise ValueError('expired request')
            if operation == 'poll':
                if row['state'] == 'APPROVED': self.verified_profile(db, row['credential'])
                return {'state': row['state']}
            if operation != 'consume' or row['state'] != 'APPROVED': raise ValueError('no unconsumed approval')
            profile = self.verified_profile(db, row['credential'])
            identity = self.vault.crypt('open', row['credential'], profile['person'], json.loads(profile['sealed']))
            if db.execute("UPDATE federation_requests SET state='CONSUMED' WHERE id=? AND state='APPROVED'", (request,)).rowcount != 1:
                raise ValueError('no unconsumed approval')
            self.event(db, row['credential'], 'AUTHENTICATED', request)
            result = {'state': 'AUTHENTICATED', 'credentialId': row['credential'], 'version': profile['version'],
                'subject': self.federation_subject(db, audience, profile['person']),
                'identity': {k: identity[k] for k in ('displayName', 'birthDateMrz', 'portraitJpeg')}}
            message = self.federation_sign_message(row)
            if message is not None: result['signMessageSha256'] = hashlib.sha256(message.encode()).hexdigest()
            # Only reachable after verify_security_code accepted the code for this request.
            if self.federation_level(row) == 'pin': result['verification'] = 'pin'
            return result

    def federation_subject(self, db, audience, person):
        return self.vault.reference('subject-v1:'+audience, person)

    def federation_check(self, ident, subject, version, audience):
        with self.transaction() as db:
            profile = self.verified_profile(db, ident)
            expected = self.federation_subject(db, audience, profile['person'])
            if not isinstance(subject, str) or not secrets.compare_digest(subject, expected) or version != profile['version']:
                raise ValueError('identity binding')
            return {'state': 'ACTIVE', 'expiresAt': self.active(db, ident)['expires']}
