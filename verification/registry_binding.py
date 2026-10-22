"""Operator-side SQLite registry binding. No registry provider or HTTP endpoint is bundled.

A lookup adapter must authenticate its registry, resolve the person and verify the
passport/registry match. A successful Python return value is not that evidence.
Synthetic identities are opt-in and can never produce national identity attributes.
"""
from dataclasses import dataclass
from datetime import date
import json
import re
import secrets
import sqlite3

from wallet import Wallet, identifier


@dataclass(frozen=True, repr=False)
class RegistryQuery:
    nonce: str
    credential: str
    profile_version: str
    document_reference: str
    passport_fields: tuple


@dataclass(frozen=True, repr=False)
class RegistryResult:
    nonce: str
    credential: str
    profile_version: str
    document_reference: str
    evidence_reference: str
    checked_at: int
    valid_until: int
    outcome: str
    protected: bool
    kind: str
    value: str


class RegistryBindings:
    MAX_AGE = 86400

    def __init__(self, wallet, *, source, lookup=None, allow_synthetic=False):
        if type(wallet) is not Wallet:
            raise ValueError('registry binding requires SQLite pilot backend')
        if not isinstance(source, str) or not re.fullmatch('[a-z][a-z0-9-]{2,63}', source):
            raise ValueError('registry source required')
        self.wallet, self.source, self.lookup = wallet, source, lookup
        self.allow_synthetic = allow_synthetic is True
        with wallet.transaction() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS registry_bindings (
                credential TEXT PRIMARY KEY REFERENCES credentials(id),
                person_tag TEXT NOT NULL, sealed TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS registry_evidence (
                reference TEXT PRIMARY KEY, credential TEXT NOT NULL REFERENCES credentials(id))''')
            db.execute('''CREATE TABLE IF NOT EXISTS registry_replacements (
                previous TEXT PRIMARY KEY REFERENCES credentials(id),
                replacement TEXT UNIQUE NOT NULL REFERENCES credentials(id))''')

    def _profile(self, db, credential):
        self.wallet.credential(db, credential)
        p = db.execute('SELECT * FROM profiles WHERE credential=?', (credential,)).fetchone()
        if p is None: raise ValueError('passport proof required')
        return p

    def _document_reference(self, db, profile):
        row = db.execute('SELECT document_tag FROM profile_documents WHERE credential=?',
                         (profile['credential'],)).fetchone()
        if row is None: raise ValueError('document binding unavailable')
        return row['document_tag']

    def _open(self, profile, sealed):
        return self.wallet.vault.crypt('open', 'registry:'+profile['credential'],
                                       profile['person'], json.loads(sealed))

    def _seal(self, profile, data):
        return json.dumps(self.wallet.vault.crypt('seal', 'registry:'+profile['credential'],
                                                profile['person'], data))

    def _tag(self, kind, value):
        return self.wallet.vault.reference('registry-person-v1:'+self.source+':'+kind, value)

    def _validate_identity(self, kind, value):
        if kind == 'synthetic':
            if not self.allow_synthetic or not isinstance(value, str) or not re.fullmatch('TEST-[A-Z0-9-]{1,60}', value):
                raise ValueError('synthetic registry identity disabled')
        elif kind not in ('personnummer', 'samordningsnummer') or not isinstance(value, str) or not re.fullmatch('[0-9]{12}', value):
            raise ValueError('registry identity format')
        else:
            day = int(value[6:8]) - (60 if kind == 'samordningsnummer' else 0)
            date(int(value[:4]), int(value[4:6]), day)
            digits = [int(c) for c in value[2:]]
            products = [digit * (2 if i % 2 == 0 else 1) for i, digit in enumerate(digits)]
            if sum(n // 10 + n % 10 for n in products) % 10:
                raise ValueError('registry identity checksum')
        # Valid syntax does not establish issuance or a person/document match:
        # both remain the responsibility of the reviewed registry adapter.

    def _fresh(self, data):
        checked, until, now = data['checkedAt'], data['validUntil'], self.wallet.clock()
        if type(checked) is not int or type(until) is not int or not checked <= now < until <= checked+self.MAX_AGE:
            raise ValueError('fresh registry evidence required')

    def bind(self, credential):
        identifier(credential)
        if self.lookup is None: raise ValueError('registry provider unavailable')
        with self.wallet.transaction() as db:
            p = self._profile(db, credential)
            profile = self.wallet.vault.crypt('open', credential, p['person'], json.loads(p['sealed']))
            fields = tuple((k, profile[k]) for k in ('givenNames', 'familyName', 'birthDateMrz',
                           'issuingState', 'nationality', 'documentExpires'))
            query = RegistryQuery(secrets.token_hex(32), credential, p['version'],
                                  self._document_reference(db, p), fields)
        try:
            result = self.lookup(query)
        except Exception:
            raise ValueError('registry provider unavailable') from None
        if type(result) is not RegistryResult or any(getattr(result, k) != getattr(query, k) for k in
                ('nonce', 'credential', 'profile_version', 'document_reference')):
            raise ValueError('registry response binding')
        if result.outcome != 'MATCH' or result.protected is not False:
            raise ValueError('registry review required')
        self._validate_identity(result.kind, result.value)
        if not isinstance(result.evidence_reference, str) or not re.fullmatch('[A-Za-z0-9_-]{8,128}', result.evidence_reference):
            raise ValueError('registry evidence reference')
        data = dict(source=self.source, kind=result.kind, value=result.value,
                    checkedAt=result.checked_at, validUntil=result.valid_until,
                    documentReference=query.document_reference, profileVersion=query.profile_version)
        tag = self._tag(result.kind, result.value)
        proof = self.wallet.vault.reference('registry-evidence-v1:'+self.source, result.evidence_reference)
        with self.wallet.transaction() as db:
            p = self._profile(db, credential)
            if p['version'] != query.profile_version or self._document_reference(db, p) != query.document_reference:
                raise ValueError('passport proof changed')
            self._fresh(data)
            old = db.execute('SELECT * FROM registry_bindings WHERE credential=?', (credential,)).fetchone()
            if old is not None:
                prior = self._open(p, old['sealed'])
                if (old['person_tag'] != tag or prior['source'] != self.source or
                        prior['kind'] != result.kind or prior['value'] != result.value):
                    raise ValueError('registry identity conflict')
            try:
                db.execute('INSERT INTO registry_evidence VALUES(?,?)', (proof, credential))
            except sqlite3.IntegrityError:
                raise ValueError('registry evidence already used') from None
            db.execute('''INSERT INTO registry_bindings VALUES(?,?,?) ON CONFLICT(credential)
                          DO UPDATE SET sealed=excluded.sealed''', (credential, tag, self._seal(p, data)))
            self.wallet.event(db, credential, 'REGISTRY_CHECKED')
        return {'state': 'BOUND', 'scope': 'PRIVATE_PILOT'}

    def _binding(self, db, credential):
        p = self._profile(db, credential)
        row = db.execute('SELECT * FROM registry_bindings WHERE credential=?', (credential,)).fetchone()
        if row is None: raise ValueError('registry binding required')
        data = self._open(p, row['sealed'])
        self._validate_identity(data['kind'], data['value'])
        self._fresh(data)
        if (data['source'] != self.source or data['profileVersion'] != p['version'] or
                data['documentReference'] != self._document_reference(db, p) or
                row['person_tag'] != self._tag(data['kind'], data['value'])):
            raise ValueError('registry identity binding')
        return p, data, row['person_tag']

    def identity_attributes(self, credential):
        # Not wired into SAML/OIDC. Disclosure needs a separate attribute/consent policy.
        with self.wallet.transaction() as db:
            self.wallet.verified_profile(db, credential)
            _, data, _ = self._binding(db, credential)
            if data['kind'] == 'synthetic': raise ValueError('synthetic national attributes forbidden')
            return {'kind': data['kind'], 'value': data['value'], 'source': data['source'],
                    'checkedAt': data['checkedAt']}

    def activate_replacement(self, previous, replacement, decision, hours=24):
        if identifier(previous) == identifier(replacement): raise ValueError('new key required')
        with self.wallet.transaction() as db:
            old, old_data, old_tag = self._binding(db, previous)
            new, data, new_tag = self._binding(db, replacement)
            if self.wallet.credential(db, previous)['decision'] is None:
                raise ValueError('previous issued identity required')
            if not secrets.compare_digest(old_tag, new_tag): raise ValueError('different registry identity')
            if db.execute('SELECT 1 FROM registry_replacements WHERE previous=?', (previous,)).fetchone():
                raise ValueError('replacement already completed')
            if self.wallet.credential(db, replacement)['state'] != 'PENDING_REVIEW':
                raise ValueError('new proofing required')
            # Do not merge an already used passport/person group implicitly.
            if old['person'] != new['person'] and db.execute(
                    'SELECT 1 FROM profiles WHERE person=? AND credential!=?', (new['person'], replacement)).fetchone():
                raise ValueError('replacement group requires review')
            profile = self.wallet.vault.crypt('open', replacement, new['person'], json.loads(new['sealed']))
            version = secrets.token_hex(32)
            sealed = self.wallet.vault.crypt('seal', replacement, old['person'], profile)
            db.execute('UPDATE profiles SET person=?,version=?,sealed=? WHERE credential=?',
                       (old['person'], version, json.dumps(sealed), replacement))
            new = self._profile(db, replacement)
            data['profileVersion'] = version
            db.execute('UPDATE registry_bindings SET sealed=? WHERE credential=?', (self._seal(new, data), replacement))
            db.execute('''INSERT INTO document_links VALUES(?,?) ON CONFLICT(document_tag)
                          DO UPDATE SET person=excluded.person''', (data['documentReference'], old['person']))
            db.execute('INSERT INTO registry_replacements VALUES(?,?)', (previous, replacement))
            if old_data['documentReference'] != data['documentReference']:
                db.execute('INSERT OR IGNORE INTO retired_documents VALUES(?)', (old_data['documentReference'],))
            self.wallet._activate(db, replacement, decision, hours)
            self.wallet.event(db, replacement, 'REGISTRY_REPLACEMENT')
        return {'state': 'ACTIVE', 'scope': 'PRIVATE_PILOT'}
