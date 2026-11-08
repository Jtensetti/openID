"""Private issuance authorization, deliberately not mounted on any HTTP server.

The issuer receives public proof keys and a lifetime, never a passport profile,
credential ID, or target website. Production wiring requires a reviewed live
evidence checker, fresh app/key attestation, and a protected document signer.
"""
import base64
from datetime import datetime, timezone
import hashlib
import json
import secrets
import threading

from age_eligibility import eligible_over_18
from wallet import Wallet, identifier


class AgeIssuance:
    TTL = 60
    PROOF_TTL = 300
    MAX_PENDING = 32
    MAX_KEYS = 30

    def __init__(self, wallet, *, attest, evidence, issue):
        # PostgreSQL and the public beta need separate rollout/retention design.
        if type(wallet) is not Wallet or wallet.test_beta:
            raise ValueError('private SQLite wallet required')
        if not all(callable(value) for value in (attest, evidence, issue)):
            raise ValueError('issuance dependencies required')
        self.wallet, self.attest, self.evidence, self.issue = wallet, attest, evidence, issue
        self.lock, self.pending = threading.RLock(), {}
        with wallet.transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS age_issued_keys (digest TEXT PRIMARY KEY)')

    @staticmethod
    def _keys(keys):
        if not isinstance(keys, list) or not 1 <= len(keys) <= AgeIssuance.MAX_KEYS:
            raise ValueError('proof keys')
        result = []
        for key in keys:
            if not isinstance(key, str) or len(key) > 128:
                raise ValueError('proof key')
            try:
                raw = base64.b64decode(key, validate=True)
            except ValueError:
                raise ValueError('proof key') from None
            # Exact DER SubjectPublicKeyInfo prefix for an uncompressed P-256 key.
            # Curve membership and possession are checked by the crypto verifier.
            if (len(raw) != 91 or raw[:27].hex() !=
                    '3059301306072a8648ce3d020106082a8648ce3d03010703420004'
                    or base64.b64encode(raw).decode() != key):
                raise ValueError('P-256 proof key required')
            result.append(key)
        if len(set(result)) != len(result):
            raise ValueError('distinct proof keys required')
        return result

    def _eligible(self, db, ident):
        wallet = self.wallet
        row = wallet.active(db, ident)
        profile = wallet.verified_profile(db, ident)
        if db.execute('''SELECT 1 FROM retired_documents r JOIN profile_documents p
                ON r.document_tag=p.document_tag WHERE p.credential=?''', (ident,)).fetchone():
            raise ValueError('document retired')
        value = wallet.vault.crypt('open', ident, profile['person'], json.loads(profile['sealed']))
        # Dates come from the authenticated sealed profile, never the caller.
        today = datetime.fromtimestamp(wallet.clock(), timezone.utc).date()
        if not eligible_over_18(value, today=today) or self.evidence(ident) is not True:
            raise ValueError('current adult evidence required')
        return min(int(wallet.clock()) + self.PROOF_TTL, row['expires'], profile['document_expires'])

    def begin(self, credential_id, public_keys):
        ident, keys = identifier(credential_id), self._keys(public_keys)
        with self.lock, self.wallet.transaction() as db:
            self._eligible(db, ident)
            now = self.wallet.clock()
            self.pending = {key: value for key, value in self.pending.items() if value['expiresAt'] > now}
            if len(self.pending) >= self.MAX_PENDING:
                raise ValueError('issuance capacity')
            challenge = secrets.token_hex(32)
            payload = {'version': 1, 'action': 'issue-age-18', 'origin': self.wallet.origin,
                       'credentialId': ident, 'challengeId': challenge,
                       'expiresAt': int(now) + self.TTL, 'publicKeys': keys}
            raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
            self.pending[challenge] = payload
            return {'id': challenge, 'signingInput': base64.b64encode(raw).decode()}

    def finish(self, challenge_id, *, owner_signature, key_signatures, attestation):
        identifier(challenge_id)
        with self.lock:
            payload = self.pending.pop(challenge_id, None)
        if payload is None or payload['expiresAt'] <= self.wallet.clock():
            raise ValueError('issuance unavailable')
        keys = payload['publicKeys']
        if not isinstance(key_signatures, list) or len(key_signatures) != len(keys):
            raise ValueError('proof of possession required')
        for signature in [owner_signature, *key_signatures]:
            if not isinstance(signature, str) or len(signature) > 160:
                raise ValueError('signature')
            base64.b64decode(signature, validate=True)
        raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
        encoded = base64.b64encode(raw).decode()
        ident = payload['credentialId']
        wallet = self.wallet
        with wallet.transaction() as db:
            expires = self._eligible(db, ident)
            owner = wallet.credential(db, ident)
            wallet.crypto('verify', publicKey=owner['public_key'], payload=encoded, signature=owner_signature)
            if owner['public_key'] in keys:
                raise ValueError('identity key cannot be a proof key')
            for key, signature in zip(keys, key_signatures):
                wallet.crypto('verify', publicKey=key, payload=encoded, signature=signature)
            # The attester must verify a fresh assertion over these exact bytes,
            # including key order, owner, server origin, challenge and expiry.
            if self.attest(ident, raw, attestation) is not True:
                raise ValueError('fresh app and key attestation required')
            if payload['expiresAt'] <= wallet.clock():
                raise ValueError('issuance expired')
            # Persistent uniqueness also serializes independent issuer instances.
            if db.execute('SELECT count(*) FROM age_issued_keys').fetchone()[0] + len(keys) > 10000:
                raise ValueError('private issuance capacity')
            for key in keys:
                db.execute('INSERT INTO age_issued_keys VALUES(?)', (hashlib.sha256(base64.b64decode(key)).hexdigest(),))
        # Commit key reservations before signing: a crash, failed signer or
        # revocation during signing burns the keys, rather than allowing reuse.
        result = self.issue(public_keys=tuple(keys), valid_until=expires)
        if (not isinstance(result, list) or len(result) != len(keys)
                or any(not isinstance(proof, str) or not 1 <= len(proof) <= 96 * 1024 for proof in result)
                or len(set(result)) != len(result)):
            raise ValueError('issuer result')
        with wallet.transaction() as db:
            # Recheck remote revocation, evidence and time after slow signing.
            if payload['expiresAt'] <= wallet.clock() or self._eligible(db, ident) < expires:
                raise ValueError('issuance no longer authorized')
            wallet.event(db, ident, 'AGE_PROOFS_ISSUED')
            return {'credentials': result, 'expiresAt': expires}
