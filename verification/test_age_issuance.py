import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from age_issuance import AgeIssuance
from identity import VerifiedDocument
from test_wallet import crypt
from wallet import Wallet


class AgeIssuanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = [json.loads(crypt(op='new')) for _ in range(4)]

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.time = int(time.time())
        self.wallet = Wallet(Path(self.directory.name)/'wallet.sqlite', 'https://issuer.example', clock=lambda: self.time)
        identity = dict(givenNames='ALICE', familyName='SYNTHETIC', birthDateMrz='900101', nationality='UTO',
                        issuingState='UTO', documentNumber='TEST00001', documentExpires='2030-10-19')
        document = VerifiedDocument(b'synthetic-image', identity, 'CHECKED_CRL', 4102444800)
        # Image decoding and passport authentication have their own test suites.
        with patch.object(VerifiedDocument, 'profile', return_value=identity):
            self.ident = self.wallet.enroll(self.keys[0]['publicKey'], document)['id']
        self.wallet.activate(self.ident, 'REVIEW-synthetic-001')
        # These are explicit test doubles, not Apple attestation or mdoc signing.
        self.attest, self.evidence = Mock(return_value=True), Mock(return_value=True)
        self.signer = Mock(return_value=['opaque-proof-1', 'opaque-proof-2'])
        self.issuer = self.make_issuer()

    def make_issuer(self):
        return AgeIssuance(self.wallet, attest=self.attest, evidence=self.evidence, issue=self.signer)

    def begin(self, issuer=None, keys=None):
        return (issuer or self.issuer).begin(self.ident, [key['publicKey'] for key in (keys or self.keys[1:3])])

    def request(self, challenge, owner=0, keys=(1, 2)):
        def sign(index):
            return crypt(op='sign', key=self.keys[index]['privateKey'], payload=challenge['signingInput'])
        return dict(challenge_id=challenge['id'], owner_signature=sign(owner),
                    key_signatures=[sign(i) for i in keys], attestation='synthetic-assertion')

    def test_exact_signed_binding_and_minimal_signer_input(self):
        challenge = self.begin()
        request = self.request(challenge)
        result = self.issuer.finish(**request)
        self.assertEqual({'credentials', 'expiresAt'}, set(result))
        self.assertEqual(self.time+300, result['expiresAt'])
        self.signer.assert_called_once_with(public_keys=tuple(k['publicKey'] for k in self.keys[1:3]), valid_until=self.time+300)
        self.attest.assert_called_once_with(self.ident, base64.b64decode(challenge['signingInput']), 'synthetic-assertion')
        raw = json.loads(base64.b64decode(challenge['signingInput']))
        self.assertEqual('issue-age-18', raw['action'])
        self.assertEqual('https://issuer.example', raw['origin'])
        with self.assertRaises(ValueError): self.issuer.finish(**request)

    def test_wrong_owner_wrong_proof_key_and_missing_attestation_burn_challenge(self):
        for owner, keys, attested in [(3, (1, 2), True), (0, (2, 1), True), (0, (1, 2), False)]:
            challenge = self.begin()
            self.attest.return_value = attested
            with self.assertRaises(ValueError): self.issuer.finish(**self.request(challenge, owner, keys))
            with self.assertRaises(ValueError): self.issuer.finish(**self.request(challenge))
        self.signer.assert_not_called()

    def test_revoke_expiry_and_stale_evidence_before_finish(self):
        challenge = self.begin()
        self.evidence.return_value = False
        with self.assertRaises(ValueError): self.issuer.finish(**self.request(challenge))
        self.evidence.return_value = True
        challenge = self.begin()
        self.time += 60
        with self.assertRaises(ValueError): self.issuer.finish(**self.request(challenge))
        challenge = self.begin()
        self.wallet.revoke(self.ident)
        with self.assertRaises(ValueError): self.issuer.finish(**self.request(challenge))
        self.signer.assert_not_called()

    def test_revocation_during_signing_withholds_result_and_keeps_keys_burned(self):
        def revoke(**_):
            self.wallet.revoke(self.ident)
            return ['proof-1', 'proof-2']
        self.signer.side_effect = revoke
        with self.assertRaises(ValueError): self.issuer.finish(**self.request(self.begin()))
        with self.wallet.transaction() as db:
            self.assertEqual(2, db.execute('SELECT count(*) FROM age_issued_keys').fetchone()[0])

    def test_failed_signer_and_restart_cannot_reuse_keys(self):
        self.signer.side_effect = OSError('signer offline')
        with self.assertRaises(OSError): self.issuer.finish(**self.request(self.begin()))
        self.signer.side_effect = None
        new = self.make_issuer()
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError): new.finish(**self.request(self.begin(new)))
        self.assertEqual(1, self.signer.call_count)

    def test_parallel_completion_and_separate_challenges_issue_once(self):
        requests = [self.request(self.begin()) for _ in range(2)]
        def finish(request):
            try: return self.issuer.finish(**request)
            except (ValueError, __import__('sqlite3').IntegrityError): return None
        with ThreadPoolExecutor(4) as pool:
            results = list(pool.map(finish, [requests[0], requests[0], requests[1], requests[1]]))
        self.assertEqual(1, sum(r is not None for r in results))
        self.assertEqual(1, self.signer.call_count)

    def test_minor_unverified_and_retired_document_are_denied(self):
        with self.wallet.transaction() as db:
            profile = db.execute('SELECT * FROM profiles WHERE credential=?', (self.ident,)).fetchone()
            sealed = json.loads(profile['sealed'])
            value = self.wallet.vault.crypt('open', self.ident, profile['person'], sealed)
            value['birthDateMrz'] = '200101'
            changed = self.wallet.vault.crypt('seal', self.ident, profile['person'], value)
            db.execute('UPDATE profiles SET sealed=? WHERE credential=?', (json.dumps(changed), self.ident))
        with self.assertRaises(ValueError): self.begin()
        with self.wallet.transaction() as db:
            db.execute('UPDATE profiles SET sealed=? WHERE credential=?', (json.dumps(sealed), self.ident))
            db.execute('INSERT INTO retired_documents SELECT document_tag FROM profile_documents WHERE credential=?', (self.ident,))
        with self.assertRaises(ValueError): self.begin()
        with self.wallet.transaction() as db:
            db.execute('DELETE FROM profiles WHERE credential=?', (self.ident,))
        with self.assertRaises(ValueError): self.begin()

    def test_bounds_invalid_keys_and_identity_key_reuse(self):
        for keys in ([], [self.keys[1]['publicKey']]*2, ['eA=='], ['!'], [self.keys[1]['publicKey']]*31):
            with self.assertRaises(ValueError): self.issuer.begin(self.ident, keys)
        c = self.begin(keys=self.keys[:2])
        with self.assertRaises(ValueError): self.issuer.finish(**self.request(c, keys=(0, 1)))
        for _ in range(32): self.begin()
        with self.assertRaises(ValueError): self.begin()
        self.time += 61
        self.begin()

    def test_expiry_during_signing_is_withheld(self):
        def expire(**_):
            self.time += 61
            return ['proof-1', 'proof-2']
        self.signer.side_effect = expire
        with self.assertRaises(ValueError): self.issuer.finish(**self.request(self.begin()))
        with self.wallet.transaction() as db:
            self.assertEqual(2, db.execute('SELECT count(*) FROM age_issued_keys').fetchone()[0])

    def test_authenticated_issuance_to_real_mdoc_presentation_on_two_sites(self):
        from test_age_dc_backend import holder
        from age_dc_backend import MdocDcBackend
        import secrets
        signed = {}
        def issue(public_keys, valid_until):
            signed.update(holder(dict(operation='issue', publicKeys=public_keys, validUntil=valid_until)))
            return signed['credentials']
        self.signer.side_effect = issue
        result = self.issuer.finish(**self.request(self.begin()))
        backend = MdocDcBackend(signed['pem'])
        for index, origin in enumerate(['https://a.example', 'https://b.example']):
            nonce = secrets.token_urlsafe(32)
            tx = backend.dc_begin(origin, nonce)
            proof = holder(dict(operation='present', pem=signed['pem'], credential=result['credentials'][index],
                holderPem=self.keys[index+1]['privateKey'], request=tx['requests'][0]['data'],
                browserOrigin=origin, approvedOrigin=origin))
            self.assertIs(True, backend.dc_complete(tx['backend_id'], nonce, proof))
        self.assertEqual(self.time + 300, result['expiresAt'])


if __name__ == '__main__': unittest.main()
