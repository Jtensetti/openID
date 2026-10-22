"""Synthetic adapter tests; no civil-register or biometric accuracy is simulated as proven."""
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from identity import VerifiedDocument
from registry_binding import RegistryBindings, RegistryResult
from test_wallet import crypt
from wallet import Wallet
from recovery import backup, restore

AUDIENCE = 'https://service.invalid/sp'


def document(number='TEST00001'):
    return VerifiedDocument.from_verifier({
        'passiveAuthentication': True, 'portrait': base64.b64encode(b'synthetic-image-placeholder').decode(),
        'identity': dict(givenNames='ALICE', familyName='SYNTHETIC', birthDateMrz='900101',
                         nationality='UTO', issuingState='UTO', documentNumber=number, documentExpires='2030-10-19')})


def profile(doc):
    return {k: v for k, v in doc.identity.items() if k != 'documentNumber'} | {
        'displayName': 'ALICE SYNTHETIC', 'portraitJpeg': 'synthetic-test-placeholder'}


class RegistryBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = [json.loads(crypt(op='new')) for _ in range(4)]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.time = 1792454400
        self.db = Path(self.tmp.name)/'wallet.sqlite'
        self.wallet = Wallet(self.db, 'https://localhost:8765', clock=lambda:self.time)
        self.profile_patch = patch.object(VerifiedDocument, 'profile', profile)
        self.profile_patch.start(); self.addCleanup(self.profile_patch.stop)
        self.old = self.enroll(0, 'TEST00001')
        self.new = self.enroll(1, 'TEST00002')
        self.wallet.activate(self.old, 'REVIEW-old-0001')
        self.queries = []
        self.registry = RegistryBindings(self.wallet, source='fixture-registry', lookup=self.lookup, allow_synthetic=True)

    def enroll(self, key, number):
        return self.wallet.enroll(self.keys[key]['publicKey'], document(number))['id']

    def lookup(self, query):
        self.queries.append(query)
        return RegistryResult(query.nonce, query.credential, query.profile_version, query.document_reference,
                              'PROOF-'+query.nonce, self.time, self.time+3600, 'MATCH', False,
                              'synthetic', 'TEST-PERSON-ALPHA')

    def bind_both(self):
        self.registry.bind(self.old); self.registry.bind(self.new)

    def state(self, ident):
        with self.wallet.transaction() as db: return self.wallet.state(self.wallet.credential(db, ident))

    def approve(self, ident, key, request):
        ch = self.wallet.challenge({'credentialId':ident, 'action':'approve', 'requestId':request['id']})
        self.wallet.execute({'challengeId':ch['id'], 'signature':crypt(op='sign', key=self.keys[key]['privateKey'], payload=ch['signingInput'])})

    def start(self): return self.wallet.federation_start('_fixture_saml', AUDIENCE)

    def consume(self, request):
        return self.wallet.federation_result('consume', request['id'], request['secret'], '_fixture_saml', AUDIENCE)

    def login(self, ident, key):
        request=self.start(); self.approve(ident, key, request); return self.consume(request)

    def test_missing_provider_and_missing_binding_fail_closed(self):
        unavailable=RegistryBindings(self.wallet, source='fixture-registry')
        with self.assertRaises(ValueError): unavailable.bind(self.old)
        with self.assertRaises(ValueError): unavailable.identity_attributes(self.old)
        with self.assertRaises(ValueError): self.registry.activate_replacement(self.old, self.new, 'REVIEW-new-001')
        self.assertEqual('ACTIVE', self.state(self.old))

    def test_binding_is_encrypted_does_not_activate_or_disclose_test_identifier(self):
        self.bind_both()
        self.assertEqual('PENDING_REVIEW', self.state(self.new))
        for text in [b'TEST-PERSON-ALPHA', b'fixture-registry', b'PROOF-']:
            self.assertNotIn(text, self.db.read_bytes())
        self.assertNotIn('portraitJpeg', dict(self.queries[0].passport_fields))
        with self.assertRaises(ValueError): self.registry.identity_attributes(self.old)
        self.assertNotIn('personalIdentityNumber', self.login(self.old, 0)['identity'])

    def test_synthetic_identifiers_need_explicit_opt_in(self):
        disabled=RegistryBindings(self.wallet, source='fixture-registry', lookup=self.lookup)
        with self.assertRaises(ValueError): disabled.bind(self.old)

    def test_malformed_national_identifiers_are_not_treated_as_registry_evidence(self):
        for kind in ('personnummer','samordningsnummer'):
            for value in ('TEST-PERSON-ALPHA','000000000000','123','9'*12):
                self.registry.lookup=lambda q:replace(self.lookup(q),kind=kind,value=value)
                with self.assertRaises(ValueError): self.registry.bind(self.new)

    def test_operator_cli_cannot_promote_synthetic_bindings(self):
        self.bind_both()
        result=subprocess.run([sys.executable,str(Path(__file__).with_name('wallet_cli.py')),
            '--db',str(self.db),'replace-passport',self.old,self.new,'--registry-source','fixture-registry',
            '--decision','REVIEW-cli-001','--private-pilot-only'],capture_output=True,text=True)
        self.assertEqual(2,result.returncode)
        self.assertNotIn('TEST-PERSON',result.stdout+result.stderr)
        self.assertEqual('PENDING_REVIEW',self.state(self.new))

    def test_existing_pilot_database_gets_document_references_without_identity_change(self):
        session=self.login(self.old,0)
        with self.wallet.transaction() as db:
            db.execute('DROP TABLE profile_documents')
            db.execute('DROP TABLE document_links')
            db.execute('DROP TABLE retired_documents')
        self.wallet=Wallet(self.db,'https://localhost:8765',clock=lambda:self.time)
        self.assertEqual('ACTIVE',self.wallet.federation_check(self.old,session['subject'],session['version'],AUDIENCE)['state'])
        with self.wallet.transaction() as db:
            ref=db.execute('SELECT document_tag FROM profile_documents WHERE credential=?',(self.old,)).fetchone()[0]
        self.assertEqual(self.wallet.vault.document_tag(document()),ref)

    def test_response_must_match_nonce_key_profile_and_passport(self):
        for field in ('nonce', 'credential', 'profile_version', 'document_reference'):
            with self.subTest(field=field):
                self.registry.lookup=lambda q:replace(self.lookup(q), **{field:'0'*64})
                with self.assertRaises(ValueError): self.registry.bind(self.new)
        with self.wallet.transaction() as db:
            self.assertEqual(0, db.execute('SELECT count(*) FROM registry_bindings').fetchone()[0])

    def test_protected_ambiguous_mismatched_and_unavailable_registry_are_rejected(self):
        for changes in ({'protected':True}, {'protected':0}, {'outcome':'MISMATCH'}, {'outcome':'AMBIGUOUS'}, {'outcome':'UNAVAILABLE'}):
            self.registry.lookup=lambda q:replace(self.lookup(q), **changes)
            with self.assertRaises(ValueError): self.registry.bind(self.new)
        self.registry.lookup=lambda q:(_ for _ in ()).throw(RuntimeError('private-provider-detail'))
        with self.assertRaisesRegex(ValueError, '^registry provider unavailable$'): self.registry.bind(self.new)

    def test_future_expired_and_unbounded_evidence_rejected(self):
        for changes in ({'checked_at':self.time+1}, {'valid_until':self.time},
                        {'valid_until':self.time+86401}, {'checked_at':True}):
            self.registry.lookup=lambda q:replace(self.lookup(q), **changes)
            with self.assertRaises(ValueError): self.registry.bind(self.new)

    def test_evidence_cannot_be_reused_for_another_key_or_same_key(self):
        self.registry.lookup=lambda q:replace(self.lookup(q), evidence_reference='PROOF-single-use')
        self.registry.bind(self.old)
        for credential in [self.new,self.old]:
            with self.assertRaises(ValueError): self.registry.bind(credential)

    def test_conflicting_identity_and_changed_profile_are_rejected(self):
        self.bind_both()
        self.registry.lookup=lambda q:replace(self.lookup(q), value='TEST-PERSON-BETA')
        with self.assertRaises(ValueError): self.registry.bind(self.new)
        def racing_lookup(q):
            with self.wallet.transaction() as db:
                db.execute('UPDATE profiles SET version=? WHERE credential=?', ('f'*64,self.new))
            return self.lookup(q)
        self.registry.lookup=racing_lookup
        with self.assertRaises(ValueError): self.registry.bind(self.new)

    def test_new_passport_replaces_old_key_sessions_and_approved_requests_atomically(self):
        session=self.login(self.old, 0)
        pending=self.start(); self.approve(self.old, 0, pending)
        self.bind_both()
        self.registry.activate_replacement(self.old,self.new,'REVIEW-renew-001')
        self.assertEqual('REVOKED',self.state(self.old)); self.assertEqual('ACTIVE',self.state(self.new))
        with self.assertRaises(ValueError): self.consume(pending)
        with self.assertRaises(ValueError): self.wallet.federation_check(self.old,session['subject'],session['version'],AUDIENCE)
        renewed=self.login(self.new,1)
        self.assertEqual(session['subject'],renewed['subject']); self.assertNotEqual(session['version'],renewed['version'])
        with self.assertRaises(ValueError): self.wallet.activate(self.old,'REVIEW-revive-001')
        with self.assertRaises(ValueError): self.registry.activate_replacement(self.old,self.new,'REVIEW-replay-001')

    def test_same_name_and_birth_with_different_registry_identity_cannot_merge(self):
        self.registry.bind(self.old)
        self.registry.lookup=lambda q:replace(self.lookup(q),value='TEST-PERSON-BETA')
        self.registry.bind(self.new)
        with self.assertRaises(ValueError): self.registry.activate_replacement(self.old,self.new,'REVIEW-wrong-001')
        self.assertEqual('ACTIVE',self.state(self.old)); self.assertEqual('PENDING_REVIEW',self.state(self.new))

    def test_lost_phone_already_revoked_can_be_replaced_but_never_reactivated(self):
        self.bind_both(); self.wallet.revoke(self.old)
        self.registry.activate_replacement(self.old,self.new,'REVIEW-lost-001')
        self.assertEqual('REVOKED',self.state(self.old)); self.assertEqual('ACTIVE',self.state(self.new))

    def test_expired_evidence_revoked_new_key_and_stale_capture_cannot_activate(self):
        self.bind_both(); self.time+=3600
        with self.assertRaises(ValueError): self.registry.activate_replacement(self.old,self.new,'REVIEW-stale-001')
        self.bind_both(); self.wallet.revoke(self.new)
        with self.assertRaises(ValueError): self.registry.activate_replacement(self.old,self.new,'REVIEW-revoked-001')

    def test_failed_activation_rolls_back_link_ciphertext_and_old_revocation(self):
        self.bind_both()
        with self.wallet.transaction() as db: before=dict(db.execute('SELECT * FROM profiles WHERE credential=?',(self.new,)).fetchone())
        with self.assertRaises(ValueError): self.registry.activate_replacement(self.old,self.new,'bad')
        with self.wallet.transaction() as db:
            self.assertEqual(before,dict(db.execute('SELECT * FROM profiles WHERE credential=?',(self.new,)).fetchone()))
            self.assertEqual(0,db.execute('SELECT count(*) FROM document_links').fetchone()[0])
            self.assertEqual(0,db.execute('SELECT count(*) FROM registry_replacements').fetchone()[0])
        self.assertEqual('ACTIVE',self.state(self.old))

    def test_concurrent_replacements_have_one_winner(self):
        other=self.enroll(2,'TEST00003'); self.bind_both(); self.registry.bind(other)
        def attempt(candidate):
            try: self.registry.activate_replacement(self.old,candidate,'REVIEW-race-001'); return True
            except ValueError: return False
        with ThreadPoolExecutor(2) as pool: self.assertEqual(1,sum(pool.map(attempt,[self.new,other])))
        self.assertEqual(1,sum(self.state(c)=='ACTIVE' for c in [self.new,other]))

    def test_future_phone_change_keeps_document_link_and_subject_after_restart(self):
        self.bind_both(); self.registry.activate_replacement(self.old,self.new,'REVIEW-first-001')
        session=self.login(self.new,1)
        self.wallet=Wallet(self.db,'https://localhost:8765',clock=lambda:self.time)
        third=self.enroll(2,'TEST00002')
        service=RegistryBindings(self.wallet,source='fixture-registry',lookup=self.lookup,allow_synthetic=True)
        service.bind(third)
        self.assertEqual(self.wallet.vault.document_tag(document('TEST00002')),self.queries[-1].document_reference)
        self.wallet.activate(third,'REVIEW-phone-001')
        self.assertEqual(session['subject'],self.login(third,2)['subject'])
        self.assertEqual('REVOKED',self.state(self.new))

    def test_replaced_passport_cannot_be_enrolled_or_pending_capture_activated(self):
        pending_old=self.enroll(2,'TEST00001')
        self.bind_both(); self.registry.activate_replacement(self.old,self.new,'REVIEW-retire-001')
        with self.assertRaises(ValueError): self.enroll(3,'TEST00001')
        with self.assertRaises(ValueError): self.wallet.activate(pending_old,'REVIEW-old-pass-001')
        self.assertEqual('REVOKED',self.state(pending_old))

    def test_expired_capture_requires_new_proof_even_after_fresh_registry_check(self):
        self.time+=86401; self.bind_both()
        with self.assertRaises(ValueError): self.registry.activate_replacement(self.old,self.new,'REVIEW-old-capture')
        self.assertEqual('PENDING_REVIEW',self.state(self.new))

    def test_new_key_revocation_racing_replacement_always_finishes_revoked(self):
        self.bind_both()
        def replace_key():
            try: self.registry.activate_replacement(self.old,self.new,'REVIEW-revoke-race')
            except ValueError: pass
        with ThreadPoolExecutor(2) as pool:
            futures=[pool.submit(replace_key),pool.submit(self.wallet.revoke,self.new)]
            for future in futures: future.result()
        self.assertEqual('REVOKED',self.state(self.new))
        with self.assertRaises(ValueError): self.wallet.start_request(self.new)

    def test_backup_restore_never_reactivates_bound_keys(self):
        self.bind_both()
        saved=backup(self.wallet,Path(self.tmp.name)/'backup')
        self.registry.activate_replacement(self.old,self.new,'REVIEW-before-restore')
        db=restore(saved,Path(self.tmp.name)/'restore',self.wallet.vault.path)
        recovered=Wallet(db,'https://localhost:8765',clock=lambda:self.time)
        bindings=RegistryBindings(recovered,source='fixture-registry',lookup=self.lookup,allow_synthetic=True)
        with recovered.transaction() as connection:
            self.assertEqual(0,connection.execute('SELECT count(*) FROM registry_bindings').fetchone()[0])
        for credential in [self.old,self.new]:
            with self.assertRaises(ValueError): recovered.activate(credential,'REVIEW-invalid-001')
            with self.assertRaises(ValueError): bindings.identity_attributes(credential)
        with self.assertRaises(ValueError): bindings.activate_replacement(self.old,self.new,'REVIEW-invalid-002')

    def test_binding_ciphertext_cannot_move_between_credentials(self):
        self.bind_both()
        with self.wallet.transaction() as db:
            sealed=db.execute('SELECT sealed FROM registry_bindings WHERE credential=?',(self.old,)).fetchone()[0]
            db.execute('UPDATE registry_bindings SET sealed=? WHERE credential=?',(sealed,self.new))
        with self.assertRaises(ValueError): self.registry.activate_replacement(self.old,self.new,'REVIEW-tamper-001')


if __name__ == '__main__': unittest.main()
