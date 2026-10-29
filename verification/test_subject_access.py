"""Synthetic rights-case extraction, real SQLite and profile encryption; no participants."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import notices
import subject_access
from enrollment_policy import EnrollmentPolicy, canonical
from test_enrollment_policy import fixture_policy, NOW
from wallet import Wallet


def consent_proof(receipt, digest):
    payload = {'receipt': receipt, 'acceptance': {'policyDigest': digest,
        'termsAccepted': True, 'biometricsAccepted': True}}
    return json.dumps({'payload': base64.b64encode(canonical(payload)).decode(),
                      'assertion': 'SECRET_ATTESTATION', 'appPublicKey': 'synthetic-app-key'})


class SubjectAccessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve(); self.path = self.root/'wallet.sqlite'
        self.wallet = Wallet(self.path, 'https://example.invalid', crypto=lambda *a, **k: None)
        self.wallet.vault.key(create=True)
        self.case = {'version': 1, 'reference': 'TEST_CASE_001', 'identityCheck': 'TEST_CHECK_001',
                     'credentials': ['a'*64, 'b'*64]}
        self.dest = self.root/'extraction'
        policy = EnrollmentPolicy(fixture_policy(), clock=lambda: NOW)
        with self.wallet.transaction() as db:
            notices.install(db)
            for credential, person, tag, name in [('a','p','x','ALICE'), ('b','p','x','ALICE'), ('c','q','y','BOB_PRIVATE')]:
                ident = credential*64
                db.execute('INSERT INTO credentials VALUES(?,?,?,?,?,?,?)',
                    (ident, 'synthetic-public-'+credential, 'REVOKED' if credential=='a' else 'ACTIVE', NOW-100, NOW+100,
                     'TEST_DECISION', 'subject-'+credential))
                db.execute('INSERT OR IGNORE INTO persons VALUES(?,?)', (person*64, tag*64))
                db.execute('INSERT INTO profile_documents VALUES(?,?)', (ident, tag*64))
                if credential == 'a':
                    db.execute('INSERT INTO profile_evidence VALUES(?,?,?,?,?)', (ident, 'old-version', NOW-100, NOW+100, NOW))
                else:
                    sealed = self.wallet.vault.crypt('seal', ident, person*64, {'displayName': name, 'portraitJpeg':'U1lOVEhFVElD'})
                    db.execute('INSERT INTO profiles VALUES(?,?,?,?,?,?)', (ident, person*64, 'version-'+credential, json.dumps(sealed), NOW, NOW+100))
                db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?)', (credential+'request', ident, 'SECRET_REQUEST_'+credential, 'PENDING', NOW, NOW+100, '123456'))
                db.execute('INSERT INTO federation_requests VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                    (credential+'federation', ident, 'SECRET_FEDERATION_'+credential, 'APPROVED', NOW, NOW+100, '654321',
                     'binding-'+credential, 'https://test.invalid', 'SYNTHETIC AGREEMENT '+name, 'test-level'))
                db.execute('INSERT INTO events(credential,kind,time,request) VALUES(?,?,?,?)', (ident, 'SYNTHETIC_EVENT', NOW, credential+'request'))
                db.execute('INSERT INTO security_codes VALUES(?,?,?,?,?)', (ident, 'SECRET_PIN_'+credential, 0, 0, NOW))
                db.execute('INSERT INTO notice_contacts VALUES(?,?,?)', (ident, 'contact-'+credential, 'evidence-'+credential))
                db.execute('INSERT INTO notice_outbox VALUES(?,?,?,?,?,?,?,?)', (credential+'notice', ident, 'contact-'+credential, 'ACTIVATED_V1', NOW, 'QUEUED', 1, 'receipt-'+credential))
                db.execute('INSERT INTO revocation_codes VALUES(?,?,?,?)', (ident, 'SECRET_REVOCATION_'+credential, 'contact-'+credential, 'evidence-'+credential))
            db.execute('INSERT INTO retired_documents VALUES(?)', ('x'*64,))
            db.execute('INSERT INTO biometric_failures VALUES(?,?)', ('x'*64, NOW))
            db.execute('INSERT INTO biometric_failures VALUES(?,?)', ('y'*64, NOW))
            db.execute('INSERT INTO enrollment_policies VALUES(?,?)', (policy.digest, canonical(policy.archived()).decode()))
            for ident, receipt in [('b','d'),('c','e')]:
                db.execute('INSERT INTO enrollment_consents VALUES(?,?,?,?,?,?)',
                    (receipt*64, ident*64, policy.digest, NOW, consent_proof(receipt*64,policy.digest), None))
                db.execute('INSERT INTO credential_consents VALUES(?,?)', (ident*64, receipt*64))
            retention = {'version':1, 'reference':'TEST_RETENTION_001', 'regime':'private-beta',
                'unboundDays':1, 'boundDays':1, 'protectedReceipts':['d'*64,'e'*64]}
            record = canonical(retention).decode()
            db.execute('INSERT INTO consent_retention_runs(time,policy,policy_sha256,counts) VALUES(?,?,?,?)',
                (NOW, record, hashlib.sha256(record.encode()).hexdigest(),
                 json.dumps({'credential_consents':0,'enrollment_consents':0,'enrollment_policies':0})))

    def export(self, **kw):
        return subject_access.export_case(self.path, self.dest, self.case, 'f'*40, **kw)

    def test_case_contains_plain_profile_history_and_own_evidence_without_other_person_or_secrets(self):
        before = self.path.read_bytes()
        result = self.export(); raw = (self.dest/'case.json').read_bytes(); data = json.loads(raw)
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(result['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertTrue(result['reviewRequired'])
        self.assertEqual('ALICE', data['records']['profiles'][0]['data']['displayName'])
        self.assertEqual('a'*64, data['records']['profile_evidence'][0]['credential'])
        self.assertEqual(['d'*64], data['records']['consent_retention_runs'][0]['protectedReceipts'])
        self.assertIs(data['records']['enrollment_consents'][0]['recordedAcceptance']['biometricsAccepted'], True)
        self.assertEqual(2, len(data['records']['events']))
        self.assertIn('DynamoDB', str(data['notCovered']))
        for forbidden in ('BOB_PRIVATE', 'SECRET_', 'c'*64, 'e'*64, 'y'*64, 'q'*64):
            self.assertNotIn(forbidden, raw.decode())
        self.assertEqual(0o700, self.dest.stat().st_mode & 0o777)
        self.assertEqual(0o600, (self.dest/'case.json').stat().st_mode & 0o777)

    def test_missing_old_registration_or_unrelated_person_rejects_without_output(self):
        for ids in (['b'*64], ['a'*64,'b'*64,'c'*64], ['f'*64]):
            with self.subTest(ids=ids):
                self.case['credentials'] = ids
                with self.assertRaises(ValueError): self.export()
                self.assertFalse(self.dest.exists())

    def test_registry_binding_decrypts_only_selected_person_and_flags_lost_profile_context(self):
        from registry_binding import RegistryBindings
        RegistryBindings(self.wallet,source='synthetic-test')
        with self.wallet.transaction() as db:
            for key,person in (('a','p'),('b','p'),('c','q')):
                sealed=self.wallet.vault.crypt('seal','registry:'+key*64,person*64,{'synthetic':'BINDING_'+key})
                db.execute('INSERT INTO registry_bindings VALUES(?,?,?)',(key*64,person*64,json.dumps(sealed)))
                db.execute('INSERT INTO registry_evidence VALUES(?,?)',('synthetic-evidence-'+key,key*64))
            db.execute('INSERT INTO registry_replacements VALUES(?,?)',('a'*64,'b'*64))
        self.export();raw=(self.dest/'case.json').read_text();data=json.loads(raw)['records']
        selected={row['credential']:row for row in data['registry_bindings']}
        self.assertEqual('BINDING_b',selected['b'*64]['data']['synthetic'])
        self.assertIs(selected['a'*64]['encryptedContentRequiresSeparateReview'],True)
        self.assertNotIn('sealed',selected['a'*64])
        self.assertNotIn('BINDING_c',raw);self.assertNotIn('c'*64,raw)
        self.assertEqual([{'previous':'a'*64,'replacement':'b'*64}],data['registry_replacements'])

    def test_mismatched_recorded_choice_is_not_exported_as_valid_acceptance(self):
        with self.wallet.transaction() as db:
            digest=db.execute('SELECT digest FROM enrollment_policies').fetchone()[0]
            db.execute('UPDATE enrollment_consents SET proof=? WHERE id=?',
                       (consent_proof('e'*64,digest),'d'*64))
        with self.assertRaisesRegex(ValueError,'recorded consent choice binding'):self.export()
        self.assertFalse(self.dest.exists())

    def test_replacement_document_keeps_alias_and_retired_history_in_one_case(self):
        with self.wallet.transaction() as db:
            db.execute('INSERT INTO persons VALUES(?,?)',('r'*64,'z'*64))
            db.execute('INSERT INTO document_links VALUES(?,?)',('z'*64,'p'*64))
            db.execute('UPDATE profile_documents SET document_tag=? WHERE credential=?',('z'*64,'b'*64))
        self.export();data=json.loads((self.dest/'case.json').read_bytes())['records']
        self.assertEqual({'p'*64,'r'*64},{r['id'] for r in data['persons']})
        self.assertEqual([{'document_tag':'z'*64,'person':'p'*64}],data['document_links'])
        self.assertEqual([{'document_tag':'x'*64}],data['retired_documents'])

    def test_legacy_schema_is_read_without_migration_or_claiming_receipts_exist(self):
        with self.wallet.transaction() as db:
            db.execute('DROP TABLE erasure_subjects'); db.execute('DROP TABLE erasure_runs')
            for table in ('credential_consents','enrollment_consents','enrollment_policies','consent_retention_runs','retention_runs','profile_evidence'):
                db.execute('DROP TABLE '+table)
        before = self.path.read_bytes(); self.export()
        result = json.loads((self.dest/'case.json').read_bytes())
        self.assertEqual(before, self.path.read_bytes())
        self.assertIn('enrollment_consents', result['tablesAbsentFromSource'])
        self.assertEqual([], result['records']['enrollment_consents'])

    def test_unknown_table_column_or_partial_group_fails_closed(self):
        for create, undo in [('CREATE TABLE future_person_data(value TEXT)', 'DROP TABLE future_person_data'),
                             ('CREATE TABLE sqliteXprivate(value TEXT)', 'DROP TABLE sqliteXprivate'),
                             ('ALTER TABLE credentials ADD COLUMN future_value TEXT','ALTER TABLE credentials DROP COLUMN future_value'),
                             ('ALTER TABLE credentials ADD COLUMN hidden_value TEXT AS (id)', 'ALTER TABLE credentials DROP COLUMN hidden_value'),
                             ('ALTER TABLE notice_contacts RENAME TO old_contacts','ALTER TABLE old_contacts RENAME TO notice_contacts')]:
            with self.subTest(create=create):
                with self.wallet.transaction() as db: db.execute(create)
                with self.assertRaises(ValueError): self.export()
                self.assertFalse(self.dest.exists())
                with self.wallet.transaction() as db: db.execute(undo)

    def test_key_failure_size_limit_and_deadline_leave_no_output_or_source_changes(self):
        before = self.path.read_bytes(); key = self.path.with_suffix('.identity-key'); original = key.read_bytes()
        key.write_bytes(b'0'*64)
        with self.assertRaises(ValueError): self.export()
        key.write_bytes(original)
        with self.assertRaises(ValueError): self.export(max_bytes=100)
        with patch.object(subject_access, 'DEADLINE', -1), self.assertRaises((ValueError, TimeoutError, sqlite3.DatabaseError)):
            self.export()
        with patch.object(subject_access, 'MAX_ROWS', 1), self.assertRaises(ValueError): self.export()
        self.assertFalse(self.dest.exists()); self.assertEqual(before, self.path.read_bytes())

    def test_receipt_only_key_does_not_require_or_create_identity_key(self):
        ident = 'f'*64
        with self.wallet.transaction() as db:
            digest = db.execute('SELECT digest FROM enrollment_policies').fetchone()[0]
            db.execute('INSERT INTO enrollment_consents VALUES(?,?,?,?,?,?)', ('9'*64,ident,digest,NOW,consent_proof('9'*64,digest),None))
        self.case['credentials']=[ident]
        key=self.path.with_suffix('.identity-key');key.unlink()
        self.export(); result=json.loads((self.dest/'case.json').read_bytes())
        self.assertEqual([],result['records']['credentials'])
        self.assertEqual('9'*64,result['records']['enrollment_consents'][0]['id'])
        self.assertFalse(key.exists())

    def test_committed_wal_data_is_included_without_using_application_writer(self):
        db=sqlite3.connect(self.path);self.addCleanup(db.close)
        self.assertEqual('wal',db.execute('PRAGMA journal_mode=WAL').fetchone()[0])
        db.execute('INSERT INTO events(credential,kind,time) VALUES(?,?,?)',('b'*64,'COMMITTED_WAL_EVENT',NOW));db.commit()
        self.export();result=json.loads((self.dest/'case.json').read_bytes())
        self.assertIn('COMMITTED_WAL_EVENT',{r['kind'] for r in result['records']['events']})
        self.assertEqual(4,db.execute('SELECT count(*) FROM events').fetchone()[0])

    def test_concurrent_revocation_does_not_mix_old_credentials_with_new_events(self):
        writer=sqlite3.connect(self.path);self.addCleanup(writer.close)
        writer.execute('PRAGMA journal_mode=WAL')
        original=subject_access.select
        def changed_after_first_read(db,table,field,values,budget):
            result=original(db,table,field,values,budget)
            if table=='credentials':
                writer.execute("UPDATE credentials SET state='REVOKED' WHERE id=?",('b'*64,))
                writer.execute('INSERT INTO events(credential,kind,time) VALUES(?,?,?)',('b'*64,'CONCURRENT_REVOKE',NOW))
                writer.commit()
            return result
        with patch.object(subject_access,'select',side_effect=changed_after_first_read):self.export()
        data=json.loads((self.dest/'case.json').read_bytes())['records']
        self.assertEqual('ACTIVE',next(r['state'] for r in data['credentials'] if r['id']=='b'*64))
        self.assertNotIn('CONCURRENT_REVOKE',{r['kind'] for r in data['events']})
        self.assertEqual('REVOKED',writer.execute('SELECT state FROM credentials WHERE id=?',('b'*64,)).fetchone()[0])

    def test_existing_or_linked_destinations_and_database_are_rejected(self):
        self.dest.mkdir();sentinel=self.dest/'keep';sentinel.write_text('KEEP')
        with self.assertRaises(FileExistsError):self.export()
        self.assertEqual('KEEP',sentinel.read_text());sentinel.unlink();self.dest.rmdir()
        self.dest.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(FileExistsError):self.export()
        self.dest.unlink()
        alias=self.root/'alias.sqlite';alias.symlink_to(self.path)
        with self.assertRaises(ValueError):subject_access.export_case(alias,self.dest,self.case,'f'*40)
        alias.unlink();os.link(self.path,alias)
        with self.assertRaises(ValueError):self.export()

    def test_private_case_input_rejects_duplicates_links_fifo_and_loose_modes(self):
        path=self.root/'case-input.json';path.write_text(json.dumps(self.case));path.chmod(0o600)
        self.assertEqual(self.case,subject_access.read_case(path))
        path.chmod(0o644)
        with self.assertRaises(ValueError):subject_access.read_case(path)
        path.chmod(0o600);alias=self.root/'alias';alias.symlink_to(path)
        with self.assertRaises(OSError):subject_access.read_case(alias)
        alias.unlink();os.link(path,alias)
        with self.assertRaises(ValueError):subject_access.read_case(path)
        alias.unlink();path.write_text('{"version":1,"version":1}')
        with self.assertRaises(ValueError):subject_access.read_case(path)
        path.unlink();os.mkfifo(path,0o600)
        result=subprocess.run([sys.executable,'-c', '''
from subject_access import read_case
import sys
try:
    read_case(sys.argv[1])
except ValueError as error:
    assert str(error) == 'private owned case file required'
else:
    raise AssertionError('FIFO accepted as a case file')
''',str(path)],
            cwd=Path(__file__).parent,capture_output=True,timeout=3)
        self.assertEqual(0,result.returncode,result.stderr.decode())

    def test_cli_error_does_not_print_case_person_or_secret(self):
        case=self.root/'case-input.json';case.write_text(json.dumps(self.case));case.chmod(0o600)
        self.path.with_suffix('.identity-key').unlink()
        result=subprocess.run([sys.executable,str(Path(subject_access.__file__)),
            '--db',str(self.path),'--case',str(case),'--destination',str(self.dest),'--revision','f'*40],capture_output=True,timeout=10)
        self.assertEqual(2,result.returncode);self.assertEqual(b'',result.stdout)
        self.assertEqual(b'Private case extraction failed; no sensitive details logged.\n',result.stderr)
        self.assertFalse(self.dest.exists())


if __name__ == '__main__': unittest.main()
