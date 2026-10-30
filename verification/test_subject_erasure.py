"""Synthetic decisions, real SQLite transactions; no participant data or live deletion."""
import base64
from contextlib import closing
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import erasure_policy as policy
import subject_erasure as erasure
from test_enrollment_policy import NOW
import test_subject_access
from wallet import Wallet


def fixture_decision(keys, *, reference='TEST_ERASURE_001', at=NOW):
    return {'format': policy.FORMAT,
        'case': {'version': 1, 'reference': 'TEST_CASE_001', 'identityCheck': 'TEST_CHECK_001',
                 'credentials': list(keys)},
        'decisionReference': reference, 'holdReviewReference': 'TEST_HOLD_REVIEW_001', 'decidedAt': at,
        'categories': {category: ({'action': 'retain', 'reasonReference': 'TEST_RETENTION_001', 'reviewBy': at+86400}
                                  if category in policy.PROTECTED else
                                  {'action': 'erase', 'reasonReference': 'TEST_ERASURE_REASON'})
                       for category in policy.CATEGORIES},
        'copies': {'inventoryReference': 'TEST_COPIES_001', 'restoreReference': 'TEST_RESTORE_001',
                   'recipientReference': 'TEST_RECIPIENTS_001'}}


def fixture_ledger(*decisions, reviewed_at=NOW+1):
    return {'format': policy.LEDGER_FORMAT, 'authorityReference': 'TEST_CUSTODIAN_001',
            'reviewedAt': reviewed_at, 'decisions': list(decisions)}


class ErasureTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_subject_access.SubjectAccessTests(); self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.wallet, self.root = self.fixture.wallet, self.fixture.root
        self.path = self.wallet.path
        with self.wallet.transaction() as db:
            db.execute("UPDATE credentials SET state='REVOKED' WHERE id IN (?,?)", ('a'*64, 'b'*64))
        self.config = fixture_decision(['a'*64, 'b'*64]); self.ledger = fixture_ledger(self.config)

    def plan(self, config=None):
        return erasure.sqlite_case(self.path, config or self.config, clock=lambda: NOW+1)

    def apply(self, config=None, expected=None, ledger=None):
        config = config or self.config
        expected = expected or self.plan(config)['planSHA256']
        return erasure.sqlite_case(self.path, config, apply=True, expected=expected,
            ledger_value=self.ledger if ledger is None else ledger, clock=lambda: NOW+1)

    def rows(self, table):
        with closing(sqlite3.connect(self.path)) as db: return db.execute('SELECT * FROM '+table+' ORDER BY 1').fetchall()

    def snapshot(self):
        with closing(sqlite3.connect(self.path)) as db: return list(db.iterdump())

    def test_plan_is_read_only_and_apply_preserves_other_person_security_and_shared_policy(self):
        protected = {t: self.rows(t) for t in ('credentials', 'persons', 'profile_documents',
            'document_links', 'retired_documents', 'biometric_failures', 'consent_retention_runs',
            'test_beta_policy', 'test_beta_deadline')}
        before = self.path.read_bytes(); planned = self.plan()
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(1, planned['delete']['profiles']); self.assertEqual(2, planned['delete']['federation_requests'])
        self.assertEqual(0, planned['delete']['enrollment_policies'])
        self.assertNotIn('SECRET_', json.dumps(planned)); self.assertNotIn('BOB_PRIVATE', json.dumps(planned))
        result = self.apply(expected=planned['planSHA256'])
        self.assertEqual('LOCAL_DECISION_APPLIED', result['status'])
        for table, rows in protected.items(): self.assertEqual(rows, self.rows(table), table)
        for table in ('profiles', 'requests', 'federation_requests', 'events', 'security_codes',
                      'credential_consents', 'notice_contacts', 'notice_outbox', 'revocation_codes', 'test_beta_revocation_codes'):
            with closing(sqlite3.connect(self.path)) as db:
                self.assertEqual(1, db.execute('SELECT count(*) FROM '+table+' WHERE credential=?', ('c'*64,)).fetchone()[0], table)
                self.assertEqual(0, db.execute('SELECT count(*) FROM '+table+' WHERE credential IN (?,?)', ('a'*64, 'b'*64)).fetchone()[0], table)
        self.assertEqual(1, len(self.rows('erasure_runs'))); self.assertEqual(2, len(self.rows('erasure_subjects')))
        policy.validate_journal(self.rows('erasure_runs')[0])

    def test_retain_decisions_preserve_profile_and_signature_while_removing_authentication(self):
        for category in ('profiles', 'signatures'):
            self.config['categories'][category] = {'action': 'retain', 'reasonReference': 'TEST_REASON_001', 'reviewBy': NOW+100}
        profiles, signatures = self.rows('profiles'), self.rows('federation_requests')
        self.apply()
        self.assertEqual(profiles, self.rows('profiles')); self.assertEqual(signatures, self.rows('federation_requests'))
        self.assertEqual(1, len(self.rows('requests')))

    def test_active_key_missing_old_key_and_other_person_are_refused_without_writes(self):
        before = self.snapshot()
        for keys in (['b'*64], ['a'*64, 'b'*64, 'c'*64], ['f'*64]):
            with self.subTest(keys=keys), self.assertRaises(ValueError): self.plan(fixture_decision(keys))
            self.assertEqual(before, self.snapshot())
        with self.wallet.transaction() as db: db.execute("UPDATE credentials SET state='ACTIVE' WHERE id=?", ('b'*64,))
        with self.assertRaisesRegex(ValueError, 'revoke'): self.plan()

    def test_same_count_changed_content_invalidates_the_reviewed_plan(self):
        prepared = self.plan()
        with self.wallet.transaction() as db: db.execute("UPDATE requests SET secret_hash='CHANGED' WHERE credential=?", ('b'*64,))
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'plan changed'): self.apply(expected=prepared['planSHA256'])
        self.assertEqual(before, self.snapshot())

    def test_failed_journal_and_side_effect_trigger_roll_back_every_deletion(self):
        for statement in (
            "CREATE TRIGGER refuse BEFORE INSERT ON erasure_runs BEGIN SELECT RAISE(ABORT,'synthetic'); END",
            "CREATE TRIGGER refuse AFTER DELETE ON profiles BEGIN DELETE FROM credentials WHERE id='"+'c'*64+"'; END"):
            with self.wallet.transaction() as db: db.execute(statement)
            before = self.snapshot()
            with self.assertRaises(sqlite3.DatabaseError): self.apply()
            self.assertEqual(before, self.snapshot())
            with self.wallet.transaction() as db: db.execute('DROP TRIGGER refuse')

    def test_missing_decision_or_forgotten_old_ledger_entry_refuses_mutation(self):
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'missing'): self.apply(ledger=fixture_ledger())
        self.assertEqual(before, self.snapshot())
        self.apply(); other = copy.deepcopy(self.config); other['decisionReference'] = 'TEST_ERASURE_002'
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'omits'): self.apply(other, ledger=fixture_ledger(other))
        self.assertEqual(before, self.snapshot())

    def test_repeat_has_no_extra_journal_but_reintroduced_content_is_refused(self):
        self.apply(); self.assertEqual('ALREADY_APPLIED', self.apply()['status'])
        self.assertEqual(1, len(self.rows('erasure_runs')))
        with self.wallet.transaction() as db:
            db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?)', ('restored', 'b'*64, 'secret', 'CANCELLED', NOW, NOW+1, '000000'))
        with self.assertRaisesRegex(ValueError, 'reappeared'): self.apply()

    def test_overdue_retention_review_remains_visible_on_repeated_backup_replay(self):
        self.apply()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.row_factory=sqlite3.Row
            results=erasure.replay_in_transaction(db,'sqlite',self.ledger,clock=lambda:NOW+86401)
        self.assertEqual('ALREADY_APPLIED',results[0]['status'])
        self.assertCountEqual(policy.PROTECTED,results[0]['retentionReviewRequired'])
        self.assertEqual(1,len(self.rows('erasure_runs')))
        self.assertEqual([('c'*64,)],[(r[0],) for r in self.rows('profiles')])

    def test_registry_binding_content_and_evidence_are_erased_but_replacement_reference_remains(self):
        from registry_binding import RegistryBindings
        RegistryBindings(self.wallet,source='synthetic-test')
        with self.wallet.transaction() as db:
            for key,person in (('b','p'),('c','q')):
                sealed=self.wallet.vault.crypt('seal','registry:'+key*64,person*64,{'synthetic':'binding-'+key})
                db.execute('INSERT INTO registry_bindings VALUES(?,?,?)',(key*64,person*64,json.dumps(sealed)))
                db.execute('INSERT INTO registry_evidence VALUES(?,?)',('synthetic-evidence-'+key,key*64))
            db.execute('INSERT INTO registry_replacements VALUES(?,?)',('a'*64,'b'*64))
        before=self.rows('registry_replacements')
        self.apply()
        self.assertEqual([('c'*64,)],[(r[0],) for r in self.rows('registry_bindings')])
        self.assertEqual([('synthetic-evidence-c','c'*64)],self.rows('registry_evidence'))
        self.assertEqual(before,self.rows('registry_replacements'))

    def test_erasure_archive_roundtrip_and_tampered_decision_are_rejected_even_with_new_manifest(self):
        import audit_archive as archive
        self.apply();dest=self.root/'erasure-archive'
        receipt=archive.export_snapshot(archive.sqlite_snapshot(self.path),dest,'sqlite','a'*40)
        self.assertEqual('VERIFIED',archive.verify(dest,receipt['manifestSha256'])['state'])
        manifest=json.loads((dest/'manifest.json').read_bytes());self.assertEqual(5,manifest['format'])
        row=json.loads((dest/'erasure_runs.jsonl').read_bytes())
        changed=json.loads(row[2]);changed['decisionReference']='FORGED_DECISION'
        row[2]=archive.encoded(changed).decode();raw=archive.encoded(row)
        (dest/'erasure_runs.jsonl').write_bytes(raw)
        manifest['files']['erasure_runs.jsonl'].update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        raw=archive.encoded(manifest);(dest/'manifest.json').write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'decision binding'):archive.verify(dest,hashlib.sha256(raw).hexdigest())

    def test_cli_plan_apply_no_overwrite_and_no_sensitive_output(self):
        now=int(time.time());config=fixture_decision(self.config['case']['credentials'],at=now-1)
        config_path=self.root/'decision.json';erasure.write_result(config_path,config)
        ledger=self.root/'ledger.json';anchor=policy.write_ledger(ledger,fixture_ledger(config,reviewed_at=now))
        planned=self.root/'plan.json';result=self.root/'result.json'
        def cli(action,output,*extra):
            return subprocess.run([sys.executable,str(Path(erasure.__file__)),action,
                '--sqlite',str(self.path),'--decision',str(config_path),'--output',str(output),*extra],
                capture_output=True,text=True,timeout=5)
        preview=cli('plan',planned);self.assertEqual(0,preview.returncode,preview.stderr)
        expected=json.loads(planned.read_bytes())['planSHA256'];before=self.snapshot()
        args=('--ledger',str(ledger),'--ledger-sha256',anchor,'--expected-plan-sha256',expected)
        refused=cli('apply',planned,*args);self.assertEqual(2,refused.returncode);self.assertEqual(before,self.snapshot())
        applied=cli('apply',result,*args);self.assertEqual(0,applied.returncode,applied.stderr)
        self.assertEqual('LOCAL_DECISION_APPLIED',json.loads(result.read_bytes())['status'])
        self.assertEqual(0o600,result.stat().st_mode&0o777)
        for raw in (preview.stdout,preview.stderr,refused.stderr,applied.stdout,applied.stderr):
            for secret in ('SECRET_','BOB_PRIVATE','Traceback',str(self.path)):self.assertNotIn(secret,raw)

    def test_receipt_only_erasure_and_old_empty_copy_replay_block_the_same_key(self):
        public = base64.b64encode(b'SYNTHETIC_KEY_FOR_ERASURE').decode()
        ident = hashlib.sha256(base64.b64decode(public)).hexdigest()
        with self.wallet.transaction() as db:
            row = db.execute('SELECT * FROM enrollment_consents WHERE subject=?', ('b'*64,)).fetchone()
            db.execute('INSERT INTO enrollment_consents VALUES(?,?,?,?,?,?)', ('f'*64, ident, *tuple(row)[2:]))
        config = fixture_decision([ident]); ledger = fixture_ledger(config)
        self.apply(config, ledger=ledger)
        with self.assertRaisesRegex(ValueError, 'retired'): self.wallet.enroll(public)
        old = Wallet(self.root/'old-copy'/'wallet.sqlite', 'https://example.invalid', crypto=lambda *a, **k: None)
        result = erasure.sqlite_case(old.path, config, apply=True, replay=True, ledger_value=ledger, clock=lambda: NOW+1)
        self.assertEqual('LOCAL_DECISION_APPLIED', result['status'])
        with self.assertRaisesRegex(ValueError, 'retired'): old.enroll(public)
        with self.assertRaisesRegex(ValueError, 'retired'): old.record_acceptance(public, None, None, 'f'*64)
        with self.assertRaisesRegex(ValueError, 'retired'): old.require_acceptance('f'*64, public)

    def test_actual_old_backup_replays_erasure_before_returning_a_restored_copy(self):
        from recovery import backup_database, bind_backup, restore
        saved = backup_database(self.path, self.root/'before-erasure')
        binding = self.root/'backup-binding.json'
        anchor = bind_backup(saved, self.wallet.vault.path, hashlib.sha256(self.wallet.vault.key()).hexdigest(), binding)
        ledger = self.root/'erasure-decisions.json'; ledger_sha = policy.write_ledger(ledger, self.ledger)
        self.apply()
        with patch('time.time', return_value=NOW+1):
            restored = restore(saved, self.root/'restored', self.wallet.vault.path, binding=binding,
                binding_sha256=anchor, erasure_ledger=ledger, erasure_ledger_sha256=ledger_sha)
        with closing(sqlite3.connect(restored)) as db:
            self.assertEqual([('c'*64,)], db.execute('SELECT credential FROM profiles').fetchall())
            self.assertEqual([('REVOKED',)], db.execute('SELECT DISTINCT state FROM credentials').fetchall())
            self.assertEqual(1, db.execute('SELECT count(*) FROM erasure_runs').fetchone()[0])
            self.assertEqual(2, db.execute('SELECT count(*) FROM erasure_subjects').fetchone()[0])
        evidence = json.loads((restored.parent/'erasure-replay.json').read_bytes())
        self.assertEqual(ledger_sha, evidence['ledgerSHA256'])
        self.assertEqual('QUARANTINED_REQUIRES_OPERATOR_REVIEW', evidence['status'])

    def test_restore_requires_current_ledger_and_rejects_forgotten_recorded_erasure(self):
        from recovery import backup_database, bind_backup, restore
        self.apply(); saved = backup_database(self.path, self.root/'after-erasure')
        binding = self.root/'backup-binding.json'
        anchor = bind_backup(saved, self.wallet.vault.path, hashlib.sha256(self.wallet.vault.key()).hexdigest(), binding)
        with self.assertRaisesRegex(ValueError, 'erasure ledger'):
            restore(saved, self.root/'no-ledger', self.wallet.vault.path, binding=binding, binding_sha256=anchor)
        self.assertFalse((self.root/'no-ledger').exists())
        ledger = self.root/'incorrect-empty-ledger.json'; ledger_sha = policy.write_ledger(ledger, fixture_ledger())
        with patch('time.time', return_value=NOW+1), self.assertRaisesRegex(ValueError, 'omits recorded'):
            restore(saved, self.root/'stale-ledger', self.wallet.vault.path, binding=binding,
                binding_sha256=anchor, erasure_ledger=ledger, erasure_ledger_sha256=ledger_sha)
        self.assertFalse((self.root/'stale-ledger').exists())

    def test_policy_requires_all_categories_review_dates_and_copy_hold_references(self):
        invalid = []
        for field in ('holdReviewReference', 'copies'):
            value = copy.deepcopy(self.config); del value[field]; invalid.append(value)
        value = copy.deepcopy(self.config); del value['categories']['profiles']; invalid.append(value)
        value = copy.deepcopy(self.config); value['categories']['securityReferences'] = {'action': 'erase', 'reasonReference': 'TEST_REASON_001'}; invalid.append(value)
        value = copy.deepcopy(self.config); value['categories']['sharedJournals']['reviewBy'] = NOW; invalid.append(value)
        value = copy.deepcopy(self.config); value['decidedAt'] = True; invalid.append(value)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError): policy.decision(value, now=NOW+1)

    def test_detached_ledger_digest_duplicates_and_private_permissions(self):
        path = self.root/'decisions.json'; anchor = policy.write_ledger(path, self.ledger)
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        self.assertEqual(policy.ledger(self.ledger), policy.read_ledger(path, anchor, now=NOW+1))
        with self.assertRaises(ValueError): policy.read_ledger(path, '0'*64, now=NOW+1)
        with self.assertRaises(ValueError): policy.ledger(fixture_ledger(self.config, self.config))
        path.chmod(0o644)
        with self.assertRaises(ValueError): policy.read_ledger(path, anchor, now=NOW+1)

    def test_unknown_schema_fails_before_mutation(self):
        with self.wallet.transaction() as db: db.execute('CREATE TABLE unknown_person_data(secret TEXT)')
        before = self.snapshot()
        with self.assertRaises(ValueError): self.plan()
        self.assertEqual(before, self.snapshot())


if __name__ == '__main__': unittest.main()
