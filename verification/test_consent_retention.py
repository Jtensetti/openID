"""Synthetic database retention, including races and rejected destructive paths."""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from consent_retention import policy,sqlite_maintain,read_policy,validate_journal
from enrollment_policy import canonical
from test_enrollment_policy import fixture_policy,NOW
from wallet import Wallet

DAY=86400
POLICY={'version':1,'reference':'SYNTHETIC_RETENTION_001','regime':'private-beta',
    'unboundDays':7,'boundDays':7,'protectedReceipts':[]}


def ident(number):return f'{number:064x}'


class ConsentRetentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.path=self.root/'wallet.sqlite'
        self.wallet=Wallet(self.path,'https://example.invalid',clock=lambda:NOW,crypto=lambda *a,**k:None)
        notice=fixture_policy();notice['notice'].update(notBefore=NOW-90*DAY,notAfter=NOW-DAY)
        self.digest=hashlib.sha256(canonical(notice['notice'])).hexdigest()
        with self.wallet.transaction() as db:
            db.execute('INSERT INTO enrollment_policies VALUES(?,?)',(self.digest,canonical(notice).decode()))
            for number,accepted,withdrawn in [(1,NOW-9*DAY,None),(2,NOW-7*DAY-300,None),
                                             (3,NOW-9*DAY,NOW-DAY),(4,NOW-9*DAY,None),(5,NOW-60,None)]:
                db.execute('INSERT INTO enrollment_consents VALUES(?,?,?,?,?,?)',
                    (ident(number),'a'*64,self.digest,accepted,'SYNTHETIC_PROOF',withdrawn))
            for number,state,created,expires,event in [
                (10,'REVOKED',NOW-40*DAY,NOW-10*DAY,NOW-40*DAY),
                (11,'ACTIVE',NOW-40*DAY,NOW+DAY,NOW-40*DAY),
                (12,'ACTIVE',NOW-40*DAY,NOW-7*DAY,NOW-40*DAY),
                (13,'PENDING_REVIEW',NOW-40*DAY,None,NOW-40*DAY),
                (14,'REVOKED',NOW-40*DAY,NOW-10*DAY,NOW-DAY)]:
                who=ident(number)
                db.execute('INSERT INTO credentials VALUES(?,?,?,?,?,?,?)',
                    (who,'SYNTHETIC_KEY_'+who,state,created,expires,'SYNTHETIC_REVIEW',who))
                db.execute('INSERT INTO enrollment_consents VALUES(?,?,?,?,?,NULL)',
                    (who,who,self.digest,created,'SYNTHETIC_PROOF'))
                db.execute('INSERT INTO credential_consents VALUES(?,?)',(who,who))
                db.execute('INSERT INTO events(credential,kind,time) VALUES(?,?,?)',(who,'SYNTHETIC_EVENT',event))
        self.config=POLICY|{'protectedReceipts':[ident(4)]}

    def rows(self,table):
        with sqlite3.connect(self.path) as db:return db.execute('SELECT * FROM '+table+' ORDER BY 1').fetchall()

    def run_retention(self,**kwargs):return sqlite_maintain(self.path,self.config,clock=lambda:NOW,**kwargs)

    def test_plan_is_read_only_and_protects_current_edge_held_and_recent_withdrawal_or_revocation(self):
        before=self.path.read_bytes();result=self.run_retention()
        self.assertEqual({'credential_consents':2,'enrollment_consents':3,'enrollment_policies':0},result['selected'])
        self.assertEqual(before,self.path.read_bytes());self.assertEqual([],self.rows('consent_retention_runs'))
        self.assertNotIn('SYNTHETIC_PROOF',json.dumps(result))
        for number in (1,4,10):self.assertNotIn(ident(number),json.dumps(result))

    def test_apply_is_bounded_preserves_credentials_events_and_records_exact_policy(self):
        protected={t:self.rows(t) for t in ('credentials','events')}
        first=self.run_retention(apply=True,batch=1)
        self.assertTrue(first['moreEligible']);self.assertEqual(1,first['selected']['enrollment_consents'])
        second=self.run_retention(apply=True)
        self.assertEqual(2,second['selected']['enrollment_consents'])
        self.assertEqual(protected,{t:self.rows(t) for t in protected})
        self.assertEqual({ident(n) for n in (2,3,4,5,11,12,14)},{r[0] for r in self.rows('enrollment_consents')})
        for row in self.rows('consent_retention_runs'):
            validate_journal(row);self.assertEqual(self.config,json.loads(row[2]))

    def test_concurrent_apply_does_not_double_delete_and_second_run_is_restartable(self):
        with ThreadPoolExecutor(2) as pool:results=list(pool.map(lambda _:self.run_retention(apply=True),range(2)))
        self.assertEqual(3,sum(r['selected']['enrollment_consents'] for r in results))
        self.assertEqual(2,len(self.rows('consent_retention_runs')))
        self.assertEqual(0,self.run_retention(apply=True)['selected']['enrollment_consents'])

    def test_journal_failure_or_deadline_rolls_back_the_whole_batch(self):
        before=self.rows('enrollment_consents')
        with patch('consent_retention.time.monotonic',side_effect=[0,11]):
            with self.assertRaises(ValueError):self.run_retention(apply=True)
        self.assertEqual(before,self.rows('enrollment_consents'))
        with self.wallet.transaction() as db:
            db.execute('DROP TABLE consent_retention_runs')
            db.execute('CREATE TABLE consent_retention_runs(id INTEGER PRIMARY KEY CHECK(id<0),time INTEGER,policy TEXT,policy_sha256 TEXT,counts TEXT)')
        with self.assertRaises(sqlite3.IntegrityError):self.run_retention(apply=True)
        self.assertEqual(before,self.rows('enrollment_consents'))

    def test_trigger_and_cascade_cannot_turn_cleanup_into_unbounded_deletion(self):
        before=self.rows('enrollment_consents')
        with self.wallet.transaction() as db:
            db.execute('CREATE TRIGGER unexpected AFTER DELETE ON enrollment_consents BEGIN DELETE FROM credentials; END')
        with self.assertRaisesRegex(ValueError,'trigger'):self.run_retention(apply=True)
        self.assertEqual(before,self.rows('enrollment_consents'))
        with self.wallet.transaction() as db:
            db.execute('DROP TRIGGER unexpected');db.execute('DROP TABLE credential_consents')
            db.execute('CREATE TABLE credential_consents(credential TEXT PRIMARY KEY REFERENCES credentials(id),receipt TEXT UNIQUE REFERENCES enrollment_consents(id) ON DELETE CASCADE)')
        with self.assertRaisesRegex(ValueError,'relationships'):self.run_retention(apply=True)
        self.assertEqual(before,self.rows('enrollment_consents'))

    def test_expired_orphan_policy_is_removed_but_live_policy_and_held_receipt_survive(self):
        with self.wallet.transaction() as db:
            for n,expiry in ((20,NOW-DAY),(21,NOW+DAY)):
                notice=fixture_policy();notice['notice']['notAfter']=expiry
                db.execute('INSERT INTO enrollment_policies VALUES(?,?)',(ident(n),canonical(notice).decode()))
        result=self.run_retention(apply=True)
        self.assertEqual(1,result['selected']['enrollment_policies'])
        self.assertEqual({self.digest,ident(21)},{r[0] for r in self.rows('enrollment_policies')})

    def test_archive_includes_and_validates_retention_evidence(self):
        from audit_archive import export_snapshot,sqlite_snapshot,verify
        self.run_retention(apply=True);target=self.root/'archive'
        result=export_snapshot(sqlite_snapshot(self.path),target,'sqlite','a'*40)
        self.assertEqual('VERIFIED',verify(target,result['manifestSha256'])['state'])
        self.assertEqual(4,json.loads((target/'manifest.json').read_text())['format'])
        self.assertIn('SYNTHETIC_RETENTION_001',(target/'consent_retention_runs.jsonl').read_text())
        row=list(self.rows('consent_retention_runs')[0]);row[3]='0'*64
        with self.assertRaises(ValueError):validate_journal(row)

    def test_policy_is_explicit_and_digg_regime_cannot_shorten_issuance_evidence(self):
        for change in ({'regime':'digg'},{'boundDays':True},{'unboundDays':0},{'reference':''},
                       {'protectedReceipts':['bad']},{'protectedReceipts':[ident(4),ident(4)]},{'extra':1}):
            with self.assertRaises(ValueError):policy(POLICY|change)
        self.assertEqual(1827,policy(POLICY|{'regime':'digg','boundDays':1827})['boundDays'])
        path=self.root/'policy.json';path.write_bytes(canonical(self.config));path.chmod(0o600)
        self.assertEqual(self.config,read_policy(path))
        path.chmod(0o644)
        with self.assertRaises(ValueError):read_policy(path)

    def test_previous_consent_archive_format_remains_readable(self):
        from audit_archive import export_snapshot,sqlite_snapshot,verify
        # This represents the previous schema, not removal during an apply run.
        with self.wallet.transaction() as db:db.execute('DROP TABLE consent_retention_runs')
        target=self.root/'previous-archive'
        result=export_snapshot(sqlite_snapshot(self.path),target,'sqlite','a'*40)
        self.assertEqual(3,json.loads((target/'manifest.json').read_text())['format'])
        self.assertEqual('VERIFIED',verify(target,result['manifestSha256'])['state'])
        with self.assertRaisesRegex(ValueError,'schema'):self.run_retention(apply=True)


if __name__=='__main__':unittest.main()
