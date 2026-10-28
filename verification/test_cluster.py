"""Integration tests require a disposable PostgreSQL database and the pinned bao binary."""
import base64
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

from test_wallet import crypt
from test_identity import document
from wallet import Wallet

DSN = os.environ.get('OPENID_TEST_POSTGRES')

@unittest.skipUnless(DSN, 'requires disposable PostgreSQL')
class ClusterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg.conninfo import conninfo_to_dict, make_conninfo
        cls.psycopg = psycopg
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = Path(cls.tmp.name)
        cls.token = secrets.token_hex(32)
        cls.address = 'http://127.0.0.1:18200'
        cls.log = open(cls.root/'bao.log', 'wb')
        cls.bao = subprocess.Popen([os.environ['OPENID_TEST_BAO'], 'server', '-dev',
            '-dev-listen-address=127.0.0.1:18200', '-dev-root-token-id='+cls.token], stdout=cls.log, stderr=cls.log)
        cls.addClassCleanup(cls.stop_bao)
        for _ in range(100):
            try:
                cls.bao_request('sys/mounts/transit', {'type':'transit'}); break
            except OSError: time.sleep(.1)
        else: raise AssertionError('OpenBao did not start')
        cls.bao_request('transit/keys/openid-profile', {'type':'aes256-gcm96', 'derived':True, 'exportable':False})
        cls.bao_request('transit/keys/openid-profile/config', {'auto_rotate_period':'720h'})
        cls.bao_request('transit/keys/openid-index', {'type':'hmac', 'key_size':32, 'exportable':False})
        cls.token_files = {}
        for role in ('enroller','wallet','maintenance'):
            policy=(Path(__file__).parents[1]/'deployment/cluster'/(role+'.hcl')).read_text()
            cls.bao_request('sys/policies/acl/'+role, {'policy':policy})
            response=cls.bao_request('auth/token/create', {'policies':[role], 'no_default_policy':True, 'ttl':'1h'})
            path=cls.root/(role+'.token'); path.write_text(response['auth']['client_token']); path.chmod(0o600)
            cls.token_files[role]=path
        cls.dsns={}
        with psycopg.connect(DSN, autocommit=True) as db:
            db.execute((Path(__file__).parents[1]/'deployment/cluster/schema.sql').read_text(), prepare=False)
            db.execute((Path(__file__).parents[1]/'deployment/cluster/archive-access.sql').read_text(), prepare=False)
            for user, roles in {'enroller':['enroller'], 'wallet':['wallet'], 'alice':['requester'],
                'bob':['approver'], 'carol':['requester','approver'], 'revoker':['revoker'],
                'maintenance':['maintenance'], 'auditor':['auditor'], 'backup':['backup']}.items():
                password=secrets.token_urlsafe(32)
                from psycopg import sql
                db.execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {}').format(sql.Identifier('test_'+user),sql.Literal(password)))
                for role in roles:
                    db.execute(sql.SQL('GRANT {} TO {}').format(sql.Identifier('openid_'+role),sql.Identifier('test_'+user)))
                cls.dsns[user]=make_conninfo(**(conninfo_to_dict(DSN)|{'user':'test_'+user,'password':password}))
        cls.keys=[json.loads(crypt(op='new')) for _ in range(20)]

    @classmethod
    def stop_bao(cls):
        cls.bao.terminate()
        try: cls.bao.wait(timeout=5)
        except subprocess.TimeoutExpired: cls.bao.kill(); cls.bao.wait()
        cls.log.close()

    @classmethod
    def bao_request(cls, path, data):
        req=urllib.request.Request(cls.address+'/v1/'+path, data=json.dumps(data).encode(),
            headers={'X-Vault-Token':cls.token, 'Content-Type':'application/json'})
        with urllib.request.urlopen(req, timeout=3) as r:
            body=r.read()
            return json.loads(body) if body else {}

    def setUp(self):
        with self.psycopg.connect(DSN, autocommit=True) as db:
            db.execute('TRUNCATE openid.credentials,openid.persons,openid.operator_events,openid.maintenance_runs,openid.biometric_attempts,openid.enrollment_quarantine,openid.enrollment_policies,openid.consent_retention_runs RESTART IDENTITY CASCADE')
        self.enroller=self.store('enroller')
        self.a=self.store('wallet'); self.b=self.store('wallet')
        self.ident=self.enroller.enroll(self.keys[0]['publicKey'], document())['id']

    def store(self, role, origin='https://localhost:8765'):
        from postgres import PostgresWallet
        from transit import TransitVault
        store=PostgresWallet(self.dsns[role],origin,TransitVault(self.address,self.token_files[role],local_test=True),local_test=True)
        self.addCleanup(store.close)
        return store

    def sql(self, role, query, args=()):
        with self.psycopg.connect(self.dsns[role], options='-c search_path=openid,pg_catalog') as db:
            result=db.execute(query,args)
            return result.fetchall() if result.description else None

    def activate(self, ident=None):
        proposal=self.sql('alice','SELECT request_activation(%s,%s,%s)',(ident or self.ident,'REVIEW-test-001',24))[0][0]
        self.sql('bob','SELECT approve_activation(%s)',(proposal,))
        return proposal

    def signed(self, action='snapshot', req=None, key=0, store=None):
        ident=hashlib.sha256(base64.b64decode(self.keys[key]['publicKey'])).hexdigest()
        c=(store or self.a).challenge({'credentialId':ident,'action':action,'requestId':req})
        return {'challengeId':c['id'],'signature':crypt(op='sign',key=self.keys[key]['privateKey'],payload=c['signingInput'])}

    def test_two_roles_and_activation_replay(self):
        proposal=self.activate()
        self.assertEqual('ACTIVE',self.b.execute(self.signed())['state'])
        with self.assertRaises(self.psycopg.Error):self.sql('bob','SELECT approve_activation(%s)',(proposal,))
        self.assertEqual(2,len(self.sql('auditor','SELECT * FROM operator_events')))

    def test_unchecked_or_expired_passport_does_not_enter_shared_registry(self):
        for doc in (replace(document(),revocation='NOT_CHECKED',revocation_valid_until=0),
                    replace(document(),revocation_valid_until=int(time.time())-1)):
            with self.subTest(status=doc.revocation):
                with self.assertRaises(ValueError):self.enroller.enroll(self.keys[1]['publicKey'],doc)
                with self.assertRaises(ValueError):self.enroller.biometric_attempt(doc)
        with self.psycopg.connect(DSN) as db:
            self.assertEqual(1,db.execute('SELECT count(*) FROM openid.credentials').fetchone()[0])
            self.assertEqual(0,db.execute('SELECT count(*) FROM openid.biometric_attempts').fetchone()[0])

    def test_biometric_budget_is_atomic_across_replicas_and_cannot_be_reset_by_services(self):
        from wallet import BiometricAttemptLimit
        second=self.store('enroller')
        def attempt(i):
            try:return (self.enroller if i%2 else second).biometric_attempt(document())
            except BiometricAttemptLimit:return None
        with ThreadPoolExecutor(max_workers=12) as pool:
            results=list(pool.map(attempt,range(24)))
        self.assertEqual(list(range(5)),sorted(r for r in results if r is not None))
        self.enroller.close();self.enroller=self.store('enroller')
        with self.assertRaises(BiometricAttemptLimit):self.enroller.biometric_attempt(document())
        self.assertEqual(4,self.enroller.biometric_attempt(document(documentNumber='TEST00009')))
        for role in self.dsns:
            with self.subTest(role=role),self.assertRaises(self.psycopg.Error):
                self.sql(role,'DELETE FROM biometric_attempts')
        with self.psycopg.connect(DSN) as db:
            db.execute('UPDATE openid.biometric_attempts SET times=ARRAY[%s::bigint]',(int(time.time())-86401,))
        self.assertEqual(4,self.enroller.biometric_attempt(document()))

    def test_short_audit_retention_is_refused_even_when_bypassing_the_cli(self):
        from maintenance import maintain
        maintenance=self.store('maintenance')
        for days in (0,1,30,1826):
            with self.subTest(days=days),self.assertRaises(ValueError):
                maintain(maintenance,profile_days=7,event_days=days)
            with self.assertRaises(self.psycopg.Error):
                self.sql('maintenance','SELECT purge_expired(7,%s,100)',(days,))
        self.activate()
        self.sql('maintenance','SELECT purge_expired(7,1827,100)')
        self.assertEqual(1,len(self.sql('auditor','SELECT * FROM activation_proposals')))

    def test_schema_one_migration_preserves_enrollment_and_enforces_new_boundaries(self):
        from postgres import PostgresWallet,RegistryUnavailable
        from psycopg.conninfo import conninfo_to_dict,make_conninfo
        target=self.restore_target()
        from psycopg import sql
        with self.psycopg.connect(DSN,autocommit=True) as admin:
            admin.execute(sql.SQL('CREATE DATABASE {} TEMPLATE template0').format(sql.Identifier(target)))
        admin_dsn=make_conninfo(**(conninfo_to_dict(DSN)|{'dbname':target}))
        def dsn(role):return make_conninfo(**(conninfo_to_dict(self.dsns[role])|{'dbname':target}))
        with self.psycopg.connect(admin_dsn,autocommit=True) as db:
            # This fixture is the exact version-1 schema from c91102b, not generated from version 2.
            db.execute((Path(__file__).parent/'fixtures/schema-v1.sql').read_text(),prepare=False)
            with self.psycopg.connect(DSN) as source:
                for table in ('credentials','persons','profiles'):
                    rows=source.execute('SELECT * FROM openid.'+table).fetchall()
                    for row in rows:
                        db.execute('INSERT INTO openid.'+table+' VALUES('+','.join(['%s']*len(row))+')',row)
            with self.assertRaises(RegistryUnavailable):
                PostgresWallet(dsn('enroller'),self.a.origin,self.enroller.vault,local_test=True)
            migration=(Path(__file__).parents[1]/'deployment/cluster/migrate-1-to-2.sql').read_text()
            db.execute(migration,prepare=False)
            self.assertEqual([(2,)],db.execute('SELECT version FROM openid.schema_version').fetchall())
            with self.assertRaises(self.psycopg.Error):db.execute(migration,prepare=False)
            db.execute('ROLLBACK')
            self.assertEqual([(2,)],db.execute('SELECT version FROM openid.schema_version').fetchall())
        with self.psycopg.connect(admin_dsn,autocommit=True) as db:
            migration3=(Path(__file__).parents[1]/'deployment/cluster/migrate-2-to-3.sql').read_text()
            db.execute(migration3,prepare=False)
            self.assertEqual([(3,)],db.execute('SELECT version FROM openid.schema_version').fetchall())
            with self.assertRaises(self.psycopg.Error):db.execute(migration3,prepare=False)
            db.execute('ROLLBACK')
        with self.psycopg.connect(admin_dsn,autocommit=True) as db:
            migration4=(Path(__file__).parents[1]/'deployment/cluster/migrate-3-to-4.sql').read_text()
            db.execute(migration4,prepare=False)
            self.assertEqual([(4,)],db.execute('SELECT version FROM openid.schema_version').fetchall())
            with self.assertRaises(self.psycopg.Error):db.execute(migration4,prepare=False)
            db.execute('ROLLBACK')
        migrated=PostgresWallet(dsn('enroller'),self.a.origin,self.enroller.vault,local_test=True)
        self.addCleanup(migrated.close)
        self.assertEqual(4,migrated.biometric_attempt(document()))
        with migrated.transaction() as db:
            self.assertEqual(self.ident,db.execute('SELECT credential FROM profiles').fetchone()[0])
            self.assertEqual('PENDING_REVIEW',db.execute('SELECT state FROM credentials').fetchone()[0])
        with self.psycopg.connect(dsn('revoker')) as revoker:revoker.execute('SELECT openid.revoke_all_after_restore()')
        from wallet import EnrollmentQuarantine
        for operation in (migrated.enrollment_available,lambda:migrated.biometric_attempt(document()),
                          lambda:migrated.enroll(self.keys[2]['publicKey'],document())):
            with self.assertRaises(EnrollmentQuarantine):operation()

    def test_private_audit_archive_uses_read_only_role_and_a_single_snapshot(self):
        from audit_archive import export_snapshot,postgres_snapshot,verify,write_table
        from unittest.mock import patch
        import audit_archive
        self.activate()
        target=self.root/('audit-'+secrets.token_hex(8))
        with self.psycopg.connect(DSN) as admin:
            admin.execute("ALTER ROLE test_auditor SET timezone='Europe/Stockholm'")
        def reset_timezone():
            with self.psycopg.connect(DSN) as admin:admin.execute('ALTER ROLE test_auditor RESET timezone')
        self.addCleanup(reset_timezone)
        def revoke_after_credentials(*args):
            result=write_table(*args)
            if args[2]=='credentials':self.sql('revoker','SELECT revoke_credential(%s)',(self.ident,))
            return result
        with patch.object(audit_archive,'write_table',side_effect=revoke_after_credentials):
            receipt=export_snapshot(postgres_snapshot(self.dsns['auditor'],local_test=True),target,'postgresql','a'*40)
        self.assertEqual('VERIFIED',verify(target,receipt['manifestSha256'])['state'])
        self.assertIn('ACTIVE',(target/'credentials.jsonl').read_text())
        self.assertNotIn('REVOKED',(target/'events.jsonl').read_text())
        self.assertNotIn('REVOKED',(target/'operator_events.jsonl').read_text())
        self.assertEqual('REVOKED',self.b.execute(self.signed())['state'])
        self.assertEqual(1,len((target/'activation_proposals.jsonl').read_text().splitlines()))
        for query in ('SELECT sealed FROM profiles','SELECT person FROM profiles','SELECT subject FROM credentials',
                      'SELECT hash FROM security_codes','SELECT secret_hash FROM federation_requests',
                      'DELETE FROM events','UPDATE credentials SET state=state','SELECT reserve_biometric_attempt(\'forged\')'):
            with self.subTest(query=query),self.assertRaises(self.psycopg.Error):self.sql('auditor',query)

    def enrollment_receipt(self, key=2):
        from enrollment_policy import EnrollmentPolicy
        from test_enrollment_policy import fixture_policy
        data=fixture_policy();now=int(time.time())
        data['notice'].update(notBefore=now-60,notAfter=now+600)
        policy=EnrollmentPolicy(data);receipt=secrets.token_hex(32)
        payload={'id':'a'*43,'nonce':'b'*43,'receipt':receipt,'devicePublicKey':self.keys[key]['publicKey'],
            'acceptance':{'policyDigest':policy.digest,'termsAccepted':True,'biometricsAccepted':True}}
        proof={'payload':base64.b64encode(json.dumps(payload).encode()).decode(),
            'assertion':'synthetic-assertion-already-checked-by-native','appPublicKey':'synthetic-app-key'}
        self.enroller.record_acceptance(self.keys[key]['publicKey'],policy,proof,receipt)
        data={'action':'withdraw-enrollment-consent','origin':self.enroller.origin,'receipt':receipt}
        raw=base64.b64encode(json.dumps(data).encode()).decode()
        request={'publicKey':self.keys[key]['publicKey'],'payload':raw,
            'signature':crypt(op='sign',key=self.keys[key]['privateKey'],payload=raw)}
        return receipt,request

    def test_consent_is_key_bound_withdrawal_is_permanent_and_roles_cannot_rewrite_evidence(self):
        receipt,request=self.enrollment_receipt()
        self.enroller.require_acceptance(receipt,self.keys[2]['publicKey'])
        for role in ('enroller','wallet','auditor','maintenance'):
            for query in ("UPDATE enrollment_consents SET proof='forged'",'DELETE FROM enrollment_consents',
                          "UPDATE enrollment_policies SET record='{}'",'DELETE FROM credential_consents'):
                with self.subTest(role=role,query=query),self.assertRaises(self.psycopg.Error):self.sql(role,query)
        self.enroller.withdraw_acceptance(request);self.enroller.withdraw_acceptance(request)
        with self.assertRaises(ValueError):self.enroller.enroll(self.keys[2]['publicKey'],document(),acceptance_receipt=receipt)
        with self.assertRaises(self.psycopg.Error):self.sql('enroller','UPDATE enrollment_consents SET withdrawn=NULL')
        self.assertEqual([],self.sql('enroller','SELECT * FROM credential_consents'))

    def test_concurrent_consent_binding_and_backup_restore_preserve_evidence(self):
        from cluster_recovery import backup,restore
        from postgres import PostgresWallet
        from psycopg.conninfo import conninfo_to_dict,make_conninfo
        from wallet import EnrollmentQuarantine
        receipt,request=self.enrollment_receipt()
        other=self.store('enroller')
        def enroll(store):
            try:return store.enroll(self.keys[2]['publicKey'],document(),acceptance_receipt=receipt)['id']
            except Exception as error:
                from postgres import RegistryUnavailable
                if not isinstance(error,(ValueError,RegistryUnavailable)):raise
                return None
        with ThreadPoolExecutor(2) as pool:results=list(pool.map(enroll,(self.enroller,other)))
        self.assertEqual(1,sum(result is not None for result in results))
        pending,pending_request=self.enrollment_receipt(key=3)
        self.enroller.withdraw_acceptance(request)
        from consent_retention import postgres_maintain,validate_journal
        from test_consent_retention import POLICY
        postgres_maintain(self.dsns['maintenance'],POLICY,apply=True,local_test=True)
        destination=self.root/('consent-backup-'+secrets.token_hex(8))
        backup(self.dsns['backup'],destination,local_test=True)
        metadata=json.loads((destination/'manifest.json').read_text())
        self.assertEqual(2,metadata['tables']['enrollment_consents']['rows'])
        self.assertEqual(1,metadata['tables']['credential_consents']['rows'])
        self.assertEqual(1,metadata['tables']['consent_retention_runs']['rows'])
        target=self.restore_target();restore(DSN,destination,target,self.a.vault,local_test=True)
        with self.psycopg.connect(DSN) as admin:
            self.assertFalse(admin.execute('SELECT datallowconn FROM pg_database WHERE datname=%s',(target,)).fetchone()[0])
        admin_dsn=self.restored_database(target,grant=True)
        with self.psycopg.connect(admin_dsn) as admin:
            rows=admin.execute('SELECT * FROM openid.consent_retention_runs').fetchall()
            self.assertEqual(1,len(rows));validate_journal(rows[0])
        restored=PostgresWallet(make_conninfo(**(conninfo_to_dict(self.dsns['enroller'])|{'dbname':target})),
            self.enroller.origin,self.enroller.vault,local_test=True);self.addCleanup(restored.close)
        with restored.transaction() as db:
            self.assertIsNotNone(db.execute('SELECT withdrawn FROM enrollment_consents WHERE id=?',(receipt,)).fetchone()[0])
        with self.assertRaises(EnrollmentQuarantine):restored.require_acceptance(pending,self.keys[3]['publicKey'])

    def test_same_login_cannot_approve_even_with_both_roles(self):
        proposal=self.sql('carol','SELECT request_activation(%s,%s,%s)',(self.ident,'REVIEW-test-002',24))[0][0]
        with self.assertRaises(self.psycopg.Error):self.sql('carol','SELECT approve_activation(%s)',(proposal,))

    def consent_retention_fixture(self):
        from enrollment_policy import canonical
        from test_enrollment_policy import fixture_policy
        from test_consent_retention import POLICY,ident,DAY
        now=int(time.time());notice=fixture_policy()
        notice['notice'].update(notBefore=now-90*DAY,notAfter=now-DAY)
        digest=hashlib.sha256(canonical(notice['notice'])).hexdigest()
        with self.psycopg.connect(DSN) as db:
            # Only the disposable fixture's owner may simulate elapsed history.
            # The INSERT guard still requires a freshly pending credential.
            db.execute('SET LOCAL ROLE openid_owner')
            db.execute('INSERT INTO openid.enrollment_policies VALUES(%s,%s)',(digest,canonical(notice).decode()))
            for number,accepted,withdrawn in ((1,now-9*DAY,None),(2,now-6*DAY,None),
                    (3,now-9*DAY,now-DAY),(4,now-9*DAY,None),(5,now-60,None)):
                db.execute('INSERT INTO openid.enrollment_consents VALUES(%s,%s,%s,%s,%s,%s)',
                    (ident(number),'a'*64,digest,accepted,'SYNTHETIC_PROOF',withdrawn))
            for number,state,expiry,event in ((10,'REVOKED',now-10*DAY,now-40*DAY),
                    (11,'ACTIVE',now+DAY,now-40*DAY),(12,'ACTIVE',now-6*DAY,now-40*DAY),
                    (13,'PENDING_REVIEW',None,now-40*DAY),(14,'REVOKED',now-10*DAY,now-DAY)):
                who=ident(number)
                db.execute('INSERT INTO openid.credentials VALUES(%s,%s,%s,%s,%s,%s,%s)',
                    (who,'SYNTHETIC_KEY_'+who,'PENDING_REVIEW',now,None,None,who))
                db.execute('UPDATE openid.credentials SET state=%s,created=%s,expires=%s,decision=%s WHERE id=%s',
                    (state,now-40*DAY,expiry,'SYNTHETIC_REVIEW',who))
                db.execute('INSERT INTO openid.enrollment_consents VALUES(%s,%s,%s,%s,%s,NULL)',
                    (who,who,digest,now-40*DAY,'SYNTHETIC_PROOF'))
                db.execute('INSERT INTO openid.credential_consents VALUES(%s,%s)',(who,who))
                db.execute('INSERT INTO openid.events(credential,kind,time) VALUES(%s,%s,%s)',(who,'SYNTHETIC_EVENT',event))
            for expiry in (now-DAY,now+DAY):
                orphan=fixture_policy();orphan['notice']['notAfter']=expiry
                orphan_digest=hashlib.sha256(canonical(orphan['notice'])).hexdigest()
                db.execute('INSERT INTO openid.enrollment_policies VALUES(%s,%s)',(orphan_digest,canonical(orphan).decode()))
        return POLICY|{'protectedReceipts':[ident(4)]}

    def test_consent_retention_plan_apply_roles_and_exact_journal(self):
        from consent_retention import postgres_maintain,validate_journal
        from enrollment_policy import canonical
        from test_consent_retention import ident
        config=self.consent_retention_fixture()
        def run(**kw):return postgres_maintain(self.dsns['maintenance'],config,local_test=True,**kw)
        protected={t:self.sql('backup','SELECT * FROM '+t+' ORDER BY 1') for t in ('credentials','events','profiles')}
        expected={'credential_consents':2,'enrollment_consents':3,'enrollment_policies':1}
        self.assertEqual(expected,run()['selected'])
        self.assertEqual([],self.sql('maintenance','SELECT * FROM consent_retention_runs'))
        self.assertEqual(10,len(self.sql('backup','SELECT id FROM enrollment_consents')))
        for query in ('SELECT proof FROM enrollment_consents','DELETE FROM credential_consents',
                      'DELETE FROM consent_retention_runs',"UPDATE consent_retention_runs SET policy='{}'"):
            with self.subTest(query=query),self.assertRaises(self.psycopg.Error):self.sql('maintenance',query)
        first=run(apply=True,batch=1);self.assertTrue(first['moreEligible'])
        self.assertEqual(1,first['selected']['enrollment_consents'])
        second=run(apply=True);self.assertEqual(2,second['selected']['enrollment_consents'])
        self.assertEqual({ident(n) for n in (2,3,4,5,11,12,14)},
            {r[0] for r in self.sql('backup','SELECT id FROM enrollment_consents')})
        self.assertEqual(protected,{t:self.sql('backup','SELECT * FROM '+t+' ORDER BY 1') for t in protected})
        for row in self.sql('maintenance','SELECT * FROM consent_retention_runs ORDER BY id'):
            validate_journal(row);self.assertEqual(canonical(config).decode(),row[2])
        self.assertEqual(0,run(apply=True)['selected']['enrollment_consents'])
        self.assertEqual(2,len(self.sql('backup','SELECT * FROM enrollment_policies')))

    def test_consent_retention_database_rejects_invalid_policy_and_rolls_back_journal_failure(self):
        from consent_retention import postgres_maintain
        from enrollment_policy import canonical
        config=self.consent_retention_fixture()
        invalid=[config|{'regime':'digg'},config|{'regime':None},config|{'boundDays':True},
            config|{'protectedReceipts':[None]},config|{'protectedReceipts':config['protectedReceipts']*2},
            config|{'extra':1}]
        for value in invalid:
            with self.subTest(value=value),self.assertRaises(self.psycopg.Error):
                self.sql('maintenance','SELECT retain_consent_evidence(%s,true,100)',(canonical(value).decode(),))
        for raw in (json.dumps(config),canonical(config).decode().replace('"version":1','"version":1,"version":1')):
            with self.assertRaises(self.psycopg.Error):
                self.sql('maintenance','SELECT retain_consent_evidence(%s,true,100)',(raw,))
        before=self.sql('backup','SELECT * FROM enrollment_consents ORDER BY id')
        with self.psycopg.connect(DSN) as db:
            db.execute('ALTER TABLE openid.consent_retention_runs ADD CONSTRAINT synthetic_journal_failure CHECK(id<0)')
        try:
            with self.assertRaises(self.psycopg.Error):
                postgres_maintain(self.dsns['maintenance'],config,apply=True,local_test=True)
        finally:
            with self.psycopg.connect(DSN) as db:
                db.execute('ALTER TABLE openid.consent_retention_runs DROP CONSTRAINT synthetic_journal_failure')
        self.assertEqual(before,self.sql('backup','SELECT * FROM enrollment_consents ORDER BY id'))
        self.assertEqual([],self.sql('maintenance','SELECT * FROM consent_retention_runs'))

    def test_consent_retention_concurrent_batches_do_not_double_delete(self):
        from consent_retention import postgres_maintain
        config=self.consent_retention_fixture()
        with ThreadPoolExecutor(2) as pool:
            results=list(pool.map(lambda _:postgres_maintain(self.dsns['maintenance'],config,apply=True,local_test=True),range(2)))
        self.assertEqual(3,sum(r['selected']['enrollment_consents'] for r in results))
        self.assertEqual(2,len(self.sql('maintenance','SELECT * FROM consent_retention_runs')))

    def test_consent_retention_rechecks_a_revocation_committed_while_waiting(self):
        from consent_retention import postgres_maintain
        from test_consent_retention import ident
        config=self.consent_retention_fixture()
        with self.psycopg.connect(DSN) as revocation,ThreadPoolExecutor(1) as pool:
            revocation.execute('SELECT id FROM openid.credentials WHERE id=%s FOR UPDATE',(ident(10),))
            blocker=revocation.info.backend_pid
            future=pool.submit(postgres_maintain,self.dsns['maintenance'],config,apply=True,local_test=True)
            try:
                end=time.monotonic()+2
                with self.psycopg.connect(DSN,autocommit=True) as observer:
                    while time.monotonic()<end:
                        if observer.execute('SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE %s=ANY(pg_blocking_pids(pid)))',(blocker,)).fetchone()[0]:break
                        time.sleep(.02)
                    else:self.fail('retention did not lock the credential against concurrent revocation')
                revocation.execute('INSERT INTO openid.events(credential,kind,time) VALUES(%s,%s,%s)',
                    (ident(10),'REVOKED',int(time.time())))
            finally:revocation.commit()
            self.assertEqual(2,future.result(timeout=5)['selected']['enrollment_consents'])
        self.assertEqual([(ident(10),)],self.sql('backup','SELECT id FROM enrollment_consents WHERE id=%s',(ident(10),)))

    def test_service_and_auditor_cannot_activate_or_modify_profile(self):
        queries=[("UPDATE credentials SET state='ACTIVE' WHERE id=%s",(self.ident,)),
            ('SELECT request_activation(%s,%s,%s)',(self.ident,'REVIEW-forged-01',24)),
            ("UPDATE profiles SET sealed='{}' WHERE credential=%s",(self.ident,)),
            ('DELETE FROM operator_events',())]
        for role in ('enroller','wallet','auditor','maintenance'):
            for query,args in queries:
                if role=='maintenance' and query.startswith('UPDATE profiles'):continue
                with self.subTest(role=role,query=query),self.assertRaises(self.psycopg.Error):self.sql(role,query,args)
        with self.assertRaises(ValueError):self.a.activate(self.ident,'REVIEW-forged-02')

    def test_function_privileges_match_actual_roles(self):
        allowed={'request_activation(text,text,integer)':{'alice','carol'},'approve_activation(text)':{'bob','carol'},
            'revoke_credential(text)':{'revoker'},'revoke_all_after_restore()':{'revoker'},
            'purge_expired(integer,integer,integer)':{'maintenance'},
            'retain_consent_evidence(text,boolean,integer)':{'maintenance'},
            'reserve_biometric_attempt(text)':{'enroller'},'security_code_status(text)':{'wallet'},
            'check_security_code(text,text)':{'wallet'},'set_security_code(text,text,text)':{'wallet'}}
        for function,users in allowed.items():
            for role in self.dsns:
                with self.subTest(function=function,role=role):
                    self.assertEqual(role in users,self.sql(role,'SELECT has_function_privilege(current_user,%s,%s)',
                        ('openid.'+function,'EXECUTE'))[0][0])

    def test_signed_text_code_level_and_federation_binding_are_shared_and_immutable(self):
        from wallet import SecurityCodeError
        self.activate()
        with self.assertRaises(SecurityCodeError) as weak:
            self.a.execute(self.signed('set-pin')|{'newPin':'123456'})
        self.assertEqual('PIN_WEAK',weak.exception.code)
        self.a.execute(self.signed('set-pin')|{'newPin':'482917'})
        r=self.a.federation_start('_shared_signing','https://rp.example.test','SYNTHETIC document 42','pin')
        inspected=self.b.execute(self.signed('inspect',r['id'],store=self.b))['requests'][0]
        self.assertEqual(('SYNTHETIC document 42','pin'),(inspected['signMessage'],inspected['verification']))
        with self.assertRaises(ValueError):self.a.challenge({'credentialId':self.ident,'action':'approve','requestId':r['id']})
        for field,value in (('sign_message','different text'),('level',None),('binding','other'),('audience','https://other.invalid')):
            with self.subTest(field=field),self.assertRaises(self.psycopg.Error):
                self.sql('wallet','UPDATE federation_requests SET '+field+'=%s WHERE id=%s',(value,r['id']))
        with self.assertRaises(SecurityCodeError) as wrong:
            self.b.execute(self.signed('sign',r['id'],store=self.b)|{'pin':'482918'})
        self.assertEqual(('PIN_INCORRECT',4),(wrong.exception.code,wrong.exception.remaining))
        self.a.execute(self.signed('sign',r['id'])|{'pin':'482917'})
        result=self.b.federation_result('consume',r['id'],r['secret'],'_shared_signing','https://rp.example.test')
        self.assertEqual('pin',result['verification'])
        self.assertEqual(hashlib.sha256(b'SYNTHETIC document 42').hexdigest(),result['signMessageSha256'])
        with self.assertRaises(ValueError):self.a.federation_result('consume',r['id'],r['secret'],'_shared_signing','https://rp.example.test')

    def test_parallel_wrong_codes_lock_once_and_service_role_cannot_read_or_reset_verifiers(self):
        from wallet import SecurityCodeError
        self.activate();self.a.execute(self.signed('set-pin')|{'newPin':'482917'})
        r=self.a.federation_start('_pin_lock','https://rp.example.test',level='pin')
        attempts=[self.signed('approve',r['id'])|{'pin':'482918'} for _ in range(10)]
        def wrong(attempt):
            try:self.b.execute(attempt);return 'unexpected approval'
            except SecurityCodeError as e:return e.code
        with ThreadPoolExecutor(max_workers=6) as pool:results=list(pool.map(wrong,attempts))
        self.assertEqual(4,results.count('PIN_INCORRECT'));self.assertEqual(6,results.count('PIN_LOCKED'))
        self.a.close();self.a=self.store('wallet')
        with self.assertRaises(SecurityCodeError) as locked:
            self.a.execute(self.signed('set-pin')|{'pin':'482917','newPin':'739154'})
        self.assertEqual('PIN_LOCKED',locked.exception.code)
        for role in ('wallet','enroller','maintenance','auditor'):
            for statement in ('SELECT hash FROM security_codes','UPDATE security_codes SET failures=0,locked=0','DELETE FROM security_codes'):
                with self.subTest(role=role,statement=statement),self.assertRaises(self.psycopg.Error):self.sql(role,statement)
        self.assertEqual(0,self.a.execute(self.signed())['securityCode']['attemptsRemaining'])

    def test_database_tls_rejects_wrong_ca_and_hostname(self):
        import socket
        from psycopg.conninfo import conninfo_to_dict,make_conninfo
        from postgres import PostgresWallet,RegistryUnavailable
        configured=conninfo_to_dict(self.dsns['wallet'])
        if configured.get('sslmode')!='verify-full':self.skipTest('requires TLS-enabled database')
        with self.a.transaction() as db:
            self.assertTrue(db.execute('SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()').fetchone()[0])
        for change in ({'sslrootcert':str(self.root/'missing-ca')},
                       {'host':'wrong-name.invalid','hostaddr':socket.gethostbyname(configured['host'])}):
            with self.assertRaises(RegistryUnavailable):
                PostgresWallet(make_conninfo(**(configured|change)),self.a.origin,self.a.vault)

    def test_service_and_operator_logins_cannot_assume_or_grant_owner(self):
        for role in self.dsns:
            with self.subTest(role=role):
                for statement in ('SET ROLE openid_owner',
                                  'GRANT openid_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE'):
                    with self.assertRaises(self.psycopg.errors.InsufficientPrivilege):
                        self.sql(role,statement)

    def test_operator_temp_tables_cannot_shadow_privileged_registry_access(self):
        with self.psycopg.connect(self.dsns['alice'],options='-c search_path=openid,pg_catalog') as db:
            for name in ('credentials','profiles','activation_proposals','operator_events'):
                db.execute('CREATE TEMP TABLE '+name+'(id text)')
                db.execute('GRANT ALL ON pg_temp.'+name+' TO openid_owner')
            proposal=db.execute('SELECT openid.request_activation(%s,%s,%s)',(self.ident,'REVIEW-temp-shadow',24)).fetchone()[0]
        with self.psycopg.connect(self.dsns['bob'],options='-c search_path=openid,pg_catalog') as db:
            for name in ('credentials','profiles','persons','activation_proposals','operator_events','events'):
                db.execute('CREATE TEMP TABLE '+name+'(id text)')
                db.execute('GRANT ALL ON pg_temp.'+name+' TO openid_owner')
            db.execute('SELECT openid.approve_activation(%s)',(proposal,))
        self.assertEqual('ACTIVE',self.b.execute(self.signed())['state'])

    def test_no_unverified_profile_or_expired_proposal(self):
        ident=self.enroller.enroll(self.keys[1]['publicKey'])['id']
        with self.assertRaises(self.psycopg.Error):self.sql('alice','SELECT request_activation(%s,%s,%s)',(ident,'REVIEW-no-pass',24))
        proposal=self.sql('alice','SELECT request_activation(%s,%s,%s)',(self.ident,'REVIEW-expired',24))[0][0]
        with self.psycopg.connect(DSN) as db:db.execute('UPDATE openid.activation_proposals SET expires=0')
        with self.assertRaises(self.psycopg.Error):self.sql('bob','SELECT approve_activation(%s)',(proposal,))

    def test_cross_instance_challenge_and_one_winner(self):
        self.activate(); signed=self.signed()
        def attempt(_):
            try:return self.b.execute(signed)['state']=='ACTIVE'
            except ValueError:return False
        with ThreadPoolExecutor(max_workers=12) as pool:self.assertEqual(1,sum(pool.map(attempt,range(24))))

    def test_wrong_signature_consumes_challenge_across_instances(self):
        signed=self.signed(); wrong=dict(signed,signature=base64.b64encode(b'wrong').decode())
        with self.assertRaises(ValueError):self.b.execute(wrong)
        with self.assertRaises(ValueError):self.a.execute(signed)

    def test_challenge_survives_restart_and_rejects_other_origin(self):
        signed=self.signed(); self.a.close(); self.a=self.store('wallet')
        self.assertEqual('PENDING_REVIEW',self.a.execute(signed)['state'])
        other=self.store('wallet','https://other.invalid:8765'); signed=self.signed()
        with self.assertRaises(ValueError):other.execute(signed)
        with self.assertRaises(ValueError):self.a.execute(signed)

    def test_single_consumption_and_revocation_after_approval(self):
        self.activate(); r=self.a.start_request(self.ident); self.b.execute(self.signed('approve',r['id']))
        def attempt(_):
            try:return self.b.consume_result(r['id'],r['secret'])['state']=='AUTHENTICATED'
            except ValueError:return False
        with ThreadPoolExecutor(max_workers=12) as pool:self.assertEqual(1,sum(pool.map(attempt,range(24))))
        r=self.a.start_request(self.ident); self.b.execute(self.signed('approve',r['id']))
        self.sql('revoker','SELECT revoke_credential(%s)',(self.ident,))
        with self.assertRaises(ValueError):self.a.consume_result(r['id'],r['secret'])
        with self.assertRaises(self.psycopg.Error):self.sql('alice','SELECT request_activation(%s,%s,%s)',(self.ident,'REVIEW-revive',24))

    def test_replacement_stable_subject_and_revocation(self):
        self.activate()
        with self.a.transaction() as db:
            person=db.execute('SELECT person FROM profiles WHERE credential=?',(self.ident,)).fetchone()[0]
            subject=self.a.federation_subject(db,'https://sp.invalid',person)
        ident=self.enroller.enroll(self.keys[1]['publicKey'],document())['id']; self.activate(ident)
        self.assertEqual('REVOKED',self.b.execute(self.signed())['state'])
        with self.b.transaction() as db:self.assertEqual(subject,self.b.federation_subject(db,'https://sp.invalid',person))

    def test_federation_ipc_shared_registry_binding_replay_and_revocation(self):
        from federation import FederationServer
        import socket
        self.activate();audience='https://localhost:8444/sp'
        path=Path(tempfile.mkdtemp(dir=self.root))/'federation.sock'
        bridge=FederationServer(path,self.a,audience);self.addCleanup(bridge.close)
        def call(operation,**data):
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                client.settimeout(5);client.connect(str(path));client.sendall(json.dumps({'operation':operation,'audience':audience,**data}).encode()+b'\n')
                with client.makefile('rb') as stream:return json.loads(stream.readline(100000))
        self.assertTrue(call('health')['ok'])
        request=call('start',binding='_signed_flow')['result']
        args={'id':request['id'],'secret':request['secret'],'binding':'_signed_flow'}
        self.assertIn('<svg',call('qr',**args)['result']['svg'])
        self.b.execute(self.signed('approve',request['id']))
        for change in ({'audience':'https://wrong.invalid'},{'binding':'wrong'},{'secret':'x'*43}):
            self.assertFalse(call('consume',**(args|change))['ok'])
        result=call('consume',**args)['result'];self.assertEqual('ALICE SYNTHETIC',result['identity']['displayName'])
        self.assertFalse(call('consume',**args)['ok'])
        check={'credentialId':self.ident,'subject':result['subject'],'version':result['version']}
        self.assertTrue(call('check',**check)['ok'])
        self.sql('revoker','SELECT revoke_credential(%s)',(self.ident,))
        self.assertFalse(call('check',**check)['ok'])

    def test_parallel_proposals_have_single_winner(self):
        def attempt(_):
            try:self.sql('alice','SELECT request_activation(%s,%s,%s)',(self.ident,'REVIEW-concurrent',24));return True
            except self.psycopg.Error:return False
        with ThreadPoolExecutor(max_workers=8) as pool:self.assertEqual(1,sum(pool.map(attempt,range(16))))

    def test_challenge_quota_shared_by_replicas(self):
        for _ in range(16):self.a.challenge({'credentialId':self.ident,'action':'snapshot','requestId':None})
        with self.assertRaises(ValueError):self.b.challenge({'credentialId':self.ident,'action':'snapshot','requestId':None})

    def test_central_keys_bind_context_and_roles(self):
        from transit import VaultUnavailable
        with self.a.transaction() as db:p=db.execute('SELECT * FROM profiles WHERE credential=?',(self.ident,)).fetchone()
        sealed=json.loads(p['sealed'])
        self.assertNotIn('ALICE',p['sealed'])
        with self.assertRaises(VaultUnavailable):self.a.vault.crypt('open',self.ident,'wrong-person',sealed)
        with self.assertRaises(VaultUnavailable):self.enroller.vault.crypt('open',self.ident,p['person'],sealed)
        with self.assertRaises(VaultUnavailable):self.a.vault.crypt('seal',self.ident,p['person'],{})
        with self.assertRaises(VaultUnavailable):self.a.vault.request('transit/export/encryption-key/openid-profile')

    def test_rotation_rewrap_without_decrypt_permission(self):
        from transit import TransitVault,VaultUnavailable
        vault=TransitVault(self.address,self.token_files['maintenance'],local_test=True)
        with self.a.transaction() as db:p=db.execute('SELECT * FROM profiles WHERE credential=?',(self.ident,)).fetchone()
        old=json.loads(p['sealed']); self.bao_request('transit/keys/openid-profile/rotate',{})
        new=vault.rewrap(self.ident,p['person'],old)
        self.assertNotEqual(old,new)
        self.assertEqual(self.a.vault.crypt('open',self.ident,p['person'],old),self.b.vault.crypt('open',self.ident,p['person'],new))
        with self.assertRaises(VaultUnavailable):vault.crypt('open',self.ident,p['person'],new)

    def test_key_service_outage_never_returns_profile(self):
        from transit import TransitVault,VaultUnavailable
        original=self.a.vault; self.a.vault=TransitVault('http://127.0.0.1:18201',self.token_files['wallet'],local_test=True)
        signed=self.signed()
        with self.assertRaises(VaultUnavailable):self.a.execute(signed)
        self.a.vault=original
        with self.assertRaises(ValueError):self.b.execute(signed)
        self.assertEqual('PENDING_REVIEW',self.b.execute(self.signed())['state'])

    def test_restore_revokes_every_key_and_invalidates_pending_approvals(self):
        self.activate(); signed=self.signed()
        self.sql('revoker','SELECT revoke_all_after_restore()')
        with self.assertRaises(ValueError):self.b.execute(signed)
        self.assertEqual('REVOKED',self.b.execute(self.signed())['state'])

    def restored_database(self, name, *, grant=False):
        from psycopg import sql
        from psycopg.conninfo import conninfo_to_dict, make_conninfo
        with self.psycopg.connect(DSN,autocommit=True) as admin:
            admin.execute(sql.SQL('ALTER DATABASE {} ALLOW_CONNECTIONS true').format(sql.Identifier(name)))
            if grant:
                admin.execute(sql.SQL('GRANT CONNECT ON DATABASE {} TO test_wallet,test_enroller,test_alice,test_bob').format(sql.Identifier(name)))
        return make_conninfo(**(conninfo_to_dict(DSN)|{'dbname':name}))

    def restore_target(self):
        from psycopg import sql
        name='openid_restore_'+secrets.token_hex(8)
        def cleanup():
            with self.psycopg.connect(DSN,autocommit=True) as admin:
                admin.execute(sql.SQL('DROP DATABASE IF EXISTS {} WITH (FORCE)').format(sql.Identifier(name)))
        self.addCleanup(cleanup)
        return name

    def test_actual_backup_restore_revokes_old_state_and_allows_new_enrollment(self):
        from cluster_recovery import backup,restore
        from psycopg.conninfo import conninfo_to_dict,make_conninfo
        from postgres import PostgresWallet
        self.activate()
        self.enroller.biometric_attempt(document())
        self.enroller.biometric_attempt(document())
        request=self.a.start_request(self.ident)
        self.a.execute(self.signed('approve',request['id']))
        signed=self.signed()
        other=self.enroller.enroll(self.keys[1]['publicKey'],document())['id']
        proposal=self.sql('alice','SELECT request_activation(%s,%s,%s)',(other,'REVIEW-before-backup',24))[0][0]
        destination=self.root/('backup-'+secrets.token_hex(8))
        saved=backup(self.dsns['backup'],destination,local_test=True)
        self.assertGreater(saved['bytes'],0)
        self.sql('revoker','SELECT revoke_credential(%s)',(self.ident,))
        target=self.restore_target()
        result=restore(DSN,destination,target,self.a.vault,local_test=True)
        self.assertEqual({'state':'QUARANTINED','profilesChecked':2},result)
        with self.psycopg.connect(DSN) as admin:
            self.assertFalse(admin.execute('SELECT datallowconn FROM pg_database WHERE datname=%s',(target,)).fetchone()[0])
        admin_dsn=self.restored_database(target)
        def dsn(role):return make_conninfo(**(conninfo_to_dict(self.dsns[role])|{'dbname':target}))
        # Even reopening the listener does not grant application access.
        with self.assertRaises(self.psycopg.Error):self.psycopg.connect(dsn('wallet'))
        self.restored_database(target,grant=True)
        restored=PostgresWallet(dsn('wallet'),self.a.origin,self.a.vault,local_test=True)
        self.addCleanup(restored.close)
        with self.assertRaises(ValueError):restored.execute(signed)
        with self.assertRaises(ValueError):restored.consume_result(request['id'],request['secret'])
        with self.psycopg.connect(dsn('bob')) as operator:
            with self.assertRaises(self.psycopg.Error):operator.execute('SELECT openid.approve_activation(%s)',(proposal,))
        self.assertEqual('REVOKED',restored.execute(self.signed(store=restored))['state'])
        enroller=PostgresWallet(dsn('enroller'),self.a.origin,self.enroller.vault,local_test=True)
        self.addCleanup(enroller.close)
        from wallet import EnrollmentQuarantine
        for operation in (enroller.enrollment_available,lambda:enroller.biometric_attempt(document()),
                          lambda:enroller.enroll(self.keys[2]['publicKey'],document())):
            with self.assertRaises(EnrollmentQuarantine):operation()
        with self.psycopg.connect(admin_dsn) as admin:
            self.assertEqual(2,admin.execute('SELECT cardinality(times) FROM openid.biometric_attempts').fetchone()[0])
            self.assertGreaterEqual(admin.execute('SELECT until_epoch-extract(epoch FROM clock_timestamp()) FROM openid.enrollment_quarantine').fetchone()[0],86390)
            # Test-only boundary simulation. No service role has this update permission.
            admin.execute('UPDATE openid.enrollment_quarantine SET until_epoch=0')
        self.assertEqual(2,enroller.biometric_attempt(document()))  # spent attempts survive COPY/restore
        with self.assertRaises(ValueError):enroller.enroll(self.keys[0]['publicKey'],document())
        ident=enroller.enroll(self.keys[2]['publicKey'],document())['id']
        with self.psycopg.connect(dsn('alice')) as operator:
            fresh=operator.execute('SELECT openid.request_activation(%s,%s,%s)',(ident,'REVIEW-after-restore',24)).fetchone()[0]
        with self.psycopg.connect(dsn('bob')) as operator:operator.execute('SELECT openid.approve_activation(%s)',(fresh,))
        self.assertEqual('ACTIVE',restored.execute(self.signed(key=2,store=restored))['state'])

        with self.psycopg.connect(admin_dsn) as admin:
            self.assertEqual(1,admin.execute("SELECT count(*) FROM openid.operator_events WHERE kind='RESTORE_REVOKED_ALL'").fetchone()[0])
        with self.assertRaises(self.psycopg.Error):restore(DSN,destination,target,self.a.vault,local_test=True)
        self.assertEqual('ACTIVE',restored.execute(self.signed(key=2,store=restored))['state'])

    def test_restore_hold_cannot_be_reset_or_shadowed_by_a_service(self):
        from wallet import EnrollmentQuarantine
        self.sql('revoker','SELECT revoke_all_after_restore()')
        with self.assertRaises(EnrollmentQuarantine):self.enroller.enrollment_available()
        with self.assertRaises(EnrollmentQuarantine):self.enroller.biometric_attempt(document())
        for role in self.dsns:
            for statement in ('UPDATE enrollment_quarantine SET until_epoch=0','DELETE FROM enrollment_quarantine'):
                with self.subTest(role=role,statement=statement),self.assertRaises(self.psycopg.Error):self.sql(role,statement)
        with self.psycopg.connect(self.dsns['enroller']) as attacker:
            attacker.execute('CREATE TEMP TABLE enrollment_quarantine(id integer,until_epoch bigint)')
            attacker.execute('SET LOCAL search_path=pg_temp,openid,pg_catalog')
            key=self.keys[2]['publicKey'];ident=hashlib.sha256(base64.b64decode(key)).hexdigest()
            with self.assertRaises(self.psycopg.Error):
                attacker.execute('INSERT INTO openid.credentials VALUES(%s,%s,%s,%s,NULL,NULL,%s)',
                    (ident,key,'PENDING_REVIEW',int(time.time()),secrets.token_hex(32)))

    def test_corrupt_unbounded_or_foreign_backup_is_rejected_before_creation(self):
        from cluster_recovery import backup,restore
        destination=self.root/('corrupt-'+secrets.token_hex(8))
        backup(self.dsns['backup'],destination,local_test=True)
        manifest=destination/'manifest.json';original=manifest.read_bytes()
        metadata=json.loads(original)
        for change in ({'schema':'0'*64},{'format':True},{'tables':{'../../outside':{}}}):
            manifest.write_text(json.dumps(metadata|change))
            with self.assertRaises(ValueError):restore(DSN,destination,self.restore_target(),self.a.vault,local_test=True)
        manifest.write_bytes(original)
        with self.assertRaises(ValueError):restore(DSN,destination,self.restore_target(),self.a.vault,local_test=True,max_bytes=1)
        part=destination/'profiles.copy';saved=part.read_bytes()
        part.write_bytes(saved[:-1])
        with self.assertRaises(ValueError):restore(DSN,destination,self.restore_target(),self.a.vault,local_test=True)
        part.write_bytes(saved);part.chmod(0o644)
        with self.assertRaises(ValueError):restore(DSN,destination,self.restore_target(),self.a.vault,local_test=True)
        part.unlink();part.symlink_to(destination/'persons.copy')
        with self.assertRaises(OSError):restore(DSN,destination,self.restore_target(),self.a.vault,local_test=True)
        with self.assertRaises(FileExistsError):backup(self.dsns['backup'],destination,local_test=True)

    def test_backup_manifest_and_table_reject_fifo_without_waiting_for_a_writer(self):
        from cluster_recovery import backup
        destination = self.root / ('fifo-' + secrets.token_hex(8))
        backup(self.dsns['backup'], destination, local_test=True)
        for name in ('manifest.json', 'profiles.copy'):
            with self.subTest(name=name):
                path = destination / name
                saved = path.read_bytes()
                path.unlink()
                os.mkfifo(path, 0o600)
                try:
                    result = subprocess.run([sys.executable, '-c', '''
import sys
import time
from contextlib import ExitStack
from cluster_recovery import read_backup, MAX_BYTES
with ExitStack() as stack:
    try:
        read_backup(sys.argv[1], stack, time.monotonic() + 1, MAX_BYTES)
    except ValueError as error:
        assert str(error) == 'private regular backup file required'
    else:
        raise AssertionError('FIFO accepted as backup input')
''', str(destination)], cwd=Path(__file__).parent, capture_output=True, timeout=5)
                    self.assertEqual(0, result.returncode, result.stderr.decode())
                finally:
                    path.unlink()
                    with path.open('xb') as stream:
                        stream.write(saved)
                    path.chmod(0o600)

    def test_wrong_key_or_key_outage_keeps_restore_empty_and_closed(self):
        from cluster_recovery import backup,restore
        from transit import TransitVault,VaultUnavailable
        destination=self.root/('key-failure-'+secrets.token_hex(8))
        backup(self.dsns['backup'],destination,local_test=True)
        vault=TransitVault('http://127.0.0.1:18201',self.token_files['wallet'],local_test=True)
        target=self.restore_target()
        with self.assertRaises(VaultUnavailable):restore(DSN,destination,target,vault,local_test=True)
        with self.psycopg.connect(DSN) as admin:
            self.assertFalse(admin.execute('SELECT datallowconn FROM pg_database WHERE datname=%s',(target,)).fetchone()[0])
        with self.psycopg.connect(self.restored_database(target)) as admin:
            self.assertEqual(0,admin.execute('SELECT count(*) FROM openid.credentials').fetchone()[0])
        # Backup login has read access only, including no activation or destructive operations.
        with self.assertRaises(self.psycopg.Error):self.sql('backup','DELETE FROM credentials')

    def test_database_restore_with_recovered_raft_keys_and_stale_key_snapshot(self):
        from cluster_recovery import backup,restore
        from raft_test_support import RaftCluster
        from transit import TransitVault,VaultUnavailable
        cluster=RaftCluster(self.root/('raft-'+secrets.token_hex(8)))
        self.addCleanup(cluster.close)
        source=cluster.start();token,seal=cluster.initialize(source)
        tokens=cluster.provision(source,token)
        obsolete_snapshot=cluster.call(source,'sys/storage/raft/snapshot',token=token,raw=True)
        cluster.call(source,'transit/keys/openid-profile/rotate',{},token)
        with self.psycopg.connect(DSN,autocommit=True) as admin:
            admin.execute('TRUNCATE openid.credentials,openid.persons,openid.operator_events,openid.maintenance_runs,openid.biometric_attempts RESTART IDENTITY CASCADE')
        self.enroller.vault=TransitVault(source['address'],tokens['enroller'],str(cluster.cert))
        self.ident=self.enroller.enroll(self.keys[0]['publicKey'],document())['id'];self.activate()
        destination=self.root/('paired-'+secrets.token_hex(8))
        backup(self.dsns['backup'],destination,local_test=True)
        snapshot=cluster.call(source,'sys/storage/raft/snapshot',token=token,raw=True)
        cluster.stop(source)
        recovered=cluster.restore_snapshot(snapshot,seal)
        vault=TransitVault(recovered['address'],tokens['recovery'],str(cluster.cert))
        target=self.restore_target()
        self.assertEqual({'state':'QUARANTINED','profilesChecked':1},restore(DSN,destination,target,vault,local_test=True))
        with self.psycopg.connect(self.restored_database(target)) as admin:
            self.assertEqual([('REVOKED',)],admin.execute('SELECT state FROM openid.credentials').fetchall())
        obsolete=cluster.restore_snapshot(obsolete_snapshot,seal)
        old_vault=TransitVault(obsolete['address'],tokens['recovery'],str(cluster.cert))
        rejected=self.restore_target()
        with self.assertRaises(VaultUnavailable):restore(DSN,destination,rejected,old_vault,local_test=True)
        with self.psycopg.connect(DSN) as admin:
            self.assertFalse(admin.execute('SELECT datallowconn FROM pg_database WHERE datname=%s',(rejected,)).fetchone()[0])
        with self.psycopg.connect(self.restored_database(rejected)) as admin:
            self.assertEqual(0,admin.execute('SELECT count(*) FROM openid.credentials').fetchone()[0])

    def test_retention_and_rotation_maintenance_is_bounded_and_repeatable(self):
        from maintenance import maintain
        maintenance=self.store('maintenance')
        self.bao_request('transit/keys/openid-profile/rotate',{})
        result=maintain(maintenance,profile_days=7,event_days=1827,batch=1)
        self.assertEqual(1,result['rewrapped'])
        self.assertEqual(0,maintain(maintenance,profile_days=7,event_days=1827)['rewrapped'])
        self.activate()
        with self.psycopg.connect(DSN) as db:
            db.execute('SET LOCAL ROLE openid_owner')
            db.execute('UPDATE openid.credentials SET expires=%s',(int(time.time())-8*86400,))
        maintain(maintenance,profile_days=7,event_days=1827)
        with self.a.transaction() as db:
            self.assertEqual(0,db.execute('SELECT count(*) FROM profiles').fetchone()[0])
            self.assertEqual(1,db.execute('SELECT count(*) FROM credentials').fetchone()[0])
        with self.assertRaises(ValueError):self.enroller.enroll(self.keys[0]['publicKey'],document())

    def test_four_tls_workers_share_state_and_survive_instance_loss(self):
        import socket,ssl,sys
        self.activate()
        directory=Path(tempfile.mkdtemp(dir=self.root))
        cert,key=directory/'cert.pem',directory/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
            '-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        context=ssl.create_default_context(cafile=str(cert));processes=[];ports=[];logs=[];container_names={}
        def stop(process):
            if process.pid in container_names:
                name=container_names[process.pid]
                subprocess.run(['docker','stop','--time','65',name],check=True,stdout=subprocess.DEVNULL)
                code=subprocess.check_output(['docker','inspect','--format','{{.State.ExitCode}}',name],text=True).strip()
                if code!='0':
                    output=subprocess.check_output(['docker','logs',name],stderr=subprocess.STDOUT,text=True)
                    self.fail('Container exit '+code+': '+output)
                process.wait(timeout=70)
            else:
                process.terminate();self.assertEqual(0,process.wait(timeout=70))
        def cleanup():
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait()
        self.addCleanup(cleanup)
        for index in range(2):
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));ports.append(sock.getsockname()[1])
            from psycopg.conninfo import conninfo_to_dict,make_conninfo
            database_options=conninfo_to_dict(self.dsns['wallet'])
            if database_options.get('sslrootcert'):
                ca=directory/'postgres.crt';ca.write_bytes(Path(database_options['sslrootcert']).read_bytes())
                database_options['sslrootcert']=str(ca)
            for name,value in [('dsn',make_conninfo(**database_options)),('pairing','x'*43),('metrics','y'*43),('wallet-token',self.token_files['wallet'].read_text())]:
                path=directory/name;path.write_text(value);path.chmod(0o600)
            config={'bind':'127.0.0.1','port':ports[-1],'origin':self.a.origin,'workers':2,'role':'wallet',
                'databaseFile':str(directory/'dsn'),'baoAddress':self.address,'baoTokenFile':str(directory/'wallet-token'),
                'baoCA':str(cert),'tlsCert':str(cert),'tlsKey':str(key),'pairingFile':str(directory/'pairing'),'metricsFile':str(directory/'metrics')}
            path=directory/(str(index)+'.json');path.write_text(json.dumps(config))
            log=open(directory/(str(index)+'.log'),'w+');logs.append(log);self.addCleanup(log.close)
            command=[sys.executable,'-c','import json,sys;from cluster_serve import run;run(json.load(open(sys.argv[1])),local_test=True)',str(path)]
            image=os.environ.get('OPENID_TEST_CONTAINER') if index==0 else None
            if image:
                name='openid-cluster-'+secrets.token_hex(8)
                command=['docker','run','--name',name,'--network','host','--read-only','--cap-drop','ALL',
                    '--security-opt','no-new-privileges','--pids-limit','128','--memory','512m','--cpus','2',
                    '--user',str(os.getuid())+':'+str(os.getgid()),'--tmpfs','/tmp:size=32m,mode=1777',
                    '-v',str(directory)+':'+str(directory)+':ro','--entrypoint','python',image,*command[1:]]
                self.addCleanup(lambda name=name:subprocess.run(['docker','rm','--force',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
            process=subprocess.Popen(command,stdout=log,stderr=log)
            if image:container_names[process.pid]=name
            processes.append(process)
        headers={'Host':'localhost:8765','Origin':self.a.origin,'X-CSRF-Token':'x'*43,'Content-Type':'application/json'}
        def request(index,path,body=None,extra=None):
            c=http.client.HTTPSConnection('localhost',ports[index],context=context,timeout=10)
            try:
                c.request('POST' if body is not None else 'GET',path,json.dumps(body) if body is not None else None,headers|(extra or {}))
                r=c.getresponse();return r.status,json.loads(r.read())
            finally:c.close()
        for index in range(2):
            for _ in range(100):
                if processes[index].poll() is not None:
                    logs[index].seek(0);raise AssertionError(logs[index].read())
                try:
                    if request(index,'/health/ready')[0]==200:break
                except OSError:pass
                time.sleep(.1)
            else:raise AssertionError('TLS service did not become ready')
        self.assertEqual(404,request(0,'/native/start',{})[0])
        self.assertEqual(403,request(0,'/metrics')[0])
        self.assertEqual(200,request(0,'/metrics',extra={'Authorization':'Bearer '+'y'*43})[0])
        code,c=request(0,'/wallet/challenge',{'credentialId':self.ident,'action':'snapshot','requestId':None});self.assertEqual(200,code)
        signed={'challengeId':c['id'],'signature':crypt(op='sign',key=self.keys[0]['privateKey'],payload=c['signingInput'])}
        stop(processes[0])
        self.assertEqual(200,request(1,'/wallet/execute',signed)[0])
        self.assertEqual(400,request(1,'/wallet/execute',signed)[0])
        def operation(_):
            start=time.monotonic()
            code,c=request(1,'/wallet/challenge',{'credentialId':self.ident,'action':'snapshot','requestId':None})
            if code!=200:return code,time.monotonic()-start
            signed={'challengeId':c['id'],'signature':crypt(op='sign',key=self.keys[0]['privateKey'],payload=c['signingInput'])}
            code,result=request(1,'/wallet/execute',signed)
            if code==200:self.assertEqual('ALICE SYNTHETIC',result['identity']['displayName'])
            return code,time.monotonic()-start
        started=time.monotonic()
        with ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(operation,range(80)))
        self.assertEqual({200},{code for code,_ in results})
        duration=time.monotonic()-started
        report={'operations':80,'concurrency':8,'workers':2,'instancesRemaining':1,'errors':0,
            'operationsPerSecond':round(80/duration,2),'p95Seconds':round(sorted(t for _,t in results)[75],3)}
        soak_seconds=int(os.environ.get('OPENID_TEST_SOAK_SECONDS','0'))
        if soak_seconds:
            self.assertTrue(30<=soak_seconds<=600)
            # Each operation makes two requests. Stay below one worker's 10 requests/s
            # even when the shared listener distributes connections unevenly.
            target_rate=4
            master=processes[1].pid
            def resources():
                children=Path(f'/proc/{master}/task/{master}/children').read_text().split()
                result={}
                for pid in children:
                    values=dict(line.split(':',1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
                    result[pid]={'rssKiB':int(values['VmRSS'].split()[0]),'fds':len(list(Path(f'/proc/{pid}/fd').iterdir()))}
                self.assertEqual(2,len(result))
                return result
            before=resources();samples=[];begin=time.monotonic();end=begin+soak_seconds
            def paced(client):
                values=[];scheduled=begin+client/target_rate
                while scheduled<end:
                    time.sleep(max(0,scheduled-time.monotonic()))
                    values.append(operation(client))
                    scheduled+=8/target_rate
                return values
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures=[pool.submit(paced,client) for client in range(8)]
                while not all(future.done() for future in futures):
                    samples.append(resources());time.sleep(1)
                sustained=[item for future in futures for item in future.result()]
            elapsed=time.monotonic()-begin;after=resources()
            self.assertEqual(soak_seconds*target_rate,len(sustained))
            self.assertEqual({200},{code for code,_ in sustained})
            self.assertEqual(set(before),set(after))
            for pid in before:
                self.assertLessEqual(after[pid]['fds'],before[pid]['fds']+8)
                self.assertLessEqual(after[pid]['rssKiB'],before[pid]['rssKiB']+32768)
            latencies=sorted(t for _,t in sustained)
            report['sustained']={'seconds':round(elapsed,2),'operations':len(sustained),'concurrency':8,
                'targetOperationsPerSecond':target_rate,'operationsPerSecond':round(len(sustained)/elapsed,2),'errors':0,
                'p95Seconds':round(latencies[int(.95*(len(latencies)-1))],3),
                'p99Seconds':round(latencies[int(.99*(len(latencies)-1))],3),
                'maxWorkerRSSMiB':round(max(value['rssKiB'] for sample in samples for value in sample.values())/1024,2),
                'maxWorkerFileDescriptors':max(value['fds'] for sample in samples for value in sample.values())}
            with self.a.transaction() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM challenges').fetchone()[0])
        print(json.dumps(report))
        if os.environ.get('OPENID_TEST_REPORT'):Path(os.environ['OPENID_TEST_REPORT']).write_text(json.dumps(report,indent=2)+'\n')
        self.sql('revoker','SELECT revoke_credential(%s)',(self.ident,))
        self.assertEqual('REVOKED',self.b.execute(self.signed())['state'])
        stop(processes[1])
        for log in logs:
            log.seek(0);output=log.read()
            for secret in (self.ident,'ALICE','x'*43,'y'*43,self.token):self.assertNotIn(secret,output)

    def test_disconnected_database_fails_closed_and_recovers(self):
        from postgres import RegistryUnavailable
        # A login may terminate its own sessions; no server-wide signalling privilege is needed.
        with self.psycopg.connect(self.dsns['wallet'],autocommit=True) as client:
            try:
                with self.psycopg.connect(DSN,autocommit=True) as db:db.execute('ALTER ROLE test_wallet NOLOGIN')
                client.execute('SELECT pg_terminate_backend(pid) FROM pg_stat_activity '
                               'WHERE usename=current_user AND pid<>pg_backend_pid()')
                with self.assertRaises(RegistryUnavailable):self.a.health()
            finally:
                with self.psycopg.connect(DSN,autocommit=True) as db:db.execute('ALTER ROLE test_wallet LOGIN')
        self.a=self.store('wallet'); self.a.health()


if __name__=='__main__':
    if not DSN:raise SystemExit('Set OPENID_TEST_POSTGRES to a disposable database')
    unittest.main()
