"""Integration tests require a disposable PostgreSQL database and the pinned bao binary."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import subprocess
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
            for user, roles in {'enroller':['enroller'], 'wallet':['wallet'], 'alice':['requester'],
                'bob':['approver'], 'carol':['requester','approver'], 'revoker':['revoker'],
                'maintenance':['maintenance'], 'auditor':['auditor']}.items():
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
            db.execute('TRUNCATE openid.credentials,openid.persons,openid.operator_events,openid.maintenance_runs RESTART IDENTITY CASCADE')
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

    def test_same_login_cannot_approve_even_with_both_roles(self):
        proposal=self.sql('carol','SELECT request_activation(%s,%s,%s)',(self.ident,'REVIEW-test-002',24))[0][0]
        with self.assertRaises(self.psycopg.Error):self.sql('carol','SELECT approve_activation(%s)',(proposal,))

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
            'purge_expired(integer,integer,integer)':{'maintenance'}}
        for function,users in allowed.items():
            for role in self.dsns:
                with self.subTest(function=function,role=role):
                    self.assertEqual(role in users,self.sql(role,'SELECT has_function_privilege(current_user,%s,%s)',
                        ('openid.'+function,'EXECUTE'))[0][0])

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

    def test_retention_and_rotation_maintenance_is_bounded_and_repeatable(self):
        from maintenance import maintain
        maintenance=self.store('maintenance')
        self.bao_request('transit/keys/openid-profile/rotate',{})
        result=maintain(maintenance,profile_days=7,event_days=30,batch=1)
        self.assertEqual(1,result['rewrapped'])
        self.assertEqual(0,maintain(maintenance,profile_days=7,event_days=30)['rewrapped'])
        self.activate()
        with self.psycopg.connect(DSN) as db:
            db.execute('SET LOCAL ROLE openid_owner')
            db.execute('UPDATE openid.credentials SET expires=%s',(int(time.time())-8*86400,))
        maintain(maintenance,profile_days=7,event_days=30)
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
                subprocess.run(['docker','stop','--time','65',container_names[process.pid]],check=True,stdout=subprocess.DEVNULL)
            else:process.terminate()
            self.assertEqual(0,process.wait(timeout=70))
        self.addCleanup(lambda:[p.kill() for p in processes if p.poll() is None])
        for index in range(2):
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));ports.append(sock.getsockname()[1])
            for name,value in [('dsn',self.dsns['wallet']),('pairing','x'*43),('metrics','y'*43),('wallet-token',self.token_files['wallet'].read_text())]:
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
                command=['docker','run','--rm','--name',name,'--network','host','--read-only','--cap-drop','ALL',
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
        # Kill live pool connections, then make the server reject this login entirely.
        with self.psycopg.connect(DSN,autocommit=True) as db:
            db.execute('ALTER ROLE test_wallet NOLOGIN')
            db.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='test_wallet'")
        try:
            with self.assertRaises(RegistryUnavailable):self.a.health()
        finally:
            with self.psycopg.connect(DSN,autocommit=True) as db:db.execute('ALTER ROLE test_wallet LOGIN')
        self.a=self.store('wallet'); self.a.health()


if __name__=='__main__':
    if not DSN:raise SystemExit('Set OPENID_TEST_POSTGRES to a disposable database')
    unittest.main()
