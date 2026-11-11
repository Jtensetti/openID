"""Run the canonical profile on a disposable Linux CI host with synthetic data.

Requires a dedicated GitHub runner: this temporarily adds local IMDS addresses
and hosts entries. It never runs on the user's machine or against an AWS account.
The only overlays are declared synthetic DNS/PKI trust, not application code.
"""
import argparse
from contextlib import ExitStack
import http.client
import http.cookiejar
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'verification'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from contract import VENDORS, IDENTITIES
import check


class CommandFailure(RuntimeError):
    def __init__(self,args,result):
        tool=Path(args[0]).name
        self.detail={'tool':tool,'exitCode':result.returncode}
        # Only infrastructure/startup commands. Never include exec output,
        # command arguments, AWS responses, profiles or credential files.
        if tool in ('ip','nft') or (tool=='docker' and args[1] in ('compose','run','pull','image')) or (
                tool.startswith('python') and len(args)>1 and Path(args[1]).name in ('metadata_guard.py','check.py')):
            self.detail['startupError']=result.stderr.decode(errors='replace')[-4000:]
        super().__init__('synthetic command failed: '+tool)


def command(args, **options):
    result = subprocess.run(args, capture_output=True, timeout=options.pop('timeout', 120), **options)
    if result.returncode:
        # Commands may contain generated fixture passwords. Never echo them.
        raise CommandFailure(args,result)
    return result.stdout.decode()


def certificate(root, name, names):
    cert, key = root/(name+'.pem'), root/(name+'.key')
    command(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','1','-subj','/CN=SYNTHETIC-'+name,
             '-addext','subjectAltName='+names,'-keyout',str(key),'-out',str(cert)])
    key.chmod(0o600)
    return cert, key


class Forms(HTMLParser):
    def __init__(self,text):
        super().__init__();self.forms=[];self.current=None;self.feed(text)
    def handle_starttag(self,tag,attrs):
        values=dict(attrs)
        if tag=='form':self.current={'action':values.get('action'),'fields':{}};self.forms.append(self.current)
        if tag=='input' and self.current is not None and 'name' in values:self.current['fields'][values['name']]=values.get('value','')
    def handle_endtag(self,tag):
        if tag=='form':self.current=None


class Runtime:
    def __init__(self,image,report):
        if sys.platform!='linux' or os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true':
            raise ValueError('dedicated disposable Linux CI host required')
        if command(['docker','ps','-aq','--filter','label=com.docker.compose.project=tjipp']).strip():
            raise ValueError('refusing an existing Tjipp deployment')
        self.report=report;self.phase('prepare_vendor_images')
        self.resources=ExitStack();self.root=Path(tempfile.mkdtemp(prefix='tjipp-runtime-')).resolve()
        self.root.chmod(0o711)
        self.resources.callback(shutil.rmtree,self.root,ignore_errors=True)
        self.image=image;self.children_started=False;self.aws=None;self.bao_root=None
        self.environment={**os.environ,'TJIPP_DIRECTORY':str(self.root),'TJIPP_IMAGE_ID':image,
            'TJIPP_POSTGRES_IMAGE_ID':VENDORS['postgres']['id'],'TJIPP_OPENBAO_IMAGE_ID':VENDORS['openbao']['id'],
            'TJIPP_NOTICE_QUEUE_URL':'https://sqs.eu-north-1.amazonaws.com/000000000000/synthetic-notices'}
        self.overlay=self.root/'synthetic-routing.json'
        self.compose=['docker','compose','-f',str(ROOT/'deployment/production/compose.yaml')]
        try:self.prepare()
        except BaseException:
            self.diagnostics();self.close();raise

    def phase(self,value):
        self.report['phase']=value
        print('Synthetic runtime phase: '+value,flush=True)

    def diagnostics(self):
        states={};vendor_logs={}
        for name in IDENTITIES:
            try:
                identifier=self.container(name)
                if identifier:
                    state=json.loads(command(['docker','inspect',identifier]))[0]['State']
                    states[name]={'status':state['Status'],'exitCode':state['ExitCode'],
                                  'health':state.get('Health',{}).get('Status')}
                    if name in VENDORS:
                        log=subprocess.run(['docker','logs','--tail','20',identifier],capture_output=True,text=True,timeout=10)
                        vendor_logs[name]=(log.stdout+log.stderr)[-4000:]
            except Exception:pass
        self.report['componentStatus']=states
        self.report['syntheticVendorStartupLogs']=vendor_logs
        if self.aws is not None:self.report['syntheticUpstreamErrors']=list(self.aws.errors)

    def directory(self,name,uid,gid,mode):
        path=self.root/name;path.mkdir(parents=True,exist_ok=True);os.chown(path,uid,gid);path.chmod(mode);return path

    def file(self,name,value,uid,gid,mode=0o600):
        path=self.root/name
        raw=value if isinstance(value,bytes) else value.encode()
        path.write_bytes(raw);os.chown(path,uid,gid);path.chmod(mode);return path

    def json(self,name,value,uid,gid,mode=0o600):return self.file(name,json.dumps(value),uid,gid,mode)

    def dc(self,*args,overlay=True):
        call=self.compose+(['-f',str(self.overlay)] if overlay else [])+list(args)
        return command(call,env=self.environment,timeout=180)

    def container(self,name):return self.dc('ps','-aq',name).strip()

    def execute(self,name,args,**options):return command(['docker','exec',self.container(name),*args],**options)

    def wait(self,predicate,description,seconds=120):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            try:
                if predicate():return
            except Exception:pass
            time.sleep(.5)
        raise AssertionError('Synthetic runtime timeout: '+description)

    def prepare(self):
        import psycopg
        from psycopg.conninfo import make_conninfo
        from synthetic_aws_runtime import SyntheticAWS
        from runtime_test_fixture import RuntimeFixture
        from test_federation_postgres import FederationPostgres
        from test_continuity_support import REFERENCE
        for name,ref in VENDORS.items():
            command(['docker','pull','--platform','linux/amd64',ref['source']])
            actual=command(['docker','image','inspect',ref['source'],'--format','{{.Id}}']).strip()
            if actual!=ref['id']:raise ValueError('vendor image identity mismatch')
        self.phase('prepare_synthetic_keys_and_boundaries')
        for name,identity in IDENTITIES.items():
            if name in ('idp','sp','notice-exporter','postgres','openbao'):continue
            uid,gid=map(int,identity.split(':'));self.directory('services/'+name,uid,gid,0o700)
        for name,uid,gid,mode in [('postgres/config',999,999,0o700),('postgres/data',999,999,0o700),
            ('openbao/config',10008,20008,0o700),('openbao/data',10008,20008,0o700),('openbao/audit',10008,20008,0o700),
            ('ipc/continuity',10007,20004,0o2710),('ipc/federation',10009,20001,0o2710),('ipc/notice',10009,20003,0o2710),
            ('aws/continuity',0,20004,0o2710),('aws/notices',0,20003,0o2710)]:self.directory(name,uid,gid,mode)
        public=self.directory('public',0,0,0o755)
        self.pki=self.directory('fixture-pki',0,0,0o700)
        self.fixture=RuntimeFixture(self.pki,api_host='api.example.test')
        for source,target,uid in [(self.fixture.idp,'federation-idp',10002),(self.fixture.sp,'federation-sp',10003)]:
            shutil.copytree(source,self.root/target)
            os.chown(self.root/target,uid,20001);(self.root/target).chmod(0o700)
            for path in (self.root/target).iterdir():os.chown(path,uid,20001);path.chmod(0o600)
        self.directory('federation-state',10002,20001,0o700)
        for role in ('idp','sp'):self.file('public/'+role+'.pem',(self.pki/(role+'-tls.crt')).read_bytes(),0,0,0o644)
        self.json('origins.json',{'idp':'https://idp.example.test','sp':'https://sp.example.test'},0,0,0o644)
        self.json('federation.json',{'version':1,'profile':'private'},0,0,0o644)
        pg_cert,pg_key=certificate(self.pki,'postgres','DNS:localhost,IP:127.0.0.1')
        bao_cert,bao_key=certificate(self.pki,'openbao','DNS:localhost,IP:127.0.0.1')
        aws_cert,aws_key=certificate(self.pki,'aws','DNS:sts.eu-north-1.amazonaws.com,DNS:lambda.eu-north-1.amazonaws.com,DNS:sqs.eu-north-1.amazonaws.com')
        for file in ('postgresql.conf','pg_hba.conf'):self.file('postgres/config/'+file,(ROOT/'deployment/production'/file).read_bytes(),999,999)
        self.file('postgres/config/server.pem',pg_cert.read_bytes(),999,999);self.file('postgres/config/server.key',pg_key.read_bytes(),999,999)
        self.json('openbao/config/openbao.json',check.example('openbao.example.json'),10008,20008)
        self.file('openbao/config/tls.pem',bao_cert.read_bytes(),10008,20008);self.file('openbao/config/tls.key',bao_key.read_bytes(),10008,20008)
        # The addresses are loopback-owned synthetic endpoints before any client
        # starts. No request reaches the runner's real cloud metadata service.
        for address in ('169.254.169.254/32','fd00:ec2::254/128'):
            command(['ip','address','add',address,'dev','lo'])
            self.resources.callback(lambda a=address:subprocess.run(['ip','address','del',a,'dev','lo'],capture_output=True))
        command([sys.executable,str(ROOT/'deployment/production/metadata_guard.py'),'install'])
        self.resources.callback(lambda:subprocess.run(['nft','delete','table','inet','tjipp_metadata'],capture_output=True))
        command(['swapoff','-a'])
        command([sys.executable,str(ROOT/'deployment/production/check.py'),'host'])
        self.aws=SyntheticAWS(aws_cert,aws_key);self.resources.callback(self.aws.close)
        original_hosts=Path('/etc/hosts').read_bytes()
        Path('/etc/hosts').write_bytes(original_hosts+b'\n127.0.0.1 api.example.test idp.example.test sp.example.test\n')
        self.resources.callback(Path('/etc/hosts').write_bytes,original_hosts)
        overlay={}
        for name in ('credential-rotator','continuity','notice-exporter'):
            overlay[name]={'extra_hosts':{service+'.eu-north-1.amazonaws.com':'127.0.0.2' for service in ('sts','lambda','sqs')},
                          'environment':{'AWS_CA_BUNDLE':'/srv/openid/test-aws-ca.pem'},
                          'volumes':[{'type':'bind','source':str(aws_cert),'target':'/srv/openid/test-aws-ca.pem','read_only':True}]}
        for name in ('idp','sp'):
            from contract import ENTRYPOINTS
            entry=ENTRYPOINTS[name]
            overlay[name]={'extra_hosts':{'idp.example.test':'127.0.0.1','sp.example.test':'127.0.0.1'},
                          'entrypoint':entry[:2]+['-Djavax.net.ssl.trustStore=/srv/openid/test-trust.p12',
                              '-Djavax.net.ssl.trustStorePassword='+self.fixture.trust_password]+entry[2:],
                          'volumes':[{'type':'bind','source':str(self.pki/'trust.p12'),'target':'/srv/openid/test-trust.p12','read_only':True}]}
        self.overlay.write_text(json.dumps({'services':overlay}))
        base=json.loads(self.dc('config','--format','json',overlay=False));check.check_compose(base,self.image,str(self.root))
        rendered=json.loads(self.dc('config','--format','json'))
        for name,service in rendered['services'].items():
            original=base['services'][name]
            allowed=overlay.get(name,{})
            for field in set(service)|set(original):
                if field not in allowed:assert service.get(field)==original.get(field),'undeclared synthetic override'
            if 'volumes' in allowed:
                actual={mount['target']:mount for mount in service['volumes']}
                for mount in original['volumes']:assert actual.pop(mount['target'])==mount,'base mount changed by fixture'
                assert set(actual)=={mount['target'] for mount in allowed['volumes']},'unexpected synthetic mount'
            if 'environment' in allowed:
                assert service['environment']==original['environment']|allowed['environment'],'base environment changed by fixture'
            if 'extra_hosts' in allowed:
                actual=service['extra_hosts']
                if isinstance(actual,list):
                    pairs=[entry.split('=',1) for entry in actual]
                    assert len({pair[0] for pair in pairs})==len(pairs),'duplicate synthetic host override'
                    actual=dict(pairs)
                assert actual==allowed['extra_hosts'],'synthetic DNS override changed'
            if 'entrypoint' in allowed:assert service['entrypoint']==allowed['entrypoint'],'synthetic Java trust override changed'
        self.phase('initialize_real_postgres_and_sealed_openbao')
        password=secrets.token_urlsafe(32)
        password_file=self.file('bootstrap-password',password,999,999)
        command(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
                 '--user','999:999','--tmpfs','/tmp:size=32m,mode=1777','-v',str(self.root/'postgres/data')+':/data',
                 '-v',str(password_file)+':/password:ro','--entrypoint','initdb',VENDORS['postgres']['id'],
                 '-D','/data','-U','postgres','--pwfile=/password','--auth=scram-sha-256'])
        self.dc('up','-d','postgres','openbao');self.children_started=True
        self.admin=make_conninfo(host='127.0.0.1',port=15432,dbname='postgres',user='postgres',password=password,
                                sslmode='verify-full',sslrootcert=str(pg_cert))
        def db_ready():
            with psycopg.connect(self.admin):return True
        self.wait(db_ready,'PostgreSQL/SCRAM/TLS')
        self.bao_context=ssl.create_default_context(cafile=str(bao_cert))
        self.wait(lambda:self.bao('sys/seal-status',method='GET')['sealed'] is True,'sealed non-dev OpenBao')
        init=self.bao('sys/init',{'secret_shares':3,'secret_threshold':2});self.unseal_keys=init['keys'][:2];self.bao_root=init['root_token']
        for key in self.unseal_keys:self.bao('sys/unseal',{'key':key})
        self.wait(lambda:self.bao('sys/leader',method='GET').get('is_self') is True,'active Raft leader')
        self.bao('sys/audit/file',{'type':'file','options':{'file_path':'/srv/openbao/audit/audit.log','log_raw':'false'}})
        self.bao('sys/mounts/transit',{'type':'transit'})
        self.bao('transit/keys/openid-profile',{'type':'aes256-gcm96','derived':True,'exportable':False})
        self.bao('transit/keys/openid-profile/config',{'auto_rotate_period':'720h'})
        self.bao('transit/keys/openid-index',{'type':'hmac','key_size':32,'exportable':False})
        tokens={}
        for role in ('enroller','wallet','bridge','registry','contact'):
            policy='wallet' if role=='bridge' else role
            self.bao('sys/policies/acl/'+role,{'policy':(ROOT/'deployment/cluster'/(policy+'.hcl')).read_text()})
            response=self.bao('auth/token/create',{'policies':[role],'no_default_policy':True,'no_parent':True,'ttl':'1h'})
            token_file=self.file('fixture-'+role+'.token',response['auth']['client_token'],0,0)
            tokens[role]=token_file
        bootstrap=secrets.token_urlsafe(32)
        with psycopg.connect(self.admin,autocommit=True) as db:
            from psycopg import sql
            db.execute(sql.SQL('CREATE ROLE test_bootstrap LOGIN NOSUPERUSER NOBYPASSRLS CREATEDB CREATEROLE PASSWORD {}').format(sql.Literal(bootstrap)))
            db.execute('CREATE DATABASE openid_runtime OWNER test_bootstrap')
        dsn=make_conninfo(host='127.0.0.1',port=15432,dbname='openid_runtime',user='test_bootstrap',password=bootstrap,
                         sslmode='verify-full',sslrootcert=str(pg_cert))
        os.environ['OPENID_TEST_POSTGRES']=dsn
        self.model=FederationPostgres(self.root,'https://api.example.test',external_bao={'address':'https://127.0.0.1:18210','ca':str(bao_cert),'tokens':tokens})
        self.resources.callback(self.model.close);self.aws.authority=self.model.synthetic
        self.bao('auth/token/revoke-self',{});self.bao_root=None
        from psycopg.conninfo import conninfo_to_dict
        for name,role in [('verifier','enroller'),('wallet','wallet'),('bridge','bridge'),('continuity','continuity')]:
            uid,gid=map(int,IDENTITIES[name].split(':'))
            options=conninfo_to_dict(self.model.dsns[role]);options['sslrootcert']='/srv/openid/service/postgres-ca.pem'
            self.file('services/'+name+'/database',make_conninfo(**options),uid,gid)
            self.file('services/'+name+'/postgres-ca.pem',pg_cert.read_bytes(),uid,gid)
            if name!='continuity':
                self.file('services/'+name+'/bao.token',tokens[role].read_bytes(),uid,gid)
                self.file('services/'+name+'/bao-ca.pem',bao_cert.read_bytes(),uid,gid)
                self.json('services/'+name+'/continuity.json',{'version':1,'socket':'/srv/openid/continuity-ipc/continuity.sock','authority':REFERENCE},uid,gid)
        for name,example in [('verifier','runtime.example.json'),('wallet','wallet.example.json'),('bridge','bridge.example.json'),
                             ('continuity','controller.example.json'),('credential-rotator','credential-rotate.example.json')]:
            uid,gid=map(int,IDENTITIES[name].split(':'));config=check.example(example)
            if name in ('verifier','wallet','bridge'):config['origin']='https://api.example.test'
            if name=='credential-rotator':config={'sourceRoleArn':'arn:aws:iam::000000000000:role/HOST',
                'roles':{'continuity':'arn:aws:iam::000000000000:role/CONTINUITY','notices':'arn:aws:iam::000000000000:role/NOTICES'}}
            self.json('services/'+name+'/runtime.json',config,uid,gid)
        self.json('services/continuity/authority.json',{'version':1,'region':'eu-north-1','backendFunction':REFERENCE},10007,20004)
        self.pairing=secrets.token_urlsafe(32)
        for name in ('verifier','wallet'):
            uid,gid=map(int,IDENTITIES[name].split(':'));cert,key=certificate(self.pki,name,'DNS:localhost,IP:127.0.0.1')
            self.file('services/'+name+'/server.pem',cert.read_bytes(),uid,gid);self.file('services/'+name+'/server.key',key.read_bytes(),uid,gid)
            self.file('services/'+name+'/pairing',self.pairing,uid,gid)
            self.file('services/'+name+'/metrics',secrets.token_urlsafe(32),uid,gid)
        # Collection is disabled. The trust material remains generated fixture
        # material and is never an issuer trust source for a real passport.
        csca,csca_key=certificate(self.pki,'csca','DNS:synthetic.example.invalid')
        self.file('services/verifier/csca.pem',csca.read_bytes(),10001,20010)
        # A valid, empty synthetic CRL avoids hiding a broken file behind the
        # closed collection flag. It never validates a real issuing authority.
        index=self.pki/'index.txt';index.touch();(self.pki/'crlnumber').write_text('01\n')
        ca_config=self.pki/'ca.conf'
        ca_config.write_text('[ca]\ndefault_ca=synthetic\n[synthetic]\ndatabase='+str(index)+
            '\ncertificate='+str(csca)+'\nprivate_key='+str(csca_key)+'\ncrlnumber='+str(self.pki/'crlnumber')+
            '\ndefault_md=sha256\ndefault_crl_days=1\n')
        crl=command(['openssl','ca','-gencrl','-config',str(ca_config)])
        self.file('services/verifier/csca.crl',crl,10001,20010)
        check.check_directory(self.root)
        self.start_ingress()
        self.phase('start_canonical_ten_service_profile')
        self.dc('up','-d','--wait','--wait-timeout','180')
        from postgres_continuity import ControllerClient
        self.controller=ControllerClient(str(self.root/'ipc/continuity/continuity.sock'),REFERENCE)
        class Remote:
            def complete(_,intent):
                for _ in range(100):
                    result=self.controller.advance(intent)
                    if result['completed']:return result
                raise ValueError('synthetic activation timeout')
        self.model.controller=Remote()
        for wallet in (self.model.wallet,self.model.enroller,self.model.registry,self.model.contact,self.model.bridge_wallet):wallet.revocation=self.controller

    def bao(self,path,data=None,method=None):
        headers={'Content-Type':'application/json'}
        if self.bao_root:headers['X-Vault-Token']=self.bao_root
        request=urllib.request.Request('https://127.0.0.1:18210/v1/'+path,data=None if data is None else json.dumps(data).encode(),
                                      headers=headers,method=method)
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=self.bao_context))
        with opener.open(request,timeout=5) as response:raw=response.read()
        return json.loads(raw) if raw else {}

    def start_ingress(self):
        from ingress import render
        configuration=render(json.loads((self.root/'services/verifier/runtime.json').read_text()),
                             json.loads((self.root/'origins.json').read_text()))
        replacements={
            'listen 443 ssl':'listen 127.0.0.1:443 ssl','listen 80 default_server':'listen 127.0.0.1:18080 default_server',
            '/etc/letsencrypt/live/tjipp/fullchain.pem':str(self.pki/'ingress.crt'),
            '/etc/letsencrypt/live/tjipp/privkey.pem':str(self.pki/'ingress.key'),
            '/etc/nginx/tjipp-idp-tls.crt':str(self.root/'public/idp.pem'),
            '/etc/nginx/tjipp-sp-tls.crt':str(self.root/'public/sp.pem'),
            '/etc/nginx/tjipp-api-tls.crt':str(self.root/'services/verifier/server.pem'),
            '/etc/nginx/tjipp-wallet-tls.crt':str(self.root/'services/wallet/server.pem'),
            '/var/log/nginx/tjipp-error.log':str(self.root/'nginx-error.log'),
            '/var/www/tjipp-acme':str(self.root/'public'),'/var/www/tjipp':str(self.root/'public')}
        for source,target in replacements.items():configuration=configuration.replace(source,target)
        prefix='daemon off; pid '+str(self.root/'nginx.pid')+'; error_log '+str(self.root/'nginx-error.log')+'; events {} http { access_log off;\n'
        prefix+=''.join(kind+'_temp_path '+str(self.root/('nginx-'+kind))+';\n' for kind in ('client_body','proxy','fastcgi','uwsgi','scgi'))
        path=self.root/'nginx.conf';path.write_text(prefix+configuration+'\n}')
        invocation=['nginx','-p',str(self.root),'-c',str(path)]
        command(invocation+['-t'])
        log=self.resources.enter_context(open(self.root/'nginx-process.log','wb'))
        process=subprocess.Popen(invocation,stdout=log,stderr=log)
        def stop():
            if process.poll() is None:process.terminate();process.wait(timeout=10)
        self.resources.callback(stop)
        self.report['ingress']={'implementation':'nginx','version':subprocess.run(['nginx','-v'],capture_output=True,text=True,check=True).stderr.strip(),
                                'templateSHA256':__import__('hashlib').sha256((ROOT/'deployment/production/nginx.conf.in').read_bytes()).hexdigest()}

    def api(self,path,body,*,native=False,direct=False):
        name='verifier' if native else 'wallet'
        context=ssl.create_default_context(cafile=str(self.root/'services'/name/'server.pem')) if direct else self.fixture.public_tls
        connection=http.client.HTTPSConnection('localhost' if direct else 'api.example.test',
            (8767 if native else 8768) if direct else 443,context=context,timeout=8)
        try:
            connection.request('POST',path,json.dumps(body),{'Host':'api.example.test','Origin':'https://api.example.test',
                'Content-Type':'application/json','X-CSRF-Token':self.pairing,
                'X-OpenID-Client-IP':'192.0.2.10'})
            response=connection.getresponse();return response.status,json.loads(response.read())
        finally:connection.close()

    def client(self):
        return urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=self.fixture.public_tls),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def web(self,client,url,fields=None):
        request=urllib.request.Request(url,data=None if fields is None else urllib.parse.urlencode(fields).encode(),
            headers={} if fields is None else {'Origin':'https://idp.example.test'})
        try:response=client.open(request,timeout=15)
        except urllib.error.HTTPError as error:response=error
        return response.status,response.read(),response.url

    def approval(self,key,credential,action,request_id=None):
        from test_wallet import crypt
        status,challenge=self.api('/wallet/challenge',{'credentialId':credential,'action':action,'requestId':request_id})
        if status!=200:raise ValueError('synthetic approval challenge denied')
        signed={'challengeId':challenge['id'],'signature':crypt(op='sign',key=key['privateKey'],payload=challenge['signingInput'])}
        status,result=self.api('/wallet/execute',signed)
        if status!=200:raise ValueError('synthetic signed action denied')
        return result

    def begin(self,path='/login'):
        client=self.client();status,body,_=self.web(client,'https://sp.example.test'+path)
        if status!=200:raise ValueError('synthetic federation request denied')
        html=body.decode();request=re.search(r'openid://request/([a-f0-9]{64})',html)
        if request is None:raise ValueError('synthetic consent request missing')
        form=next(f for f in Forms(html).forms if f['action']=='/phone/complete')
        return client,request.group(1),form['fields']

    def finish(self,client,fields):
        status,body,url=self.web(client,'https://idp.example.test/phone/complete',fields)
        for form in Forms(body.decode()).forms:
            if 'SAMLResponse' in form['fields']:return self.web(client,form['action'],form['fields'])
        return status,body,url

    def inspect_boundaries(self):
        from contract import LIMITS,MOUNTS,GROUPS
        report=[]
        for name,identity in IDENTITIES.items():
            info=json.loads(command(['docker','inspect',self.container(name)]))[0]
            uid,gid=map(int,identity.split(':'))
            assert info['Config']['User']==identity and info['State']['Running'],'service identity or liveness changed'
            assert info['Image']==(VENDORS[name]['id'] if name in VENDORS else self.image),'running image differs'
            host=info['HostConfig']
            assert host['NetworkMode']=='host' and host['ReadonlyRootfs'] is True,'runtime boundary changed'
            assert host['CapDrop']==['ALL'] and (host['CapAdd'] or [])==(['CHOWN'] if name=='credential-rotator' else []),'capability boundary changed'
            assert 'no-new-privileges:true' in host['SecurityOpt'],'privilege escalation protection missing'
            memory,cpu=LIMITS[name]
            assert host['Memory']==host['MemorySwap']==memory*1024*1024,'memory or swap differs'
            assert host['NanoCpus']==int(cpu*1_000_000_000),'CPU boundary changed'
            ulimits={value['Name']:(value['Soft'],value['Hard']) for value in host['Ulimits']}
            assert ulimits=={'core':(0,0),'nofile':(1024,1024)},'running core dump or file descriptor limits changed'
            status=Path('/proc')/str(info['State']['Pid'])/'status'
            fields=dict(line.split(':',1) for line in status.read_text().splitlines() if ':' in line)
            assert int(fields['Uid'].split()[1])==uid and int(fields['Gid'].split()[1])==gid,'host identity remapping unsupported'
            observed_groups=set(map(int,fields['Groups'].split()));allowed_groups={gid,*map(int,GROUPS.get(name,[]))}
            assert set(map(int,GROUPS.get(name,[])))<=observed_groups<=allowed_groups,'unexpected supplementary group'
            assert int(fields['NoNewPrivs'])==1 and int(fields['CapEff'],16)==(1 if name=='credential-rotator' else 0),'effective process privilege differs'
            expected=MOUNTS[name]
            for mount in info['Mounts']:
                if mount['Destination'] in expected:
                    source,ro=expected[mount['Destination']]
                    assert mount['Source']==str(self.root/source) and mount['RW'] is not ro,'running mount differs'
            if name not in VENDORS:
                script='from pathlib import Path;import sys\ntry:Path("/srv/openid/aws/session.json").read_bytes()\nexcept (PermissionError,FileNotFoundError):sys.exit(17)\nsys.exit(0)'
                result=subprocess.run(['docker','exec',self.container(name),'python','-c',script],capture_output=True,timeout=5)
                assert result.returncode==(0 if name in ('continuity','notice-exporter') else 17),'cloud session mount boundary failed'
            if uid:
                # The fixture's parent is traversable. Denial must come from
                # the real delivery directory/file, not a fixture ancestor.
                for owner in ('continuity','notices'):
                    script='from pathlib import Path;import sys\ntry:Path('+repr(str(self.root/'aws'/owner/'session.json'))+').read_bytes()\nexcept PermissionError:sys.exit(17)\nsys.exit(0)'
                    groups='--groups='+','.join(map(str,GROUPS.get(name,[]))) if GROUPS.get(name) else '--clear-groups'
                    result=subprocess.run(['setpriv','--reuid='+str(uid),'--regid='+str(gid),groups,'--no-new-privs',
                        '--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','/usr/bin/python3','-c',script],capture_output=True,timeout=5)
                    owns=(name=='continuity' and owner=='continuity') or (name=='notice-exporter' and owner=='notices')
                    assert result.returncode==(0 if owns else 17),'per-UID cloud session ownership failed'
                for family,address in [(socket.AF_INET,'169.254.169.254'),(socket.AF_INET6,'fd00:ec2::254')]:
                    script='import socket,sys;s=socket.socket('+str(int(family))+',socket.SOCK_STREAM);s.settimeout(2)\ntry:s.connect(('+repr(address)+',80))\nexcept OSError:sys.exit(0)\nsys.exit(3)'
                    result=subprocess.run(['setpriv','--reuid='+str(uid),'--regid='+str(gid),'--clear-groups','--no-new-privs',
                        '--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','/usr/bin/python3','-c',script],capture_output=True,timeout=5)
                    assert result.returncode==0,'non-root service can reach synthetic IMDS'
            report.append({'service':name,'uid':uid,'gid':gid,'actual_container_inspected':True,
                           'imds_ipv4':'blocked' if uid else 'trusted_rotator','imds_ipv6':'blocked' if uid else 'trusted_rotator'})
        return report

    def run(self):
        from test_wallet import crypt
        from test_identity import document
        self.phase('inspect_actual_service_boundaries')
        report=self.report
        report.update({'schema':'tjipp-production-composition-v1','status':'RUNNING','synthetic':True,'productionApproved':False,
            'externalConformance':False,'awsScope':'local TLS/SigV4 STS/Lambda/SQS and IMDSv2 fixtures; no AWS account calls',
            'overlayScope':'synthetic DNS/PKI plus loopback nginx listener and fixture file paths; canonical routes, verified upstream TLS, code/images/roles/mount boundaries retained',
            'sourceRevision':command(['git','rev-parse','HEAD'],cwd=ROOT).strip(),
            'applicationImage':self.image,'vendorImages':{k:v['id'] for k,v in VENDORS.items()},'checks':[]})
        report['serviceBoundaries']=self.inspect_boundaries();report['checks'].append('actual_service_uid_gid_mount_capability_and_dual_stack_imds_isolation')
        assert self.aws.imds_v2>0,'rotator did not use IMDSv2'
        assert self.api('/native/start',{},native=True)[0]==503,'new registration unexpectedly open'
        assert self.api('/wallet/challenge',{},native=True,direct=True)[0]==404,'wallet route exposed through enroller'
        assert self.api('/native/start',{},direct=True)[0]==404,'proofing route exposed through wallet'
        report['checks'].append('closed_registration_and_separate_api_roles')
        self.phase('activate_and_deliver_opaque_notice')
        key=json.loads(crypt(op='new'));credential=self.model.enroller.enroll(key['publicKey'],document())['id']
        self.model.activate(credential)
        self.wait(lambda:len(self.aws.attempts)>=2,'opaque notice retry and receipt',seconds=40)
        assert len(self.aws.messages)==1 and len(set(self.aws.attempts))==1,'notice identity changed or duplicated'
        from notice_ipc import dispatch
        self.wait(lambda:dispatch(self.model.wallet,{'operation':'next'}) is None,'transactional outbox acknowledgement')
        report['checks'].append('actual_controller_activation_atomic_outbox_role_scoped_sqs_retry_and_ack')
        self.phase('saml_oidc_and_separate_document_consent')
        client,request,fields=self.begin();self.approval(key,credential,'approve',request)
        assert self.finish(client,fields)[0]==200 and self.web(client,'https://sp.example.test/me')[0]==200,'SAML consent failed'
        report['checks'].append('actual_pg_bridge_java_saml_signed_consent_and_session')
        oidc,request,fields=self.begin('/oidc/login');self.approval(key,credential,'approve',request)
        assert self.finish(oidc,fields)[0]==200 and self.web(oidc,'https://sp.example.test/oidc/me')[0]==200,'OIDC consent failed'
        report['checks'].append('actual_pg_bridge_java_oidc_signed_consent_and_session')
        signed,request,fields=self.begin('/test/run/sign-encrypted')
        self.approval(key,credential,'sign',request)
        status,body,url=self.finish(signed,fields)
        assert status==200 and b'SAD' in body,'document consent or validation failed'
        with signed.open(url+'/signed.pdf',timeout=15) as response:pdf=response.read()
        assert pdf.startswith(b'%PDF-') and b'/ETSI.CAdES.detached' in pdf and b'/ByteRange' in pdf,'signed PDF missing'
        report['checks'].append('actual_separate_sign_message_sad_and_test_ca_pades')
        self.phase('authority_outage_and_service_restart')
        self.aws.authority.outage=True
        try:assert self.web(client,'https://sp.example.test/me')[0]!=200,'authority outage fell back to local ACTIVE'
        finally:self.aws.authority.outage=False
        # Restart with the same data, configuration and keys. No fixture rebuild.
        self.dc('restart','bridge','wallet','continuity')
        self.wait(lambda:all(json.loads(command(['docker','inspect',self.container(name)]))[0]['State'].get('Health',{}).get('Status')=='healthy'
                            for name in ('bridge','wallet','continuity')),'shared restart')
        assert len(self.aws.messages)==1,'notice replayed with a new event'
        report['checks'].append('same_configuration_data_and_keys_after_service_restart')
        self.phase('sealed_key_service_restart_and_external_revocation')
        self.dc('restart','openbao')
        self.wait(lambda:self.bao('sys/seal-status',method='GET')['sealed'] is True,'sealed key-service restart')
        assert self.web(client,'https://sp.example.test/me')[0]!=200,'sealed key service left a live session'
        # A remote security action bypasses the principal database entirely.
        # Keep local ACTIVE so the last checks specifically prove the external
        # decision survives, rather than a local state change hiding a failure.
        self.model.synthetic.authority.revoke(credential)
        for share in self.unseal_keys:self.bao('sys/unseal',{'key':share})
        self.wait(lambda:self.bao('sys/seal-status',method='GET')['sealed'] is False,'key-service unseal')
        assert self.web(client,'https://sp.example.test/me')[0]!=200,'external revocation lost across key-service outage'
        assert self.web(oidc,'https://sp.example.test/oidc/me')[0]!=200,'OIDC session survived external revocation'
        with self.model.wallet.transaction() as db:assert db.execute('SELECT state FROM credentials WHERE id=?',(credential,)).fetchone()[0]=='ACTIVE','fixture did not isolate external revocation'
        report['checks'].append('sealed_openbao_and_external_revocation_survive_restart_without_local_active_fallback')
        assert ('HOST','sts') in self.aws.signed_calls and ('CONTINUITY','lambda') in self.aws.signed_calls and ('NOTICES','sqs') in self.aws.signed_calls,'dedicated role use not established'
        report['signedCallCounts']={service:sum(s==service for _,s in self.aws.signed_calls) for service in ('sts','lambda','sqs')}
        for name in IDENTITIES:
            logs=command(['docker','logs',self.container(name)])
            assert 'ALICE' not in logs and '900101' not in logs,'synthetic identity entered service logs'
        report['checks'].append('synthetic_identity_absent_from_service_logs')
        self.phase('complete')
        report['status']='PASS';return report

    def close(self):
        if self.children_started:
            try:self.dc('down','--remove-orphans','--timeout','70')
            except Exception:pass
            self.children_started=False
        self.resources.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image',required=True);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();runtime=None;report={'schema':'tjipp-production-composition-v1','status':'FAILED','synthetic':True,'productionApproved':False}
    try:
        runtime=Runtime(args.image,report);report=runtime.run();return_code=0
    except Exception as error:
        report['status']='FAILED';report['failureType']=type(error).__name__;return_code=1
        if isinstance(error,CommandFailure):report['failedCommand']=error.detail
        if isinstance(error,AssertionError):report['assertion']=str(error)
        if runtime is not None:
            runtime.diagnostics()
    finally:
        if runtime is not None:runtime.close()
        args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
    print('Synthetic canonical runtime: '+report['status']+'; formal approval is false.')
    return return_code


if __name__=='__main__':sys.exit(main())
