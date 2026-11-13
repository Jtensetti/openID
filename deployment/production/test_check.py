import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
import check
from contract import VENDORS
ROOT=Path(__file__).resolve().parent
IMAGE='sha256:'+'a'*64
DIRECTORY=str(Path('/tmp/tjipp-config-test').resolve())

def values():
    return {key:check.example(file) for key,file in {
        'verifier':'runtime.example.json','wallet':'wallet.example.json','bridge':'bridge.example.json',
        'continuity':'controller.example.json','client':'controller-client.example.json','authority':'continuity.example.json',
        'rotation':'credential-rotate.example.json','openbao':'openbao.example.json','federation':'federation.example.json'
    }.items()}|{'origins':{'idp':'https://idp.example.org','sp':'https://sp.example.org'}}

class SettingsTests(unittest.TestCase):
    def test_closed_coherent_services(self):check.check_values(values())

    def test_open_registration_development_wrong_worker_or_proxy_rejected(self):
        for key,value in [('newRegistrationsEnabled',True),('developmentAttestation',True),('workers',2),
                          ('trustedProxy','10.0.0.1'),('role','wallet')]:
            data=values();data['verifier'][key]=value
            with self.subTest(field=key),self.assertRaises(ValueError):check.check_values(data)

    def registration(self):
        data=values(); now=int(time.time())
        data['verifier'].update(newRegistrationsEnabled=True,enrollmentPolicyFile=check.ENROLLMENT_PATH)
        data['enrollment']={'schema':1,'decisionReference':'SYNTHETIC_DECISION_001','notice':{
            'version':'SYNTHETIC_TERMS_001','locale':'sv-SE','notBefore':now-60,'notAfter':now+600,
            'controller':'Syntetisk testoperatör','contact':'privacy@example.invalid',
            'terms':'Syntetiska testvillkor.','privacy':'Endast syntetiska uppgifter.',
            'biometrics':'Syntetiskt biometrival.','withdrawal':'Syntetisk återkallelseinformation.'}}
        return data

    def test_registration_requires_current_exact_policy_and_keeps_production_boundaries(self):
        data=self.registration();check.check_values(data)
        self.assertIn('enrollment-policy.json',check.private_files('verifier',data['verifier']))
        self.assertNotIn('enrollment-policy.json',check.private_files('wallet',data['wallet']))
        for kind in ('missing','expired','future','empty_text','no_decision','wrong_path','wrong_type','beta'):
            data=self.registration()
            if kind=='missing':del data['enrollment']
            elif kind=='expired':data['enrollment']['notice']['notAfter']=int(time.time())-1
            elif kind=='future':data['enrollment']['notice']['notBefore']=int(time.time())+60
            elif kind=='empty_text':data['enrollment']['notice']['biometrics']=''
            elif kind=='no_decision':data['enrollment']['decisionReference']=''
            elif kind=='wrong_path':data['verifier']['enrollmentPolicyFile']='/tmp/other.json'
            elif kind=='wrong_type':data['verifier']['newRegistrationsEnabled']=1
            else:data['verifier']['testBeta']=True
            with self.subTest(kind=kind),self.assertRaises(ValueError):check.check_values(data)

    def test_closed_default_rejects_stale_policy_and_policy_cannot_change_other_roles(self):
        data=self.registration();data['verifier']['newRegistrationsEnabled']=False
        with self.assertRaises(ValueError):check.check_values(data)
        data=self.registration();data['wallet']['enrollmentPolicyFile']=check.ENROLLMENT_PATH
        with self.assertRaises(ValueError):check.check_values(data)

    def test_policy_file_has_separate_size_limit_and_rejects_duplicate_fields_and_links(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'policy.json'; value=self.registration()['enrollment']
            value['notice']['privacy']='x'*20000;path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):check.private_json(path)
            self.assertEqual(value,check.private_json(path,65536))
            with self.assertRaises(ValueError):check.enrollment_policy(value)
            path.write_text('{"schema":1,"schema":1}')
            with self.assertRaises(ValueError):check.private_json(path,65536)
            path.write_text('{}');os.link(path,Path(temp)/'linked')
            with self.assertRaises(ValueError):check.private_json(path,65536)

    def test_separate_wallet_origin_and_service_socket_overrides_rejected(self):
        for role,key,value in [('wallet','origin','https://different.example.org'),('wallet','workers',4),
                ('bridge','noticeGroup',20001),('bridge','federationFile','/tmp/other.json'),
                ('continuity','socketGroup',20003)]:
            data=values();data[role][key]=value
            with self.subTest(role=role,field=key),self.assertRaises(ValueError):check.check_values(data)

    def test_legacy_beta_or_mismatched_authority_rejected(self):
        for change in ['beta','client','region']:
            data=values()
            if change=='beta':data['authority']['testBeta']=True
            elif change=='client':data['client']['authority']+='different'
            else:data['authority']['region']='us-east-1'
            with self.subTest(change=change),self.assertRaises(ValueError):check.check_values(data)

    def test_shared_or_cross_account_aws_role_rejected(self):
        for change in ['shared','source','account']:
            data=values()
            if change=='shared':data['rotation']['roles']['notices']=data['rotation']['roles']['continuity']
            elif change=='source':data['rotation']['sourceRoleArn']=data['rotation']['roles']['continuity']
            else:data['rotation']['roles']['notices']=data['rotation']['roles']['notices'].replace('000000000000','111111111111')
            with self.subTest(change=change),self.assertRaises(ValueError):check.check_values(data)

    def test_dev_bao_unencrypted_listener_or_profile_ambiguity_rejected(self):
        for change in ['listener','storage','profile','raw_audit']:
            data=values()
            if change=='listener':data['openbao']['listener'][0]['tcp']['tls_disable']=True
            elif change=='storage':data['openbao']['storage']={'inmem':{}}
            elif change=='profile':data['federation']['profile']='phone-init'
            else:data['openbao']['audit'][0]['file']['tjipp']['options']['log_raw']='true'
            with self.subTest(change=change),self.assertRaises(ValueError):check.check_values(data)

class ComposeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('docker'):raise unittest.SkipTest('Docker Compose is required and runs in Linux CI')
        env={**os.environ,'TJIPP_IMAGE_ID':IMAGE,'TJIPP_DIRECTORY':DIRECTORY,
             'TJIPP_POSTGRES_IMAGE_ID':VENDORS['postgres']['id'],'TJIPP_OPENBAO_IMAGE_ID':VENDORS['openbao']['id'],
             'TJIPP_NOTICE_QUEUE_URL':'https://sqs.eu-north-1.amazonaws.com/000000000000/synthetic'}
        cls.original=json.loads(subprocess.check_output(['docker','compose','-f',str(ROOT/'compose.yaml'),'config','--format','json'],env=env,text=True))
    def setUp(self):self.data=copy.deepcopy(self.original)
    def check(self):check.check_compose(self.data,IMAGE,DIRECTORY)
    def test_actual_rendered_complete_compose(self):self.check()
    def test_wrong_service_uid_root_or_shared_group_rejected(self):
        for role,key,value in [('postgres','user','0:0'),('openbao','user','0:0'),('wallet','user','10001:20010'),
                               ('bridge','group_add',['20003']),('credential-rotator','cap_add',['SYS_ADMIN'])]:
            self.data=copy.deepcopy(self.original);self.data['services'][role][key]=value
            with self.subTest(role=role),self.assertRaises(ValueError):self.check()
    def test_cross_credential_data_or_code_overlay_rejected(self):
        for role,target in [('notice-exporter','/srv/openid/aws'),('wallet','/srv/openid/service'),('credential-rotator','/srv/openid/service')]:
            self.data=copy.deepcopy(self.original)
            next(v for v in self.data['services'][role]['volumes'] if v['target']==target)['source']=DIRECTORY+'/services/continuity'
            with self.subTest(role=role),self.assertRaises(ValueError):self.check()
        self.data=copy.deepcopy(self.original)
        self.data['services']['idp']['volumes'].append({'type':'bind','source':'/tmp/a','target':'/app/verification','read_only':True})
        with self.assertRaises(ValueError):self.check()
        self.data=copy.deepcopy(self.original)
        self.data['services']['postgres']['volumes'][0]['bind']['create_host_path']=True
        with self.assertRaises(ValueError):self.check()
    def test_missing_process_provider_environment_keys_or_imds_override_rejected(self):
        for role,key,value in [('continuity','OPENID_AWS_SESSION_FILE',None),('notice-exporter','AWS_ACCESS_KEY_ID','synthetic'),
                               ('verifier','AWS_EC2_METADATA_DISABLED','false'),('credential-rotator','AWS_CONTAINER_CREDENTIALS_FULL_URI','http://example.invalid')]:
            self.data=copy.deepcopy(self.original);env=self.data['services'][role]['environment']
            if value is None:del env[key]
            else:env[key]=value
            with self.subTest(role=role,key=key),self.assertRaises(ValueError):self.check()
    def test_unreviewed_image_restart_dependency_and_swap_rejected(self):
        for role,key,value in [('openbao','image','ghcr.io/openbao/openbao:latest'),('verifier','memswap_limit',-1),
                               ('bridge','entrypoint',['python','-c','pass']),('sp','healthcheck',{'test':['CMD','true']})]:
            self.data=copy.deepcopy(self.original);self.data['services'][role][key]=value
            with self.subTest(role=role,key=key),self.assertRaises(ValueError):self.check()
        self.data=copy.deepcopy(self.original);self.data['services']['wallet']['depends_on']['continuity']['condition']='service_started'
        with self.assertRaises(ValueError):self.check()

if __name__=='__main__':unittest.main()
