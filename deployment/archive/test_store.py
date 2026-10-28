"""Offline AWS contract and negative delivery tests; never use live credentials."""
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout,redirect_stderr

sys.path.insert(0,str(Path(__file__).resolve().parent))
import store
from template import template

CFG = {'bucket':'openid-synthetic-archive','owner':'111111111111','issuer':'222222222222',
       'custodianRole':'arn:aws:iam::111111111111:role/ArchiveCustodian',
       'region':'eu-north-1','prefix':'openid-archive','days':1827}
NOW = datetime(2026,10,24,12,tzinfo=timezone.utc)


class STS:
    def __init__(self,owner=False):self.owner=owner
    def get_caller_identity(self):
        account=CFG['owner'] if self.owner else CFG['issuer']
        role='ArchiveCustodian' if self.owner else 'IssuerArchiveWriter'
        return {'Account':account,'Arn':f'arn:aws:sts::{account}:assumed-role/{role}/synthetic'}


class S3:
    """Version-preserving storage double. IAM itself is checked in template tests."""
    def __init__(self):
        self.objects={};self.calls=[];self.bodies=[];self.mode='COMPLIANCE';self.versioning='Enabled'
        self.transform=lambda response:response
        self.public_block=True;self.receipt_guard=True
    def metadata(self,kwargs):
        assert kwargs['ExpectedBucketOwner']==CFG['owner']
        assert kwargs['Bucket']==CFG['bucket']
    def get_bucket_location(self,**kwargs):self.metadata(kwargs);return {'LocationConstraint':'eu-north-1'}
    def get_bucket_versioning(self,**kwargs):self.metadata(kwargs);return {'Status':self.versioning}
    def get_public_access_block(self,**kwargs):
        self.metadata(kwargs)
        return {'PublicAccessBlockConfiguration':{k:self.public_block for k in
            ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')}}
    def get_bucket_ownership_controls(self,**kwargs):
        self.metadata(kwargs);return {'OwnershipControls':{'Rules':[{'ObjectOwnership':'BucketOwnerEnforced'}]}}
    def get_bucket_policy(self,**kwargs):
        self.metadata(kwargs)
        statement={'Effect':'Deny','Principal':'*','Action':['s3:PutObject','s3:PutObjectRetention'],
            'Resource':'arn:aws:s3:::'+CFG['bucket']+'/'+CFG['prefix']+'/receipts/*',
            'Condition':{'ArnNotEquals':{'aws:PrincipalArn':CFG['custodianRole']}}}
        return {'Policy':store.archive.encoded({'Statement':[statement] if self.receipt_guard else []}).decode()}
    def get_object_lock_configuration(self,**kwargs):
        self.metadata(kwargs)
        return {'ObjectLockConfiguration':{'ObjectLockEnabled':'Enabled','Rule':{'DefaultRetention':{'Mode':self.mode,'Days':1827}}}}
    def put_object(self,**kwargs):
        self.metadata(kwargs);assert kwargs['IfNoneMatch']=='*';assert kwargs['ObjectLockMode']=='COMPLIANCE'
        self.calls.append(kwargs['Key'])
        data=kwargs['Body'].read();assert len(data)==kwargs['ContentLength']
        assert base64.b64encode(hashlib.sha256(data).digest()).decode()==kwargs['ChecksumSHA256']
        ident='version-'+str(len(self.objects)+1)
        self.objects[kwargs['Key'],ident]=(data,kwargs['ObjectLockRetainUntilDate'])
        return {'VersionId':ident}
    def get_object(self,**kwargs):
        self.metadata(kwargs)
        data,until=self.objects[kwargs['Key'],kwargs['VersionId']]
        body=io.BytesIO(data);self.bodies.append(body)
        return self.transform({'Body':body,'VersionId':kwargs['VersionId'],'ContentLength':len(data),
            'ServerSideEncryption':'AES256','ObjectLockMode':'COMPLIANCE','ObjectLockRetainUntilDate':until})


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.source=self.root/'archive';self.source.mkdir(mode=0o700)
        files={}
        rows={'credentials':[['credential','public','ACTIVE',1000,2000,'REVIEW-synthetic']],
              'profiles':[['credential','proof',1000,3000]],'events':[[1,'credential','ACTIVATED',1000,None]]}
        for name, values in rows.items():
            raw=b''.join(store.archive.encoded(v) for v in values)
            store.archive.write_file(self.source/(name+'.jsonl'),raw)
            files[name+'.jsonl']={'columns':list(store.archive.TABLES[name]),'rows':len(values),
                'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        manifest=store.archive.encoded({'format':1,'backend':'sqlite','source_revision':'a'*40,
            'snapshot':{'database_schema':None,'read_at':NOW.isoformat()},'files':files})
        store.archive.write_file(self.source/'manifest.json',manifest)
        self.digest=hashlib.sha256(manifest).hexdigest();self.s3=S3()
    def deliver(self):return store.deliver(self.source,self.digest,CFG,self.s3,STS(),now=NOW)
    def confirm(self,delivery):return store.confirm(delivery,self.digest,CFG,self.s3,STS(True),now=NOW)

    def test_full_delivery_custodian_confirmation_and_later_readback(self):
        delivery=self.deliver()
        self.assertEqual('DELIVERY',delivery['kind'])
        self.assertFalse(any('/receipts/' in key for key in self.s3.calls))
        location=self.confirm(delivery)
        result=store.check(location,self.digest,CFG,self.s3,STS(True),now=NOW+timedelta(days=30))
        self.assertEqual('READABLE',result['state']);self.assertEqual(3,result['rows'])
        self.assertTrue(all(body.closed for body in self.s3.bodies))
        self.assertTrue(self.s3.calls[-1].startswith(CFG['prefix']+'/receipts/'+self.digest+'/'))

    def test_v2_journal_delivery_receipt_readback_and_retention_boundary(self):
        baseline = store.required_until(self.source, CFG, NOW)
        policy = {'version': 1, 'reference': 'TEST_POLICY_001', 'profileDays': 7,
                  'authenticationRequestDays': 1}
        policy_hash = hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        counts = json.dumps(dict(profiles=1, security_codes=1, requests=0, federation_requests=0))
        row = [1, int((NOW+timedelta(hours=48)).timestamp()), policy['reference'], policy_hash, 7, 1, counts]
        path = self.source/'retention_runs.jsonl'; raw = store.archive.encoded(row)
        store.archive.write_file(path, raw)
        manifest_path = self.source/'manifest.json'; manifest = json.loads(manifest_path.read_bytes())
        manifest['format'] = 2
        manifest['files'][path.name] = {'columns': list(store.archive.TABLES['retention_runs']),
            'rows': 1, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        raw_manifest = store.archive.encoded(manifest); manifest_path.write_bytes(raw_manifest)
        self.digest = hashlib.sha256(raw_manifest).hexdigest()
        self.assertGreater(store.required_until(self.source, CFG, NOW), baseline)
        location = self.confirm(self.deliver())
        result = store.check(location, self.digest, CFG, self.s3, STS(True), now=NOW+timedelta(days=30))
        self.assertEqual('READABLE', result['state']); self.assertEqual(4, result['rows'])
        self.assertTrue(any(key.endswith('/retention_runs.jsonl') for key in self.s3.calls))
        row[1] = int((NOW+timedelta(hours=73)).timestamp()); path.write_bytes(store.archive.encoded(row))
        with self.assertRaisesRegex(ValueError, 'future register time'):
            store.required_until(self.source, CFG, NOW)

    def test_issuer_cannot_confirm_or_check_and_wrong_account_cannot_upload(self):
        delivery=self.deliver()
        with self.assertRaises(ValueError):store.confirm(delivery,self.digest,CFG,self.s3,STS(),now=NOW)
        self.assertEqual(4,len(self.s3.calls))
        with self.assertRaises(ValueError):store.deliver(self.source,self.digest,CFG,self.s3,STS(True),now=NOW)
        location=self.confirm(delivery)
        with self.assertRaises(ValueError):store.check(location,self.digest,CFG,self.s3,STS(),now=NOW)

    def test_v4_consent_journal_delivery_and_withdrawal_retention_boundary(self):
        from consent_retention import TABLES
        from enrollment_policy import canonical
        baseline=store.required_until(self.source,CFG,NOW)
        config={'version':1,'reference':'SYNTHETIC_RETENTION_001','regime':'private-beta',
            'unboundDays':7,'boundDays':7,'protectedReceipts':[]}
        raw_policy=canonical(config).decode()
        receipt=['a'*64,'b'*64,'c'*64,int(NOW.timestamp()),'SYNTHETIC_PROOF',int((NOW+timedelta(hours=48)).timestamp())]
        journal=[1,int((NOW+timedelta(hours=36)).timestamp()),raw_policy,
            hashlib.sha256(raw_policy.encode()).hexdigest(),canonical(dict.fromkeys(TABLES,0)).decode()]
        extra={'retention_runs':[],'enrollment_policies':[],'enrollment_consents':[receipt],
            'credential_consents':[],'consent_retention_runs':[journal]}
        manifest_path=self.source/'manifest.json';manifest=json.loads(manifest_path.read_bytes())
        manifest['format']=4
        for name,values in extra.items():
            raw=b''.join(store.archive.encoded(row) for row in values)
            path=self.source/(name+'.jsonl');store.archive.write_file(path,raw)
            manifest['files'][path.name]={'columns':list(store.archive.TABLES[name]),'rows':len(values),
                'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        raw_manifest=store.archive.encoded(manifest);manifest_path.write_bytes(raw_manifest)
        self.digest=hashlib.sha256(raw_manifest).hexdigest()
        self.assertGreater(store.required_until(self.source,CFG,NOW),baseline)
        location=self.confirm(self.deliver())
        self.assertEqual(5,store.check(location,self.digest,CFG,self.s3,STS(True),now=NOW+timedelta(days=30))['rows'])
        for name,row,indexes in (('enrollment_consents',receipt,(3,5)),('consent_retention_runs',journal,(1,))):
            path=self.source/(name+'.jsonl');original=path.read_bytes()
            for index in indexes:
                future=list(row);future[index]=int((NOW+timedelta(hours=100)).timestamp())
                path.write_bytes(store.archive.encoded(future))
                with self.assertRaisesRegex(ValueError,'future register time'):store.required_until(self.source,CFG,NOW)
                path.write_bytes(original)

    def test_wrong_custodian_role_is_not_accepted(self):
        cfg=CFG|{'custodianRole':'arn:aws:iam::111111111111:role/OtherCustodian'}
        with self.assertRaises(ValueError):store.confirm(self.deliver(),self.digest,cfg,self.s3,STS(True),now=NOW)

    def test_missing_versioning_or_governance_only_lock_prevents_upload(self):
        for versioning,mode in [('Suspended','COMPLIANCE'),('Enabled','GOVERNANCE')]:
            self.s3.versioning=versioning;self.s3.mode=mode
            with self.assertRaises(ValueError):self.deliver()
        self.assertEqual([],self.s3.calls)

    def test_public_storage_is_rejected_before_any_upload(self):
        self.s3.public_block=False
        with self.assertRaises(ValueError):self.deliver()
        self.assertEqual([],self.s3.calls)

    def test_live_policy_drift_prevents_confirmation_and_later_check(self):
        delivery=self.deliver();self.s3.receipt_guard=False
        with self.assertRaises(ValueError):self.confirm(delivery)
        self.assertFalse(any('/receipts/' in k for k in self.s3.calls))
        self.s3.receipt_guard=True;location=self.confirm(delivery);self.s3.receipt_guard=False
        with self.assertRaises(ValueError):store.check(location,self.digest,CFG,self.s3,STS(True),now=NOW)

    def test_failed_readback_never_publishes_receipt_and_always_closes_stream(self):
        delivery=self.deliver()
        key,ident=next(iter(self.s3.objects));data,until=self.s3.objects[key,ident]
        self.s3.objects[key,ident]=(data.replace(b'ACTIVE',b'FORGED'),until)
        with self.assertRaises(ValueError):self.confirm(delivery)
        self.assertFalse(any('/receipts/' in key for key in self.s3.calls))
        self.assertTrue(all(body.closed for body in self.s3.bodies))

    def test_short_retention_wrong_version_or_encryption_are_rejected(self):
        delivery=self.deliver()
        for change in ({'ObjectLockMode':'GOVERNANCE'},{'ObjectLockRetainUntilDate':NOW},
                       {'VersionId':'wrong'},{'ServerSideEncryption':'aws:kms'},{'ContentLength':0}):
            self.s3.transform=lambda response:response|change
            with self.subTest(change=change),self.assertRaises(ValueError):self.confirm(delivery)
        self.assertFalse(any('/receipts/' in key for key in self.s3.calls))
        self.assertTrue(all(body.closed for body in self.s3.bodies))

    def test_delivery_and_receipt_binding_tampering_is_rejected(self):
        delivery=self.deliver()
        for field,value in [('owner','333333333333'),('manifestSha256','b'*64),('transfer','../escape')]:
            with self.subTest(field=field),self.assertRaises(ValueError):self.confirm(delivery|{field:value})
        location=self.confirm(delivery)
        for change in ({'key':'openid-archive/transfers/not-a-receipt'}, {'manifestSha256':'b'*64},
                       {'sha256':'b'*64},{'version':'null'}):
            with self.subTest(change=change),self.assertRaises((ValueError,KeyError)):
                store.check(location|change,self.digest,CFG,self.s3,STS(True),now=NOW)

    def test_last_credential_validity_extends_retention_and_future_time_is_refused(self):
        columns=store.archive.TABLES['credentials'];path=self.source/'credentials.jsonl'
        values=store.archive.decode(path.read_bytes());values[columns.index('expires')]=int((NOW+timedelta(hours=72)).timestamp())
        path.write_bytes(store.archive.encoded(values))
        self.assertGreater(store.required_until(self.source,CFG,NOW),NOW+timedelta(days=1829))
        values[columns.index('expires')]=int((NOW+timedelta(days=100)).timestamp());path.write_bytes(store.archive.encoded(values))
        with self.assertRaises(ValueError):store.required_until(self.source,CFG,NOW)

    def test_expired_receipt_or_delayed_confirmation_does_not_count_as_valid(self):
        delivery=self.deliver();location=self.confirm(delivery)
        with self.assertRaises(ValueError):store.check(location,self.digest,CFG,self.s3,STS(True),now=NOW+timedelta(days=1830))
        with self.assertRaises(ValueError):store.confirm(delivery,self.digest,CFG,self.s3,STS(True),now=NOW+timedelta(days=5))

    def test_account_separation_and_retention_are_mandatory(self):
        for change in ({'owner':CFG['issuer']},{'days':1},{'days':True},{'region':'us-east-1'}):
            with self.subTest(change=change),self.assertRaises(ValueError):store.config(CFG|change)

    def test_cloudformation_retention_separation_and_deletion_guards(self):
        stack=template();bucket=stack['Resources']['Archive'];props=bucket['Properties']
        self.assertEqual('Retain',bucket['DeletionPolicy']);self.assertEqual('Retain',bucket['UpdateReplacePolicy'])
        self.assertTrue(all(props['PublicAccessBlockConfiguration'].values()))
        self.assertTrue(props['ObjectLockEnabled']);self.assertEqual('Enabled',props['VersioningConfiguration']['Status'])
        self.assertEqual('BucketOwnerEnforced',props['OwnershipControls']['Rules'][0]['ObjectOwnership'])
        statements={s['Sid']:s for s in stack['Resources']['Policy']['Properties']['PolicyDocument']['Statement']}
        self.assertEqual('Deny',statements['OnlyCustodianCanReceipt']['Effect'])
        self.assertIn('s3:DeleteObjectVersion',statements['IssuerCannotDestroy']['Action'])
        self.assertNotEqual(statements['UploaderTransfer']['Resource'],statements['CustodianReceipt']['Resource'])
        self.assertEqual('COMPLIANCE',props['ObjectLockConfiguration']['Rule']['DefaultRetention']['Mode'])

    def test_botocore_validates_exact_put_and_version_pinned_read_contract(self):
        import boto3
        from botocore.response import StreamingBody
        from botocore.stub import Stubber
        from botocore.config import Config
        client=boto3.client('s3',region_name='eu-north-1',aws_access_key_id='synthetic',
            aws_secret_access_key='synthetic',config=Config(ignore_configured_endpoint_urls=True))
        data=b'synthetic';sha=hashlib.sha256(data).hexdigest();until=NOW+timedelta(days=1829)
        body=io.BytesIO(data);key='openid-archive/transfers/synthetic'
        with Stubber(client) as stub:
            stub.add_response('put_object',{'VersionId':'version-1'},{'Bucket':CFG['bucket'],'Key':key,
                'Body':body,'ContentLength':len(data),'ExpectedBucketOwner':CFG['owner'],'IfNoneMatch':'*',
                'ServerSideEncryption':'AES256','ChecksumAlgorithm':'SHA256',
                'ChecksumSHA256':base64.b64encode(bytes.fromhex(sha)).decode(),
                'ObjectLockMode':'COMPLIANCE','ObjectLockRetainUntilDate':until})
            stub.add_response('get_object',{'VersionId':'version-1','ContentLength':len(data),
                'ServerSideEncryption':'AES256','ObjectLockMode':'COMPLIANCE','ObjectLockRetainUntilDate':until,
                'Body':StreamingBody(io.BytesIO(data),len(data))},
                {'Bucket':CFG['bucket'],'Key':key,'VersionId':'version-1','ExpectedBucketOwner':CFG['owner']})
            self.assertEqual('version-1',store.put(client,CFG,key,body,len(data),sha,until))
            stub.assert_no_pending_responses()

    def test_cli_deliver_confirm_check_and_existing_output_are_safe(self):
        config_path=self.root/'config.json';store.archive.write_file(config_path,store.archive.encoded(CFG))
        class Session:
            owner=False
            def client(inner,name,config):
                self.assertTrue(config.ignore_configured_endpoint_urls)
                self.assertEqual('s3v4' if name=='s3' else 'v4',config.signature_version)
                return self.s3 if name=='s3' else STS(inner.owner)
        session=Session()
        def run(operation,source,output):
            arguments=['store.py',operation,'--config',str(config_path),'--source',str(source),
                       '--manifest-sha256',self.digest,'--output',str(output)]
            with patch.object(sys,'argv',arguments),patch('boto3.Session',return_value=session),redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
                return store.main()
        delivery=self.root/'delivery.json';receipt=self.root/'receipt.json';checked=self.root/'check.json'
        self.assertEqual(0,run('deliver',self.source,delivery))
        count=len(self.s3.calls)
        self.assertEqual(2,run('deliver',self.source,delivery));self.assertEqual(count,len(self.s3.calls))
        self.assertEqual(2,run('confirm',delivery,receipt));self.assertFalse(receipt.exists())
        session.owner=True
        self.assertEqual(0,run('confirm',delivery,receipt))
        self.assertEqual(0,run('check',receipt,checked))
        self.assertEqual('READABLE',store.archive.decode(checked.read_bytes())['state'])
        for path in (delivery,receipt,checked):self.assertEqual(0o600,path.stat().st_mode&0o777)


if __name__ == '__main__':unittest.main()
