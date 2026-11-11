"""Synthetic STS deliveries and real SDK provider selection; no AWS requests."""
import datetime
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import aws_credential_process as consumer
import aws_credential_rotate as rotation

NOW = datetime.datetime.now(datetime.timezone.utc)


def session(letter='A', seconds=3600):
    return {'Version': 1, 'AccessKeyId': 'ASIA'+letter*16, 'SecretAccessKey': letter*40,
            'SessionToken': 'SYNTHETIC_SESSION_TOKEN_'+letter,
            'Expiration': (NOW+datetime.timedelta(seconds=seconds)).isoformat()}


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root/'session.json'
        self.path.write_text(json.dumps(session())); self.path.chmod(0o600)

    def test_private_expiring_delivery_and_metadata_boundaries(self):
        self.assertEqual(session(), consumer.load(self.path, now=NOW))
        for mode in (0o644, 0o640, 0o400):
            self.path.chmod(mode)
            with self.assertRaises(ValueError): consumer.load(self.path, now=NOW)
        self.path.chmod(0o600)
        with patch('aws_credential_process.os.geteuid', return_value=os.geteuid()+1), self.assertRaises(ValueError):
            consumer.load(self.path, now=NOW)
        linked = self.root/'linked'; linked.symlink_to(self.path)
        with self.assertRaises(OSError): consumer.load(linked, now=NOW)
        fifo = self.root/'fifo'; os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError): consumer.load(fifo, now=NOW)
        self.path.write_text('{"Version":1,"Version":1}')
        with self.assertRaises(ValueError): consumer.load(self.path, now=NOW)

    def test_no_expired_static_ambiguous_or_long_lived_credentials(self):
        values = [session(seconds=n) for n in (-1, 0, 60, 7200)]
        values += [session()|{'Version':True}, session()|{'AccessKeyId':'AKIA'+'A'*16},
                   session()|{'Expiration':NOW.replace(tzinfo=None).isoformat()}, session()|{'extra':True}]
        for value in values:
            with self.subTest(fields=list(value)), self.assertRaises(ValueError): consumer.validate(value, now=NOW)

    def test_sdk_uses_only_expiring_process_even_with_static_environment_keys(self):
        from botocore.credentials import ProcessProvider
        from aws_client import runtime_client
        class Process:
            returncode = 0
            def communicate(self): return json.dumps(session('P')).encode(), b''
        calls = []
        def provider(*args, **kwargs):
            def popen(command, **options): calls.append(command); return Process()
            return ProcessProvider(*args, **kwargs, popen=popen)
        env = {'OPENID_AWS_SESSION_FILE':'/srv/openid/aws/session.json', 'AWS_ACCESS_KEY_ID':'AKIA'+'Z'*16,
               'AWS_SECRET_ACCESS_KEY':'Z'*40, 'AWS_EC2_METADATA_DISABLED':'true',
               'AWS_CONFIG_FILE':'/dev/null','AWS_SHARED_CREDENTIALS_FILE':'/dev/null'}
        with patch.dict(os.environ,env), patch('botocore.credentials.ProcessProvider',side_effect=provider):
            client = runtime_client('lambda',read_timeout=3)
            self.addCleanup(client.close)
            credentials = client._request_signer._credentials
            self.assertEqual('custom-process',credentials.method)
            self.assertEqual(session('P')['AccessKeyId'],credentials.get_frozen_credentials().access_key)
            self.assertEqual('https://lambda.eu-north-1.amazonaws.com',client.meta.endpoint_url)
            self.assertEqual('/srv/openid/aws/session.json',calls[0][-1])

    def test_failed_process_never_falls_back_to_environment_credentials(self):
        from botocore.credentials import ProcessProvider
        from aws_client import runtime_client
        class Process:
            returncode = 2
            def communicate(self): return b'', b'Temporary AWS session unavailable.'
        def provider(*args, **kwargs): return ProcessProvider(*args, **kwargs, popen=lambda *a,**k:Process())
        env = {'OPENID_AWS_SESSION_FILE':'/srv/openid/aws/session.json','AWS_ACCESS_KEY_ID':'AKIA'+'Z'*16,
               'AWS_SECRET_ACCESS_KEY':'Z'*40,'AWS_CONFIG_FILE':'/dev/null','AWS_SHARED_CREDENTIALS_FILE':'/dev/null'}
        with patch.dict(os.environ,env), patch('botocore.credentials.ProcessProvider',side_effect=provider):
            with self.assertRaises(Exception): runtime_client('sqs',read_timeout=3)

    def test_rotator_uses_only_instance_provider_even_with_environment_keys(self):
        response = {'role_name':'SYNTHETIC_HOST','access_key':session('M')['AccessKeyId'],
                    'secret_key':session('M')['SecretAccessKey'],'token':session('M')['SessionToken'],
                    'expiry_time':session('M')['Expiration']}
        env = {'AWS_ACCESS_KEY_ID':'AKIA'+'Z'*16,'AWS_SECRET_ACCESS_KEY':'Z'*40,
               'AWS_CONFIG_FILE':'/dev/null','AWS_SHARED_CREDENTIALS_FILE':'/dev/null','AWS_EC2_METADATA_DISABLED':'false'}
        with patch.dict(os.environ,env), patch('botocore.utils.InstanceMetadataFetcher.retrieve_iam_role_credentials',return_value=response):
            client = rotation.metadata_client(); self.addCleanup(client.close)
            credentials = client._request_signer._credentials
            self.assertEqual('iam-role',credentials.method)
            self.assertEqual(response['access_key'],credentials.get_frozen_credentials().access_key)

    def test_atomic_delivery_preserves_rejected_paths(self):
        value = session()
        with patch('aws_credential_rotate.output_directory'):
            rotation.deliver(self.root,value,os.geteuid(),os.getgid())
            self.assertEqual(value,consumer.load(self.path,now=NOW))
            target = self.root/'target'; target.write_text('preserve'); self.path.unlink(); self.path.symlink_to(target)
            with self.assertRaises(ValueError): rotation.deliver(self.root,value,os.geteuid(),os.getgid())
            self.assertTrue(self.path.is_symlink()); self.assertEqual('preserve',target.read_text())

    def test_both_role_calls_finish_before_delivery_and_wrong_identity_is_rejected(self):
        config={'sourceRoleArn':'arn:aws:iam::000000000000:role/HOST','roles':{
            'continuity':'arn:aws:iam::000000000000:role/CONTINUITY','notices':'arn:aws:iam::000000000000:role/NOTICES'}}
        calls=[]
        class Client:
            bad=False; fail=False
            def get_caller_identity(self): return {'Account':'000000000000','Arn':'arn:aws:sts::000000000000:assumed-role/'+('OTHER' if self.bad else 'HOST')+'/test'}
            def assume_role(self,**kwargs):
                calls.append(kwargs)
                if self.fail and len(calls)==2: raise OSError('synthetic outage')
                role=kwargs['RoleArn'].split('/')[-1];v=session('A' if role=='CONTINUITY' else 'B')
                return {'AssumedRoleUser':{'Arn':'arn:aws:sts::000000000000:assumed-role/'+role+'/test'},
                        'Credentials':{k:datetime.datetime.fromisoformat(x) if k=='Expiration' else x for k,x in v.items() if k!='Version'}}
        client=Client(); directories={n:self.root/n for n in rotation.TARGETS}
        with patch('aws_credential_rotate.output_directory'), patch('aws_credential_rotate.deliver') as deliver:
            client.fail=True
            with self.assertRaises(OSError): rotation.refresh(config,client,directories,now=NOW)
            deliver.assert_not_called(); calls.clear(); client.fail=False
            result=rotation.refresh(config,client,directories,now=NOW)
            self.assertEqual({'continuity','notices'},set(result)); self.assertEqual(2,deliver.call_count)
            self.assertEqual({'tjipp-continuity','tjipp-notices'},{c['RoleSessionName'] for c in calls})
            calls.clear(); deliver.reset_mock(); client.bad=True
            with self.assertRaises(ValueError): rotation.refresh(config,client,directories,now=NOW)
            self.assertFalse(calls); deliver.assert_not_called()


if __name__ == '__main__': unittest.main()
