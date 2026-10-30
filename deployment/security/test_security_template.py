"""Exercise security rules against both the real template and unsafe mutations."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from template import template


class SecurityTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.guard = os.environ.get('GUARD_BIN')
        if not cls.guard: raise RuntimeError('GUARD_BIN must point to the verified cfn-guard binary')

    def check(self, data, valid):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'template.json';path.write_text(json.dumps(data))
            result = subprocess.run([self.guard, 'validate', '--rules', str(Path(__file__).with_name('security.guard')),
                '--data', str(path), '--output-format', 'json'],capture_output=True,text=True,timeout=20)
            self.assertEqual(0 if valid else 19, result.returncode, result.stdout+result.stderr)

    def test_real_template(self): self.check(template(), True)

    def test_additional_compute_and_paid_scanning_rejected(self):
        for kind in ('AWS::EC2::Instance', 'AWS::Lambda::Function', 'AWS::GuardDuty::Detector',
                     'AWS::StepFunctions::StateMachine', 'AWS::CloudTrail::EventDataStore'):
            with self.subTest(kind=kind):
                data=template();data['Resources']['ExtraJob']={'Type':kind,'Properties':{}}
                self.check(data,False)
        data=template()
        data['Resources']['Trail']['Properties']['InsightSelectors']=[{'InsightType':'ApiCallRateInsight'}]
        self.check(data,False)
        data=template()
        data['Resources']['Trail']['Properties']['EventSelectors'][0]['DataResources']=[
            {'Type':'AWS::S3::Object','Values':['arn:aws:s3:::example/']}]
        self.check(data,False)

    def test_public_bucket_rejected(self):
        data=template();data['Resources']['AuditBucket']['Properties']['PublicAccessBlockConfiguration']['BlockPublicPolicy']=False
        self.check(data,False)

    def test_log_and_key_deletion_rejected(self):
        for resource in ('AuditBucket','AuditLog','AuditKey'):
            with self.subTest(resource=resource):
                data=template();data['Resources'][resource]['DeletionPolicy']='Delete';self.check(data,False)

    def test_disabled_or_incomplete_trail_rejected(self):
        for property in ('IsLogging','IsMultiRegionTrail','IncludeGlobalServiceEvents','EnableLogFileValidation'):
            with self.subTest(property=property):
                data=template();data['Resources']['Trail']['Properties'][property]=False;self.check(data,False)

    def test_unencrypted_or_unversioned_storage_rejected(self):
        data=template();del data['Resources']['AuditBucket']['Properties']['BucketEncryption'];self.check(data,False)
        data=template();data['Resources']['AuditBucket']['Properties']['VersioningConfiguration']['Status']='Suspended';self.check(data,False)

    def test_unsafe_snapshot_deletion_rejected(self):
        for key in ('ec2:ResourceTag/aws:dlm:lifecycle-policy-id','ec2:ResourceTag/openIDBackup'):
            with self.subTest(key=key):
                data=template()
                statement=next(s for s in data['Resources']['SnapshotPermissions']['Properties']['PolicyDocument']['Statement'] if s['Action']=='ec2:DeleteSnapshot')
                del statement['Condition']['StringEquals'][key];self.check(data,False)

    def test_backup_scope_and_unbounded_permission_rejected(self):
        data=template();data['Resources']['SnapshotPolicy']['Properties']['PolicyDetails']['Parameters']['ExcludeBootVolume']=True;self.check(data,False)
        data=template();data['Resources']['SnapshotPermissions']['Properties']['PolicyDocument']['Statement'].append({'Effect':'Allow','Action':'ec2:*','Resource':'*'});self.check(data,False)

    def test_absent_backups_must_alarm(self):
        data=template();data['Resources']['SnapshotsMissing']['Properties']['TreatMissingData']='notBreaching';self.check(data,False)

    def test_alarms_must_have_encrypted_delivery(self):
        data=template();del data['Resources']['AlertTopic']['Properties']['KmsMasterKeyId'];self.check(data,False)
        data=template();data['Resources']['NoticeDeadLetters']['Properties']['AlarmActions']=[];self.check(data,False)


if __name__ == '__main__': unittest.main()
