"""Generate a private, retained S3 archive. Does not deploy resources."""
import json


def template():
    issuer = {'Fn::Sub':'arn:${AWS::Partition}:iam::${IssuerAccountId}:role/${IssuerRoleName}'}
    custodian = {'Fn::Sub':'arn:${AWS::Partition}:iam::${AWS::AccountId}:role/${CustodianRoleName}'}
    bucket = {'Fn::GetAtt':['Archive','Arn']}
    objects = {'Fn::Sub':'${Archive.Arn}/${ArchivePrefix}/*'}
    transfers = {'Fn::Sub':'${Archive.Arn}/${ArchivePrefix}/transfers/*'}
    receipts = {'Fn::Sub':'${Archive.Arn}/${ArchivePrefix}/receipts/*'}
    def statement(sid, principal, actions, resources, effect='Allow', condition=None):
        result = {'Sid':sid,'Effect':effect,'Principal':principal,'Action':actions,'Resource':resources}
        if condition: result['Condition']=condition
        return result
    metadata = ['s3:GetBucketLocation','s3:GetBucketVersioning','s3:GetBucketObjectLockConfiguration']
    writing = ['s3:PutObject','s3:PutObjectRetention']
    policy = [
        statement('UploaderMetadata',{'AWS':issuer},metadata,bucket),
        statement('CustodianMetadata',{'AWS':custodian},metadata,bucket),
        statement('UploaderTransfer',{'AWS':issuer},writing+['s3:GetObjectVersion','s3:GetObjectRetention'],transfers),
        statement('CustodianRead',{'AWS':custodian},['s3:GetObjectVersion','s3:GetObjectRetention'],[transfers,receipts]),
        statement('CustodianReceipt',{'AWS':custodian},writing,receipts),
        statement('OnlyCustodianCanReceipt','*',writing,receipts,'Deny',{'ArnNotEquals':{'aws:PrincipalArn':custodian}}),
        statement('TLSRequired','*','s3:*',[bucket,{'Fn::Sub':'${Archive.Arn}/*'}],'Deny',{'Bool':{'aws:SecureTransport':'false'}}),
        statement('EncryptionRequired','*',['s3:PutObject'],objects,'Deny',
                  {'StringNotEquals':{'s3:x-amz-server-side-encryption':'AES256'}}),
        statement('ComplianceRequired','*',writing,objects,'Deny',{'StringNotEquals':{'s3:object-lock-mode':'COMPLIANCE'}}),
        statement('RetentionFloor','*',writing,objects,'Deny',
                  {'NumericLessThan':{'s3:object-lock-remaining-retention-days':{'Ref':'RetentionDays'}}}),
        statement('RetentionCeiling','*',writing,objects,'Deny',{'NumericGreaterThan':{'s3:object-lock-remaining-retention-days':3655}}),
        statement('IssuerCannotDestroy',{'AWS':issuer},['s3:DeleteObject','s3:DeleteObjectVersion',
            's3:BypassGovernanceRetention','s3:PutBucketPolicy','s3:PutBucketVersioning',
            's3:PutBucketObjectLockConfiguration','s3:PutLifecycleConfiguration'],
            [bucket,{'Fn::Sub':'${Archive.Arn}/*'}],'Deny'),
    ]
    role_pattern = '[A-Za-z0-9_+=,.@-]{1,64}'
    return {
        'AWSTemplateFormatVersion':'2010-09-09',
        'Description':'Private cross-account OpenID archive with custodian-only receipts. No automatic data upload.',
        'Parameters':{
            'IssuerAccountId':{'Type':'String','AllowedPattern':'[0-9]{12}'},
            'IssuerRoleName':{'Type':'String','AllowedPattern':role_pattern},
            'CustodianRoleName':{'Type':'String','AllowedPattern':role_pattern},
            'ArchivePrefix':{'Type':'String','Default':'openid-archive','AllowedPattern':'[a-z0-9-]{1,40}'},
            'RetentionDays':{'Type':'Number','Default':1827,'MinValue':1827,'MaxValue':3650},
        },
        'Resources':{
            'Archive':{'Type':'AWS::S3::Bucket','DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain','Properties':{
                'PublicAccessBlockConfiguration':{name:True for name in ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')},
                'OwnershipControls':{'Rules':[{'ObjectOwnership':'BucketOwnerEnforced'}]},
                'VersioningConfiguration':{'Status':'Enabled'},
                'BucketEncryption':{'ServerSideEncryptionConfiguration':[{'ServerSideEncryptionByDefault':{'SSEAlgorithm':'AES256'}}]},
                'ObjectLockEnabled':True,'ObjectLockConfiguration':{'ObjectLockEnabled':'Enabled','Rule':{
                    'DefaultRetention':{'Mode':'COMPLIANCE','Days':{'Ref':'RetentionDays'}}}},
                'Tags':[{'Key':'Project','Value':'OpenID'},{'Key':'DataClass','Value':'Private'}],
            }},
            'Policy':{'Type':'AWS::S3::BucketPolicy','Properties':{'Bucket':{'Ref':'Archive'},
                'PolicyDocument':{'Version':'2012-10-17','Statement':policy}}},
        },
        'Outputs':{
            'Bucket':{'Description':'Archive bucket name for the private CLI configuration','Value':{'Ref':'Archive'}},
            'Owner':{'Description':'Expected archive account','Value':{'Ref':'AWS::AccountId'}},
            'Region':{'Description':'Use eu-north-1 for the current archive client','Value':{'Ref':'AWS::Region'}},
            'CustodianRoleArn':{'Description':'Existing custodian role; trust is managed separately','Value':custodian},
        },
    }


if __name__ == '__main__': print(json.dumps(template(),indent=2))
