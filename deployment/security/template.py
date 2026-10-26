"""Generate retained audit storage, scoped EBS backup and operational alarms.

No resources are deployed and no subscriptions are created by this generator.
"""
import json


def ref(name): return {'Ref': name}
def sub(value): return {'Fn::Sub': value}
def arn(name): return {'Fn::GetAtt': [name, 'Arn']}
def policy(statements): return {'Version': '2012-10-17', 'Statement': statements}
def allow(actions, resource, **extra):
    return {'Effect': 'Allow', 'Action': actions, 'Resource': resource, **extra}
def retained(kind, properties):
    return {'Type': kind, 'DeletionPolicy': 'Retain', 'UpdateReplacePolicy': 'Retain', 'Properties': properties}


def template():
    trail_arn = sub('arn:${AWS::Partition}:cloudtrail:${AWS::Region}:${AWS::AccountId}:trail/${AWS::StackName}')
    log_arn = sub('arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/openid/security/${AWS::StackName}')
    streams = sub('arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/openid/security/${AWS::StackName}:log-stream:${AWS::AccountId}_CloudTrail_*')
    snapshots = sub('arn:${AWS::Partition}:ec2:${AWS::Region}::snapshot/*')
    source_account = {'StringEquals': {'aws:SourceAccount': ref('AWS::AccountId')}}
    alarm_source = {**source_account, 'ArnLike': {
        'aws:SourceArn': sub('arn:${AWS::Partition}:cloudwatch:${AWS::Region}:${AWS::AccountId}:alarm:${AWS::StackName}-*')}}
    key_policy = policy([
        allow('kms:*', '*', Principal={'AWS': sub('arn:${AWS::Partition}:iam::${AWS::AccountId}:root')}),
        allow('kms:GenerateDataKey*', '*', Principal={'Service': 'cloudtrail.amazonaws.com'},
              Condition={'StringEquals': {'aws:SourceArn': trail_arn}, 'StringLike': {
                  'kms:EncryptionContext:aws:cloudtrail:arn': sub('arn:${AWS::Partition}:cloudtrail:*:${AWS::AccountId}:trail/${AWS::StackName}')}}),
        allow('kms:DescribeKey', '*', Principal={'Service': 'cloudtrail.amazonaws.com'},
              Condition={'StringEquals': {'aws:SourceArn': trail_arn}}),
        allow(['kms:Encrypt', 'kms:Decrypt', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:DescribeKey'], '*',
              Principal={'Service': sub('logs.${AWS::Region}.amazonaws.com')},
              Condition={'ArnEquals': {'kms:EncryptionContext:aws:logs:arn': log_arn}}),
        allow(['kms:GenerateDataKey*', 'kms:Decrypt'], '*', Principal={'Service': 'cloudwatch.amazonaws.com'},
              Condition=alarm_source),
    ])
    resources = {
        'AuditKey': retained('AWS::KMS::Key', {'Description': 'openID audit encryption', 'EnableKeyRotation': True,
            'PendingWindowInDays': 30, 'KeyPolicy': key_policy}),
        'AuditBucket': retained('AWS::S3::Bucket', {
            'PublicAccessBlockConfiguration': {name: True for name in (
                'BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')},
            'OwnershipControls': {'Rules': [{'ObjectOwnership': 'BucketOwnerEnforced'}]},
            'VersioningConfiguration': {'Status': 'Enabled'},
            'BucketEncryption': {'ServerSideEncryptionConfiguration': [{'ServerSideEncryptionByDefault': {
                'SSEAlgorithm': 'aws:kms', 'KMSMasterKeyID': arn('AuditKey')}}]},
            'LifecycleConfiguration': {'Rules': [{'Id': 'AuditRetention', 'Status': 'Enabled',
                'ExpirationInDays': 365, 'NoncurrentVersionExpiration': {'NoncurrentDays': 365},
                'AbortIncompleteMultipartUpload': {'DaysAfterInitiation': 7}}]},
            'Tags': [{'Key': 'Project', 'Value': 'openID'}, {'Key': 'DataClass', 'Value': 'RestrictedAudit'}]}),
        'AuditLog': retained('AWS::Logs::LogGroup', {'LogGroupName': sub('/openid/security/${AWS::StackName}'),
            'RetentionInDays': 90, 'KmsKeyId': arn('AuditKey')}),
        'AlertTopic': {'Type': 'AWS::SNS::Topic', 'Properties': {
            'TopicName': sub('${AWS::StackName}-alerts'), 'KmsMasterKeyId': arn('AuditKey')}},
        'AlertTopicPolicy': {'Type': 'AWS::SNS::TopicPolicy', 'Properties': {
            'Topics': [ref('AlertTopic')], 'PolicyDocument': policy([
                allow('sns:Publish', ref('AlertTopic'), Principal={'Service': 'cloudwatch.amazonaws.com'},
                      Condition=alarm_source),
                {'Effect': 'Deny', 'Principal': '*', 'Action': 'sns:*', 'Resource': ref('AlertTopic'),
                 'Condition': {'Bool': {'aws:SecureTransport': 'false'}}}])}},
        'TrailRole': {'Type': 'AWS::IAM::Role', 'Properties': {
            'AssumeRolePolicyDocument': policy([{'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'},
                'Action': 'sts:AssumeRole', 'Condition': {'StringEquals': {'aws:SourceArn': trail_arn,
                    'aws:SourceAccount': ref('AWS::AccountId')}}}]),
            'Policies': [{'PolicyName': 'WriteTrailOnly', 'PolicyDocument': policy([
                allow(['logs:CreateLogStream', 'logs:PutLogEvents'], streams)])}]}},
        'BucketPolicy': {'Type': 'AWS::S3::BucketPolicy', 'Properties': {
            'Bucket': ref('AuditBucket'), 'PolicyDocument': policy([
                allow('s3:GetBucketAcl', arn('AuditBucket'), Principal={'Service': 'cloudtrail.amazonaws.com'},
                      Condition={'StringEquals': {'aws:SourceArn': trail_arn}}),
                allow('s3:PutObject', sub('${AuditBucket.Arn}/AWSLogs/${AWS::AccountId}/*'),
                      Principal={'Service': 'cloudtrail.amazonaws.com'}, Condition={'StringEquals': {
                          'aws:SourceArn': trail_arn, 's3:x-amz-acl': 'bucket-owner-full-control'}}),
                {'Effect': 'Deny', 'Principal': '*', 'Action': 's3:*',
                 'Resource': [arn('AuditBucket'), sub('${AuditBucket.Arn}/*')],
                 'Condition': {'Bool': {'aws:SecureTransport': 'false'}}}])}},
        'Trail': retained('AWS::CloudTrail::Trail', {'TrailName': ref('AWS::StackName'), 'IsLogging': True,
            'IsMultiRegionTrail': True, 'IncludeGlobalServiceEvents': True, 'EnableLogFileValidation': True,
            'KMSKeyId': arn('AuditKey'), 'S3BucketName': ref('AuditBucket'),
            'CloudWatchLogsLogGroupArn': arn('AuditLog'), 'CloudWatchLogsRoleArn': arn('TrailRole'),
            'EventSelectors': [{'IncludeManagementEvents': True, 'ReadWriteType': 'All'}]}),
        'SnapshotRole': {'Type': 'AWS::IAM::Role', 'Properties': {
            'AssumeRolePolicyDocument': policy([{'Effect': 'Allow', 'Principal': {'Service': 'dlm.amazonaws.com'},
                'Action': 'sts:AssumeRole', 'Condition': {**source_account, 'ArnLike': {
                    'aws:SourceArn': sub('arn:${AWS::Partition}:dlm:${AWS::Region}:${AWS::AccountId}:policy/*')}}}])}},
        'SnapshotPolicy': {'Type': 'AWS::DLM::LifecyclePolicy', 'Properties': {
            'Description': 'openID daily multi volume snapshots', 'State': ref('BackupState'),
            'ExecutionRoleArn': arn('SnapshotRole'),
            'PolicyDetails': {'PolicyType': 'EBS_SNAPSHOT_MANAGEMENT', 'ResourceTypes': ['INSTANCE'],
                'TargetTags': [{'Key': 'openIDBackup', 'Value': ref('AWS::StackName')}],
                'Parameters': {'ExcludeBootVolume': False},
                'Schedules': [{'Name': 'DailyPrivateBackup', 'CopyTags': False,
                    'TagsToAdd': [{'Key': 'openIDBackup', 'Value': ref('AWS::StackName')}],
                    'CreateRule': {'Interval': 24, 'IntervalUnit': 'HOURS', 'Times': ['17:00']},
                    'RetainRule': {'Count': 14}}]}}},
    }
    resources['Trail']['DependsOn'] = ['BucketPolicy']
    # Separate policy avoids a role/policy circular dependency and scopes deletion
    # to snapshots created by this exact lifecycle policy, never manual snapshots.
    resources['SnapshotPermissions'] = {'Type': 'AWS::IAM::Policy', 'Properties': {
        'PolicyName': 'SelectedInstanceSnapshots', 'Roles': [ref('SnapshotRole')], 'PolicyDocument': policy([
            allow(['ec2:DescribeInstances', 'ec2:DescribeVolumes', 'ec2:DescribeSnapshots', 'ec2:DescribeTags'], '*',
                  Condition={'StringEquals': {'ec2:Region': ref('AWS::Region')}}),
            allow('ec2:CreateSnapshots', [sub('arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/${InstanceId}'),
                sub('arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:volume/${RootVolumeId}'),
                sub('arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:volume/${DataVolumeId}'), snapshots]),
            allow('ec2:CreateTags', snapshots, Condition={'StringEquals': {
                'aws:RequestTag/openIDBackup': ref('AWS::StackName')}}),
            allow('ec2:CreateTags', snapshots, Condition={'StringEquals': {
                'ec2:ResourceTag/aws:dlm:lifecycle-policy-id': ref('SnapshotPolicy')}}),
            allow('ec2:DeleteSnapshot', snapshots, Condition={'StringEquals': {
                'ec2:ResourceTag/aws:dlm:lifecycle-policy-id': ref('SnapshotPolicy'),
                'ec2:ResourceTag/openIDBackup': ref('AWS::StackName')}}),
            allow(['events:PutRule', 'events:DeleteRule', 'events:DescribeRule', 'events:EnableRule',
                'events:DisableRule', 'events:ListTargetsByRule', 'events:PutTargets', 'events:RemoveTargets'],
                sub('arn:${AWS::Partition}:events:${AWS::Region}:${AWS::AccountId}:rule/AwsDataLifecycleRule.managed-cwe.*')),
        ])}}

    def alarm(name, namespace, metric, dimensions, threshold=1, period=300, statistic='Sum', evaluations=1):
        resources[name] = {'Type': 'AWS::CloudWatch::Alarm', 'Properties': {
            'AlarmName': sub('${AWS::StackName}-'+name),
            'AlarmDescription': 'openID: investigate with the incident runbook; no identity data in alarm labels.',
            'Namespace': namespace, 'MetricName': metric, 'Dimensions': dimensions, 'Period': period,
            'Statistic': statistic, 'EvaluationPeriods': evaluations, 'DatapointsToAlarm': evaluations,
            'Threshold': threshold, 'ComparisonOperator': 'GreaterThanOrEqualToThreshold',
            'TreatMissingData': 'notBreaching',
            'AlarmActions': [ref('AlertTopic')], 'OKActions': [ref('AlertTopic')]}}
    for parameter in ('BackendFunction', 'PublicFunction', 'DeliveryFunction'):
        for metric in ('Errors', 'Throttles'):
            alarm(parameter+metric, 'AWS/Lambda', metric, [{'Name': 'FunctionName', 'Value': ref(parameter)}])
    alarm('NoticeBacklog', 'AWS/SQS', 'ApproximateAgeOfOldestMessage',
          [{'Name': 'QueueName', 'Value': ref('NoticeQueueName')}], threshold=300, statistic='Maximum')
    alarm('NoticeDeadLetters', 'AWS/SQS', 'ApproximateNumberOfMessagesVisible',
          [{'Name': 'QueueName', 'Value': ref('NoticeDeadLetterQueueName')}], statistic='Maximum')
    alarm('InstanceFailure', 'AWS/EC2', 'StatusCheckFailed',
          [{'Name': 'InstanceId', 'Value': ref('InstanceId')}], period=60, statistic='Maximum', evaluations=2)
    alarm('SnapshotErrors', 'AWS/EBS', 'SnapshotsCreateFailed',
          [{'Name': 'DLMPolicyId', 'Value': ref('SnapshotPolicy')}])
    alarm('SnapshotDeletionErrors', 'AWS/EBS', 'SnapshotsDeleteFailed',
          [{'Name': 'DLMPolicyId', 'Value': ref('SnapshotPolicy')}])
    alarm('SnapshotsMissing', 'AWS/EBS', 'SnapshotsCreateCompleted',
          [{'Name': 'DLMPolicyId', 'Value': ref('SnapshotPolicy')}], threshold=2, period=86400)
    resources['SnapshotsMissing']['Condition'] = 'BackupEnabled'
    resources['SnapshotsMissing']['Properties'].update({
        'ComparisonOperator': 'LessThanThreshold', 'TreatMissingData': 'breaching',
        'AlarmDescription': 'Fewer than two completed volume snapshots in the daily period. Verify each volume and snapshot age; aggregate count is not a restore test.'})
    filters = {
        'UnauthorizedCalls': '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
        'AuditChanges': '{ ($.eventSource = "cloudtrail.amazonaws.com") && (($.eventName = "StopLogging") || ($.eventName = "DeleteTrail") || ($.eventName = "UpdateTrail") || ($.eventName = "PutEventSelectors")) }',
        'RootActivity': '{ ($.userIdentity.type = "Root") && ($.eventType != "AwsServiceEvent") }',
        'PolicyChanges': '{ ($.eventSource = "iam.amazonaws.com") && (($.eventName = "PutRolePolicy") || ($.eventName = "AttachRolePolicy") || ($.eventName = "CreatePolicyVersion") || ($.eventName = "SetDefaultPolicyVersion") || ($.eventName = "UpdateAssumeRolePolicy")) }',
    }
    for name, pattern in filters.items():
        resources[name+'Filter'] = {'Type': 'AWS::Logs::MetricFilter', 'Properties': {
            'LogGroupName': ref('AuditLog'), 'FilterPattern': pattern, 'MetricTransformations': [{
                'MetricName': name, 'MetricNamespace': sub('OpenID/${AWS::StackName}'), 'MetricValue': '1', 'DefaultValue': 0}]}}
        alarm(name, sub('OpenID/${AWS::StackName}'), name, [])
    parameters = {
        'InstanceId': {'Type': 'AWS::EC2::Instance::Id'},
        'RootVolumeId': {'Type': 'String', 'AllowedPattern': 'vol-[a-f0-9]{17}'},
        'DataVolumeId': {'Type': 'String', 'AllowedPattern': 'vol-[a-f0-9]{17}'},
        'BackupState': {'Type': 'String', 'Default': 'DISABLED', 'AllowedValues': ['DISABLED', 'ENABLED'],
            'Description': 'Create disabled, verify IAM and target tags, then explicitly enable.'},
    }
    for name in ('BackendFunction', 'PublicFunction', 'DeliveryFunction', 'NoticeQueueName', 'NoticeDeadLetterQueueName'):
        parameters[name] = {'Type': 'String', 'AllowedPattern': '[A-Za-z0-9_-]{1,80}'}
    return {'AWSTemplateFormatVersion': '2010-09-09',
        'Description': 'openID audit trail, scoped daily EBS backup and alarms; explicit operational activation required',
        'Parameters': parameters, 'Conditions': {
            'BackupEnabled': {'Fn::Equals': [ref('BackupState'), 'ENABLED']}},
        'Resources': resources, 'Outputs': {
            'AuditBucketName': {'Value': ref('AuditBucket')}, 'TrailArn': {'Value': trail_arn},
            'SnapshotPolicyId': {'Value': ref('SnapshotPolicy')}, 'SnapshotRoleArn': {'Value': arn('SnapshotRole')},
            'BackupTargetTag': {'Value': sub('openIDBackup=${AWS::StackName}')},
            'AlarmTopicArn': {'Value': ref('AlertTopic')},
            'NotificationMode': {'Value': 'Encrypted topic; subscribe an approved receiver and verify delivery before operational acceptance'}}}


if __name__ == '__main__': print(json.dumps(template(), indent=2))
