"""Generate a disposable RDS validation stack, with an independent expiry task."""
import argparse
import json
from pathlib import Path
import re
import time


def ref(name):
    return {'Ref': name}


def sub(value):
    return {'Fn::Sub': value}


def attr(name, value):
    return {'Fn::GetAtt': [name, value]}


def template(ami, now):
    if not re.fullmatch(r'ami-[a-f0-9]{17}', ami):
        raise ValueError('resolved, pinned x86_64 Ubuntu 24.04 AMI required')
    tags = [{'Key': 'OpenIDTest', 'Value': ref('AWS::StackName')},
            {'Key': 'Environment', 'Value': 'disposable-test'}]
    resources = {}

    def add(name, kind, properties, **extra):
        resources[name] = {'Type': 'AWS::' + kind, 'Properties': properties, **extra}

    def policy(statements):
        return {'Version': '2012-10-17', 'Statement': statements}

    def trust(service):
        return policy([{'Effect': 'Allow', 'Principal': {'Service': service}, 'Action': 'sts:AssumeRole'}])

    add('ExpiryRole', 'IAM::Role', {
        'AssumeRolePolicyDocument': trust('lambda.amazonaws.com'),
        'Policies': [{'PolicyName': 'expire-this-test', 'PolicyDocument': policy([
            {'Effect': 'Allow', 'Action': ['rds:DescribeDBInstances'], 'Resource': '*'},
            {'Effect': 'Allow', 'Action': ['rds:ListTagsForResource', 'rds:DeleteDBInstance'],
             'Resource': sub('arn:${AWS::Partition}:rds:${AWS::Region}:${AWS::AccountId}:db:${AWS::StackName}')},
            {'Effect': 'Allow', 'Action': ['ec2:DescribeInstances'], 'Resource': '*'},
            {'Effect': 'Allow', 'Action': ['ec2:TerminateInstances'],
             'Resource': sub('arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/*'),
             'Condition': {'StringEquals': {'ec2:ResourceTag/OpenIDTest': ref('AWS::StackName'),
                                            'ec2:ResourceTag/Environment': 'disposable-test'}}},
            {'Effect': 'Allow', 'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'],
             'Resource': sub('arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/${AWS::StackName}-expiry:*')},
        ])}], 'Tags': tags})
    add('ExpiryLog', 'Logs::LogGroup', {'LogGroupName': sub('/aws/lambda/${AWS::StackName}-expiry'), 'RetentionInDays': 1})
    add('Expiry', 'Lambda::Function', {
        'FunctionName': sub('${AWS::StackName}-expiry'), 'Runtime': 'python3.12', 'Handler': 'index.handler',
        'Role': attr('ExpiryRole', 'Arn'), 'Timeout': 60, 'MemorySize': 128,
        'Code': {'ZipFile': Path(__file__).with_name('expiry.py').read_text()},
        'Environment': {'Variables': {'STACK': ref('AWS::StackName'), 'CREATED': str(now), 'EXPIRES': str(now + 14400)}},
        'Tags': tags}, DependsOn=['ExpiryLog'])
    add('ExpiryRule', 'Events::Rule', {'ScheduleExpression': 'rate(5 minutes)', 'State': 'ENABLED',
        'Targets': [{'Arn': attr('Expiry', 'Arn'), 'Id': 'expire',
                     'RetryPolicy': {'MaximumEventAgeInSeconds': 3600, 'MaximumRetryAttempts': 12}}]})
    add('ExpiryPermission', 'Lambda::Permission', {'Action': 'lambda:InvokeFunction', 'FunctionName': ref('Expiry'),
        'Principal': 'events.amazonaws.com', 'SourceArn': attr('ExpiryRule', 'Arn'), 'SourceAccount': ref('AWS::AccountId')})
    add('Vpc', 'EC2::VPC', {'CidrBlock': '10.77.0.0/16', 'EnableDnsSupport': True, 'EnableDnsHostnames': True, 'Tags': tags})
    add('Gateway', 'EC2::InternetGateway', {'Tags': tags})
    add('GatewayAttachment', 'EC2::VPCGatewayAttachment', {'VpcId': ref('Vpc'), 'InternetGatewayId': ref('Gateway')})
    for name, cidr, zone in [('RunnerSubnet', '10.77.0.0/24', 0), ('DatabaseSubnetA', '10.77.10.0/24', 0), ('DatabaseSubnetB', '10.77.11.0/24', 1)]:
        add(name, 'EC2::Subnet', {'VpcId': ref('Vpc'), 'CidrBlock': cidr, 'MapPublicIpOnLaunch': False,
            'AvailabilityZone': {'Fn::Select': [zone, {'Fn::GetAZs': ''}]}, 'Tags': tags})
    add('RunnerRoutes', 'EC2::RouteTable', {'VpcId': ref('Vpc'), 'Tags': tags})
    add('RunnerInternet', 'EC2::Route', {'RouteTableId': ref('RunnerRoutes'), 'DestinationCidrBlock': '0.0.0.0/0',
        'GatewayId': ref('Gateway')}, DependsOn=['GatewayAttachment'])
    add('RunnerRouteAssociation', 'EC2::SubnetRouteTableAssociation', {'SubnetId': ref('RunnerSubnet'), 'RouteTableId': ref('RunnerRoutes')})
    add('RunnerSecurity', 'EC2::SecurityGroup', {'VpcId': ref('Vpc'), 'GroupDescription': 'SSM runner without inbound access',
        'SecurityGroupEgress': [{'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'CidrIp': '0.0.0.0/0'},
                                {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'CidrIp': '0.0.0.0/0'},
                                {'IpProtocol': 'tcp', 'FromPort': 5432, 'ToPort': 5432, 'CidrIp': '10.77.10.0/23'}], 'Tags': tags})
    add('DatabaseSecurity', 'EC2::SecurityGroup', {'VpcId': ref('Vpc'), 'GroupDescription': 'PostgreSQL from test runner only',
        'SecurityGroupIngress': [{'IpProtocol': 'tcp', 'FromPort': 5432, 'ToPort': 5432, 'SourceSecurityGroupId': ref('RunnerSecurity')}],
        'SecurityGroupEgress': [{'IpProtocol': '-1', 'CidrIp': '127.0.0.1/32'}], 'Tags': tags})
    add('DatabaseSubnets', 'RDS::DBSubnetGroup', {'DBSubnetGroupDescription': 'Private database subnets',
        'SubnetIds': [ref('DatabaseSubnetA'), ref('DatabaseSubnetB')], 'Tags': tags})
    add('DatabaseParameters', 'RDS::DBParameterGroup', {'Description': 'TLS mandatory; no SQL or bind values in logs',
        'Family': 'postgres18', 'Parameters': {'rds.force_ssl': '1', 'log_statement': 'none',
            'log_min_error_statement': 'panic', 'log_parameter_max_length': '0', 'log_parameter_max_length_on_error': '0'}, 'Tags': tags})
    add('Database', 'RDS::DBInstance', {'DBInstanceIdentifier': ref('AWS::StackName'), 'DBName': 'openid_test',
        'Engine': 'postgres', 'EngineVersion': '18.6', 'DBInstanceClass': 'db.t4g.micro',
        'EngineLifecycleSupport': 'open-source-rds-extended-support-disabled',
        'AllocatedStorage': '20', 'StorageType': 'gp3', 'StorageEncrypted': True,
        'MultiAZ': False, 'PubliclyAccessible': False, 'DeletionProtection': False,
        'BackupRetentionPeriod': 0, 'DeleteAutomatedBackups': True, 'AutoMinorVersionUpgrade': False,
        'MasterUsername': 'openid_bootstrap', 'ManageMasterUserPassword': True,
        'DBSubnetGroupName': ref('DatabaseSubnets'), 'DBParameterGroupName': ref('DatabaseParameters'),
        'VPCSecurityGroups': [ref('DatabaseSecurity')], 'Tags': tags},
        DeletionPolicy='Delete', UpdateReplacePolicy='Delete', DependsOn=['ExpiryPermission', 'ExpiryRule'])
    add('RunnerRole', 'IAM::Role', {'AssumeRolePolicyDocument': trust('ec2.amazonaws.com'),
        'ManagedPolicyArns': [sub('arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore')],
        'Policies': [{'PolicyName': 'read-test-database-secret', 'PolicyDocument': policy([
            {'Effect': 'Allow', 'Action': ['secretsmanager:GetSecretValue'], 'Resource': attr('Database', 'MasterUserSecret.SecretArn')}
        ])}], 'Tags': tags})
    add('RunnerProfile', 'IAM::InstanceProfile', {'Roles': [ref('RunnerRole')]})
    add('Runner', 'EC2::Instance', {'ImageId': ami, 'InstanceType': 't3.small',
        'IamInstanceProfile': ref('RunnerProfile'), 'MetadataOptions': {'HttpTokens': 'required', 'HttpPutResponseHopLimit': 1},
        'CreditSpecification': {'CPUCredits': 'standard'},
        'BlockDeviceMappings': [{'DeviceName': '/dev/sda1', 'Ebs': {'VolumeSize': 12, 'VolumeType': 'gp3', 'Encrypted': True, 'DeleteOnTermination': True}}],
        'NetworkInterfaces': [{'DeviceIndex': '0', 'AssociatePublicIpAddress': True, 'SubnetId': ref('RunnerSubnet'), 'GroupSet': [ref('RunnerSecurity')]}],
        'Tags': tags}, DependsOn=['RunnerInternet', 'RunnerRouteAssociation', 'ExpiryPermission'])
    outputs = {name: {'Value': value, 'Description': name} for name, value in {
        'RunnerId': ref('Runner'), 'DatabaseHost': attr('Database', 'Endpoint.Address'),
        'DatabaseSecretArn': attr('Database', 'MasterUserSecret.SecretArn'), 'ExpiryFunction': ref('Expiry'),
        'ExpiresAtEpoch': str(now + 14400)}.items()}
    return {'AWSTemplateFormatVersion': '2010-09-09',
        'Description': 'Disposable OpenID RDS compatibility test. Automatically expires after four hours.',
        'Resources': resources, 'Outputs': outputs}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--ami', required=True)
    args = parser.parse_args()
    print(json.dumps(template(args.ami, int(time.time())), indent=2))
