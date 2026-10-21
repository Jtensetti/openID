"""Expire only the database and runner belonging to one disposable test stack."""
import os
import re
import time

import boto3
from botocore.exceptions import ClientError


def expire(config, now, rds, ec2):
    name = config['STACK']
    if not re.fullmatch(r'openid-aws-check-[a-f0-9]{12}', name):
        raise ValueError('unexpected stack name')
    created, deadline = int(config['CREATED']), int(config['EXPIRES'])
    if not 0 < deadline - created <= 14400:
        raise ValueError('maximum lifetime is four hours')
    if now < deadline:
        return {'state': 'WAITING', 'secondsRemaining': deadline - now}
    result = {'state': 'EXPIRED', 'database': 'absent', 'instances': []}
    try:
        db = rds.describe_db_instances(DBInstanceIdentifier=name)['DBInstances'][0]
    except ClientError as error:
        if error.response['Error']['Code'] != 'DBInstanceNotFound':
            raise
    else:
        tags = {x['Key']: x['Value'] for x in rds.list_tags_for_resource(ResourceName=db['DBInstanceArn'])['TagList']}
        if tags.get('OpenIDTest') != name or tags.get('Environment') != 'disposable-test':
            raise ValueError('database tags do not authorize deletion')
        result['database'] = db['DBInstanceStatus']
        if db['DBInstanceStatus'] != 'deleting':
            try:
                rds.delete_db_instance(DBInstanceIdentifier=name, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
                result['database'] = 'deleting'
            except ClientError as error:
                if error.response['Error']['Code'] != 'InvalidDBInstanceState':
                    raise
                result['database'] = 'retry'
    pages = ec2.get_paginator('describe_instances').paginate(Filters=[
        {'Name': 'tag:OpenIDTest', 'Values': [name]},
        {'Name': 'tag:Environment', 'Values': ['disposable-test']},
        {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']},
    ])
    for page in pages:
        for reservation in page['Reservations']:
            for instance in reservation['Instances']:
                tags = {x['Key']: x['Value'] for x in instance.get('Tags', [])}
                if tags.get('OpenIDTest') != name or tags.get('Environment') != 'disposable-test':
                    raise ValueError('instance tags do not authorize termination')
                ec2.terminate_instances(InstanceIds=[instance['InstanceId']])
                result['instances'].append(instance['InstanceId'])
    return result


def handler(event, context):
    # Caller input cannot change the deadline or target resources.
    return expire(os.environ, int(time.time()), boto3.client('rds'), boto3.client('ec2'))
