"""Independent, monotonic revocation store. No endpoint can reactivate an ID.

Backend and public handlers must be separate Lambda functions with separate
IAM roles. Provisioning is operator-only and is not exposed by either handler.
"""
import hashlib
import json
import os
import re
import time


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
        raise ValueError('identifier')
    return value


class Authority:
    def __init__(self, table, clock=time.time):
        self.table, self.clock = table, clock

    def status(self, credential):
        item = self.table.get_item(Key={'credential': identifier(credential)},
                                   ConsistentRead=True).get('Item', {})
        state = item.get('state', 'UNKNOWN')
        if state not in {'ENABLED', 'REVOKED', 'UNKNOWN'}:
            raise ValueError('invalid stored state')
        return {'credential': credential, 'state': state}

    def revoke(self, credential, token=None):
        identifier(credential)
        values = {':revoked': 'REVOKED', ':now': int(self.clock())}
        condition = None
        if token is not None:
            if not isinstance(token, str) or not re.fullmatch('[A-Za-z0-9_-]{43}', token):
                raise ValueError('invalid revocation proof')
            values[':hash'] = hashlib.sha256(token.encode('ascii')).hexdigest()
            condition = 'token_hash = :hash'
        kwargs = {'ConditionExpression': condition} if condition else {}
        # IAM-authenticated backend may create a tombstone even before enrolment.
        # Public token checks and revocation are a single conditional write.
        self.table.update_item(Key={'credential': credential},
            UpdateExpression='SET #state = :revoked, revoked_at = if_not_exists(revoked_at, :now)',
            ExpressionAttributeNames={'#state': 'state'},
            ExpressionAttributeValues=values, **kwargs)
        return {'credential': credential, 'state': 'REVOKED'}


def store():
    import boto3
    from botocore.config import Config
    return Authority(boto3.resource('dynamodb', config=Config(
        connect_timeout=2, read_timeout=2, retries={'total_max_attempts': 2}
    )).Table(os.environ['REVOCATION_TABLE']))


def backend_handler(event, context):
    # InvokeFunction via IAM only. Never connect this handler to a public route.
    if not isinstance(event, dict) or set(event) != {'operation', 'credential'}:
        raise ValueError('request fields')
    authority = store()
    if event['operation'] == 'status':
        return authority.status(event['credential'])
    if event['operation'] == 'revoke':
        return authority.revoke(event['credential'])
    raise ValueError('operation')


def response(status, message):
    return {'statusCode': status, 'headers': {'Content-Type': 'application/json',
        'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff'},
        'body': json.dumps({'message': message}, ensure_ascii=False)}


def public_handler(event, context):
    # Tokens belong in a POST body, never in URLs, logs or automatic email links.
    if event.get('requestContext', {}).get('http', {}).get('method') != 'POST':
        return response(405, 'Använd spärrformuläret för att bekräfta spärren.')
    raw = event.get('body', '')
    if event.get('isBase64Encoded') or not isinstance(raw, str) or len(raw) > 1024:
        return response(400, 'Kontrollera spärrkoden och försök igen.')
    try:
        data = json.loads(raw)
        if not isinstance(data, dict) or set(data) != {'credential', 'token', 'confirm'} or data['confirm'] is not True:
            raise ValueError('confirmation required')
        # None would select the backend's unconditional path, so validate here.
        if not isinstance(data['token'], str):
            raise ValueError('revocation proof required')
        store().revoke(data['credential'], data['token'])
        return response(200, 'Ditt ID är spärrat. Det kan inte aktiveras igen.')
    except (ValueError, TypeError):
        return response(400, 'Kontrollera spärrkoden och försök igen.')
    except Exception as error:
        if getattr(error, 'response', {}).get('Error', {}).get('Code') == 'ConditionalCheckFailedException':
            return response(400, 'Kontrollera spärrkoden och försök igen.')
        return response(503, 'Spärren kunde inte bekräftas. Försök igen. Ditt ID är inte bekräftat spärrat.')
