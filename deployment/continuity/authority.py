"""Independent, monotonic revocation store. No endpoint can reactivate an ID.

Backend and public handlers must be separate Lambda functions with separate
IAM roles. Provisioning is operator-only and is not exposed by either handler.
"""
import hashlib
import base64
import html
import json
import os
import re
import time
from urllib.parse import parse_qs

FORM = '''<!doctype html><html lang="sv"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Spärra ditt openID</title><main><h1>Spärra ditt openID</h1>
<p>Du kan spärra dygnet runt. Du behöver spärrkoden som du sparat från appen. Spärren är permanent.</p>
<form method="post" action="/revoke"><p><label for="code">Spärrkod</label><br>
<input id="code" name="code" type="password" required maxlength="108" autocomplete="off" spellcheck="false"></p>
<p><label><input type="checkbox" name="confirm" value="yes" required>Jag vill spärra mitt ID permanent.</label></p>
<button type="submit">Spärra permanent</button></form>
<p>Saknar du spärrkoden behöver du kontakta pilotens operatör. Att radera appen spärrar inte ditt ID.</p>
<p><a href="https://openid.tensetti.io">Till projektsidan</a></p></main></html>'''


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


def page(status, body):
    result = response(status, '')
    result['headers'].update({'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"})
    result['body'] = body
    return result


def public_handler(event, context):
    # Tokens belong in a POST body, never in URLs, logs or automatic email links.
    method = event.get('requestContext', {}).get('http', {}).get('method')
    if method == 'GET': return page(200, FORM)
    if method != 'POST':
        return response(405, 'Använd spärrformuläret för att bekräfta spärren.')
    raw = event.get('body', '')
    is_form = event.get('headers', {}).get('content-type', '').split(';')[0] == 'application/x-www-form-urlencoded'
    def reply(status, message):
        if not is_form: return response(status, message)
        return page(status, '<!doctype html><html lang="sv"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Spärr av openID</title><main><h1>Spärr av openID</h1><p>'+html.escape(message)+'</p><a href="/revoke">Till spärrformuläret</a></main></html>')
    if not isinstance(raw, str) or len(raw) > 2048:
        return response(400, 'Kontrollera spärrkoden och försök igen.')
    try:
        if event.get('isBase64Encoded'):
            raw = base64.b64decode(raw, validate=True).decode('utf-8')
        if len(raw) > 1024: raise ValueError('request size')
        if is_form:
            fields = parse_qs(raw, strict_parsing=True, max_num_fields=3)
            if set(fields) != {'code', 'confirm'} or any(len(v) != 1 for v in fields.values()):
                raise ValueError('form fields')
            credential, token = fields['code'][0].strip().split('.')
            data = {'credential': credential, 'token': token, 'confirm': fields['confirm'] == ['yes']}
        else: data = json.loads(raw)
        if not isinstance(data, dict) or set(data) != {'credential', 'token', 'confirm'} or data['confirm'] is not True:
            raise ValueError('confirmation required')
        # None would select the backend's unconditional path, so validate here.
        if not isinstance(data['token'], str):
            raise ValueError('revocation proof required')
        store().revoke(data['credential'], data['token'])
        return reply(200, 'Ditt ID är spärrat. Det kan inte aktiveras igen.')
    except (ValueError, TypeError):
        return reply(400, 'Kontrollera spärrkoden och försök igen.')
    except Exception as error:
        if getattr(error, 'response', {}).get('Error', {}).get('Code') == 'ConditionalCheckFailedException':
            return reply(400, 'Kontrollera spärrkoden och försök igen.')
        return reply(503, 'Spärren kunde inte bekräftas. Försök igen. Ditt ID är inte bekräftat spärrat.')
