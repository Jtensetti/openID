"""Private SQS consumer. Transport acceptance is never labelled delivery."""
import json
import os
import re
import time


def validate(event):
    if not isinstance(event, dict) or set(event) != {'event', 'contactVersion', 'kind', 'created'}:
        raise ValueError('notification fields')
    if not isinstance(event['event'], str) or not re.fullmatch('[a-f0-9]{64}', event['event']):
        raise ValueError('notification identifier')
    if not isinstance(event['contactVersion'], str) or not re.fullmatch('[A-Za-z0-9_-]{16,128}', event['contactVersion']):
        raise ValueError('contact version')
    if event['kind'] not in {'ACTIVATED_V1', 'DELIVERY_TEST_V1'} or type(event['created']) is not int:
        raise ValueError('notification template')


def deliver(event, table, ses, sender, feedback, clock=time.time):
    validate(event)
    key = {'id': 'event#'+event['event']}
    prior = table.get_item(Key=key, ConsistentRead=True).get('Item', {})
    if prior.get('state') == 'ACCEPTED': return
    # The sender cannot change the address: only an immutable operator-bound
    # contact version is accepted, never an address from the queue message.
    contact = table.get_item(Key={'id': 'contact#'+event['contactVersion']},
                             ConsistentRead=True).get('Item', {})
    if contact.get('verified') is not True or not contact.get('evidence'):
        raise ValueError('independent contact not verified')
    recipient = contact.get('recipient')
    if not isinstance(recipient, str) or len(recipient) > 254 or '\n' in recipient or '\r' in recipient:
        raise ValueError('recipient')
    now = int(clock())
    table.update_item(Key=key,
        UpdateExpression='SET #state=:sending, lease_until=:until',
        ConditionExpression='attribute_not_exists(id) OR (#state <> :accepted AND lease_until < :now)',
        ExpressionAttributeNames={'#state': 'state'},
        ExpressionAttributeValues={':sending': 'SENDING', ':accepted': 'ACCEPTED', ':now': now, ':until': now+90})
    if event['kind'] == 'ACTIVATED_V1':
        subject = 'openID – ditt ID har aktiverats'
        body = ('Ett ID har aktiverats efter manuell granskning i openIDs pilot.\n\n'
                'Om du inte har begärt detta, kontakta pilotens operatör omedelbart. '
                'Använd din separata spärrkod för att spärra ditt ID.\n\n'
                'Svara inte med passuppgifter, personnummer eller spärrkod.\n')
    else:
        subject = 'openID – test av den separata aviseringskön'
        body = ('Detta är ett leveransprov från openIDs separata aviseringskö. '
                'Inget ID har aktiverats eller spärrats genom detta test.\n')
    result = ses.send_email(FromEmailAddress=sender, Destination={'ToAddresses': [recipient]},
        FeedbackForwardingEmailAddress=feedback, ReplyToAddresses=[feedback],
        Content={'Simple': {'Subject': {'Data': subject, 'Charset': 'UTF-8'},
            'Body': {'Text': {'Data': body, 'Charset': 'UTF-8'}}}})
    receipt = result.get('MessageId')
    if not isinstance(receipt, str) or not receipt: raise ValueError('transport receipt missing')
    # A crash after SES acceptance can repeat the same notice after the lease
    # expires. This is at-least-once delivery, never a second ID activation.
    table.update_item(Key=key, UpdateExpression='SET #state=:accepted, receipt=:receipt',
        ExpressionAttributeNames={'#state': 'state'},
        ExpressionAttributeValues={':accepted': 'ACCEPTED', ':receipt': receipt})


def handler(event, context):
    import boto3
    from botocore.config import Config
    config = Config(connect_timeout=2, read_timeout=3, retries={'total_max_attempts': 1})
    table = boto3.resource('dynamodb', config=config).Table(os.environ['NOTICE_TABLE'])
    ses = boto3.client('sesv2', config=config)
    failures = []
    for record in event.get('Records', []):
        notice = None
        try:
            if record.get('eventSourceARN') != os.environ['NOTICE_QUEUE_ARN']:
                raise ValueError('queue source')
            if len(record['body']) > 1024: raise ValueError('message size')
            notice = json.loads(record['body'])
            deliver(notice, table, ses, os.environ['NOTICE_FROM'], os.environ['NOTICE_FEEDBACK'])
        except Exception as error:
            # Let SQS retry; no event bodies, emails or provider errors in logs.
            failures.append({'itemIdentifier': record['messageId']})
            code = getattr(error, 'response', {}).get('Error', {}).get('Code', type(error).__name__)
            if isinstance(notice, dict) and re.fullmatch('[a-f0-9]{64}', str(notice.get('event', ''))) and re.fullmatch('[A-Za-z0-9_]{1,80}', code):
                try:
                    table.update_item(Key={'id': 'event#'+notice['event']},
                        UpdateExpression='SET last_error=:code', ConditionExpression='attribute_exists(id)',
                        ExpressionAttributeValues={':code': code})
                except Exception: pass
    return {'batchItemFailures': failures}
