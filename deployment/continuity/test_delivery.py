import copy
import unittest
from delivery import deliver


class Table:
    def __init__(self):
        self.items = {'contact#synthetic-contact-01': {
            'verified': True, 'recipient': 'synthetic@example.invalid', 'evidence': 'synthetic-review'}}

    def get_item(self, Key, ConsistentRead):
        assert ConsistentRead is True
        return {'Item': copy.deepcopy(self.items.get(Key['id'], {}))}

    def update_item(self, **kwargs):
        values = kwargs['ExpressionAttributeValues']
        key = kwargs['Key']['id']
        row = self.items.setdefault(key, {})
        if 'ConditionExpression' in kwargs:
            if row.get('state') == 'ACCEPTED' or row.get('lease_until', -1) >= values[':now']:
                raise ValueError('lease held')
            row.update(state='SENDING', lease_until=values[':until'])
        else: row.update(state='ACCEPTED', receipt=values[':receipt'])


class Sender:
    def __init__(self): self.calls = []; self.failed = False
    def send_email(self, **kwargs):
        self.calls.append(kwargs)
        if self.failed: raise OSError('ambiguous transport error')
        return {'MessageId': 'synthetic-receipt'}


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.table, self.sender = Table(), Sender()
        self.event = {'event': 'a'*64, 'contactVersion': 'synthetic-contact-01',
                      'kind': 'ACTIVATED_V1', 'created': 1000}
        self.now = 1000

    def send(self):
        deliver(self.event, self.table, self.sender, 'sender@example.invalid',
                'feedback@example.invalid', clock=lambda: self.now)

    def test_accepted_notice_is_not_resent_or_marked_delivered(self):
        self.send(); self.send()
        self.assertEqual(1, len(self.sender.calls))
        self.assertEqual('ACCEPTED', self.table.items['event#'+'a'*64]['state'])

    def test_recipient_cannot_be_injected_into_queue(self):
        self.event['recipient'] = 'attacker@example.invalid'
        with self.assertRaises(ValueError): self.send()
        self.assertEqual([], self.sender.calls)

    def test_unknown_unverified_and_missing_evidence_contact_block_send(self):
        for field in ['verified', 'evidence', 'recipient']:
            self.table = Table()
            del self.table.items['contact#synthetic-contact-01'][field]
            with self.subTest(field=field), self.assertRaises(ValueError): self.send()
        self.assertEqual([], self.sender.calls)

    def test_ambiguous_failure_waits_for_lease_and_preserves_event(self):
        self.sender.failed = True
        with self.assertRaises(OSError): self.send()
        self.sender.failed = False
        with self.assertRaises(ValueError): self.send()
        self.now += 91
        self.send()
        self.assertEqual(2, len(self.sender.calls))
        self.assertEqual('ACCEPTED', self.table.items['event#'+'a'*64]['state'])

    def test_synthetic_delivery_template_does_not_claim_activation(self):
        self.event['kind'] = 'DELIVERY_TEST_V1'
        self.send()
        body = self.sender.calls[0]['Content']['Simple']['Body']['Text']['Data']
        self.assertIn('Inget ID har aktiverats', body)


if __name__ == '__main__': unittest.main()
