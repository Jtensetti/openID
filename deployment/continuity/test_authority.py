import hashlib
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from authority import Authority, public_handler


class ConditionFailed(Exception):
    response = {'Error': {'Code': 'ConditionalCheckFailedException'}}


class Table:
    """Atomic fake for negative tests; not evidence of a live DynamoDB test."""
    def __init__(self):
        self.items = {}
        self.lock = threading.Lock()

    def get_item(self, Key, ConsistentRead):
        assert ConsistentRead is True
        with self.lock: return {'Item': dict(self.items.get(Key['credential'], {}))}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeNames,
                    ExpressionAttributeValues, ConditionExpression=None):
        assert UpdateExpression == 'SET #state = :revoked, revoked_at = if_not_exists(revoked_at, :now)'
        assert ExpressionAttributeNames == {'#state': 'state'}
        with self.lock:
            item = self.items.get(Key['credential'], {})
            if ConditionExpression:
                assert ConditionExpression == 'token_hash = :hash'
                if item.get('token_hash') != ExpressionAttributeValues[':hash']: raise ConditionFailed()
            item['state'] = ExpressionAttributeValues[':revoked']
            item.setdefault('revoked_at', ExpressionAttributeValues[':now'])
            self.items[Key['credential']] = item


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.table = Table()
        self.authority = Authority(self.table, clock=lambda: 123)
        self.credential = 'a'*64
        self.token = 'x'*43
        self.table.items[self.credential] = {'state': 'ENABLED',
            'token_hash': hashlib.sha256(self.token.encode()).hexdigest()}

    def event(self, **changes):
        data = {'credential': self.credential, 'token': self.token, 'confirm': True}
        data.update(changes)
        return {'requestContext': {'http': {'method': 'POST'}}, 'body': json.dumps(data)}

    def call(self, event):
        with patch('authority.store', return_value=self.authority): return public_handler(event, None)

    def test_wrong_token_and_unknown_id_never_write(self):
        self.assertEqual(400, self.call(self.event(token='z'*43))['statusCode'])
        self.assertEqual(400, self.call(self.event(credential='b'*64))['statusCode'])
        self.assertEqual('ENABLED', self.authority.status(self.credential)['state'])
        self.assertNotIn('b'*64, self.table.items)

    def test_missing_null_and_short_token_never_use_backend_authority(self):
        for token in [None, '', 'short', 3]:
            self.assertEqual(400, self.call(self.event(token=token))['statusCode'])
        self.assertEqual('ENABLED', self.authority.status(self.credential)['state'])

    def test_email_scanner_get_and_missing_confirmation_never_revoke(self):
        self.assertEqual(405, self.call({'requestContext': {'http': {'method': 'GET'}}})['statusCode'])
        self.assertEqual(400, self.call(self.event(confirm=False))['statusCode'])
        self.assertEqual('ENABLED', self.authority.status(self.credential)['state'])

    def test_concurrent_replays_are_idempotent(self):
        with ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda _: self.call(self.event()), range(20)))
        self.assertTrue(all(r['statusCode'] == 200 for r in results))
        self.assertEqual('REVOKED', self.authority.status(self.credential)['state'])
        self.assertEqual(123, self.table.items[self.credential]['revoked_at'])

    def test_backend_can_tombstone_unknown_credential(self):
        self.authority.revoke('b'*64)
        self.assertEqual('REVOKED', self.authority.status('b'*64)['state'])

    def test_provider_failure_never_returns_success(self):
        with patch('authority.store', side_effect=OSError('private detail')):
            result = public_handler(self.event(), None)
        self.assertEqual(503, result['statusCode'])
        self.assertNotIn('private detail', result['body'])
        self.assertEqual('no-store', result['headers']['Cache-Control'])


if __name__ == '__main__': unittest.main()
