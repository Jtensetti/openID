import hashlib
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from authority import Authority, public_handler, backend_handler, TEST_BETA_END


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

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues,
                    ExpressionAttributeNames=None, ConditionExpression=None):
        if UpdateExpression == 'SET beta_ends_at = :ends':
            assert ConditionExpression == 'attribute_not_exists(credential)'
            with self.lock:
                if Key['credential'] in self.items: raise ConditionFailed()
                self.items[Key['credential']] = {'beta_ends_at':ExpressionAttributeValues[':ends']}
            return
        if ConditionExpression == 'attribute_not_exists(credential)':
            assert UpdateExpression == 'SET #state = :enabled, token_hash = :hash, beta_ends_at = :ends'
            with self.lock:
                if Key['credential'] in self.items: raise ConditionFailed()
                self.items[Key['credential']] = {'state':ExpressionAttributeValues[':enabled'],
                    'token_hash':ExpressionAttributeValues[':hash'], 'beta_ends_at':ExpressionAttributeValues[':ends']}
            return
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
        self.assertEqual(200, self.call({'requestContext': {'http': {'method': 'GET'}}})['statusCode'])
        self.assertEqual(400, self.call(self.event(confirm=False))['statusCode'])
        self.assertEqual('ENABLED', self.authority.status(self.credential)['state'])

    def test_browser_form_and_base64_payload(self):
        import base64
        body = 'code='+self.credential+'.'+self.token+'&confirm=yes'
        event = self.event()
        event.update(headers={'content-type': 'application/x-www-form-urlencoded'},
                     body=base64.b64encode(body.encode()).decode(), isBase64Encoded=True)
        result = self.call(event)
        self.assertEqual(200, result['statusCode'])
        self.assertIn('text/html', result['headers']['Content-Type'])
        self.assertNotIn(self.token, result['body'])
        self.assertEqual('REVOKED', self.authority.status(self.credential)['state'])

    def test_duplicate_confirmation_is_rejected(self):
        event = self.event()
        event.update(headers={'content-type': 'application/x-www-form-urlencoded'},
                     body='code='+self.credential+'.'+self.token+'&confirm=yes&confirm=no')
        self.assertEqual(400, self.call(event)['statusCode'])
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

    def test_test_registration_is_explicit_backend_only_and_never_reactivates(self):
        ident = 'c'*64; digest = hashlib.sha256(self.token.encode()).hexdigest()
        with self.assertRaises(ValueError): self.authority.register_test(ident, digest)
        self.authority.test_beta = True
        event = {'operation':'register-test-beta', 'credential':ident, 'tokenHash':digest}
        with patch('authority.store', return_value=self.authority):
            result = backend_handler(event, None)
            self.assertEqual(TEST_BETA_END, result['betaEndsAt'])
            self.assertEqual(result, backend_handler(event, None))
        with self.assertRaises(ValueError): self.authority.register_test(ident, 'd'*64)
        self.authority.revoke(ident)
        with self.assertRaises(ValueError): self.authority.register_test(ident, digest)
        self.assertEqual('REVOKED', self.authority.status(ident)['state'])
        public = {'requestContext':{'http':{'method':'POST'}}, 'body':json.dumps(event)}
        self.assertEqual(400, self.call(public)['statusCode'])

    def test_campaign_end_revokes_old_and_new_ids_without_test_server(self):
        self.authority.test_beta = True
        self.authority.register_test('c'*64, 'd'*64)
        self.authority.test_beta = False  # Configuration rollback cannot undo campaign revocation.
        self.authority.clock = lambda:TEST_BETA_END
        for ident in (self.credential, 'c'*64):
            self.assertEqual('REVOKED', self.authority.status(ident)['state'])
            self.assertEqual('REVOKED', self.table.items[ident]['state'])
        with self.assertRaises(ValueError): self.authority.register_test('e'*64, 'f'*64)
        self.assertNotIn('e'*64, self.table.items)
        # Persisted tombstones cannot disappear if the clock is later corrected backwards.
        self.authority.clock = lambda:123
        self.assertEqual('REVOKED', self.authority.status(self.credential)['state'])

    def test_concurrent_registration_and_revoke_leave_a_tombstone(self):
        self.authority.test_beta = True
        def register(_):
            try: self.authority.register_test('c'*64, 'd'*64)
            except ValueError: pass
        with ThreadPoolExecutor(8) as pool:
            tasks = [pool.submit(register, i) for i in range(8)]
            tasks.append(pool.submit(self.authority.revoke, 'c'*64))
            for task in tasks: task.result()
        self.assertEqual('REVOKED', self.authority.status('c'*64)['state'])

    def test_campaign_dates_match_wallet_contract(self):
        from pathlib import Path
        import re
        root = Path(__file__).resolve().parents[2]
        wallet = (root/'verification/wallet.py').read_text()
        deadline = int(re.search(r'^TEST_BETA_END = ([0-9]+)', wallet, re.M)[1])
        self.assertEqual(deadline, TEST_BETA_END)


if __name__ == '__main__': unittest.main()
