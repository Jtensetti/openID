"""Synthetic transaction tests. Crypto and DynamoDB are deliberately stubbed."""
import base64
import copy
from pathlib import Path
import tempfile
import unittest
from continuity_operator import prepare
from revocation import RevocationAuthority
from wallet import Wallet


class Client:
    def __init__(self): self.items = {}; self.fail = False
    def transact_write_items(self, TransactItems):
        if self.fail: raise OSError('unavailable')
        pending = []
        for request in TransactItems:
            put = request['Put']; item = put['Item']
            key = (put['TableName'], next(iter(item.values()))['S'])
            if key in self.items: raise ValueError('conditional write rejected')
            pending.append((key, copy.deepcopy(item)))
        self.items.update(pending)
    def get_item(self, TableName, Key, ConsistentRead):
        assert ConsistentRead is True
        return {'Item': copy.deepcopy(self.items.get((TableName, next(iter(Key.values()))['S'])))}


class OperatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        authority = RevocationAuthority(lambda request: {'credential': request['credential'], 'state': 'UNKNOWN'})
        self.wallet = Wallet(Path(self.tmp.name)/'wallet.sqlite', 'https://example.invalid',
            clock=lambda: 1000, crypto=lambda *a, **k: None, revocation=authority, notifications=True)
        self.ident = self.wallet.enroll(base64.b64encode(b'synthetic-key').decode())['id']
        self.aads = []
        def crypt(operation, credential, domain, value):
            self.aads.append((credential, domain))
            return {'synthetic': value} if operation == 'seal' else value['synthetic']
        self.wallet.vault.crypt = crypt
        with self.wallet.transaction() as db:
            db.execute('INSERT INTO persons VALUES(?,?)', ('synthetic-person', 'synthetic-document'))
            db.execute('INSERT INTO profiles VALUES(?,?,?,?,?,?)',
                (self.ident, 'synthetic-person', 'synthetic-version', '{}', 1000, 9999))
        self.client = Client()

    def prepare(self, email='synthetic@example.invalid', evidence='synthetic-review-01'):
        return prepare(self.wallet, self.ident, email, evidence, self.client, 'ledger', 'contacts')

    def test_retry_is_idempotent_and_never_activates(self):
        self.assertTrue(self.prepare()['activationRequired'])
        original = copy.deepcopy(self.client.items)
        self.prepare()
        self.assertEqual(original, self.client.items)
        with self.wallet.transaction() as db:
            self.assertEqual('PENDING_REVIEW', self.wallet.credential(db, self.ident)['state'])
            self.assertEqual(1, db.execute('SELECT count(*) FROM notice_contacts').fetchone()[0])
        self.assertTrue(all(domain == 'revocation-token-v1' for _, domain in self.aads))

    def test_cloud_failure_keeps_staged_proof_but_does_not_bind_contact(self):
        self.client.fail = True
        with self.assertRaises(ValueError): self.prepare()
        with self.wallet.transaction() as db:
            staged = db.execute('SELECT sealed FROM revocation_codes').fetchone()[0]
            self.assertEqual(0, db.execute('SELECT count(*) FROM notice_contacts').fetchone()[0])
        self.client.fail = False
        self.prepare()
        with self.wallet.transaction() as db:
            self.assertEqual(staged, db.execute('SELECT sealed FROM revocation_codes').fetchone()[0])

    def test_revoked_remote_record_cannot_be_replaced(self):
        self.prepare()
        self.client.items[('ledger', self.ident)]['state'] = {'S': 'REVOKED'}
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual({'S': 'REVOKED'}, self.client.items[('ledger', self.ident)]['state'])

    def test_contact_and_review_cannot_be_changed(self):
        self.prepare()
        with self.assertRaises(ValueError): self.prepare(email='attacker@example.invalid')
        with self.assertRaises(ValueError): self.prepare(evidence='different-review-01')


if __name__ == '__main__': unittest.main()
