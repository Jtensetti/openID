"""Synthetic acceptance lifecycle; assertion authenticity is tested at the native boundary."""
import base64
from contextlib import contextmanager
import json
import sqlite3
import unittest

import acceptance_journal as journal
from enrollment_policy import EnrollmentPolicy
from test_enrollment_policy import fixture_policy, NOW


class AcceptanceJournalTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:', isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('CREATE TABLE credentials(id TEXT PRIMARY KEY)')
        journal.install_sqlite(self.db)
        self.policy = EnrollmentPolicy(fixture_policy(), clock=lambda: NOW)
        self.key = base64.b64encode(b'synthetic device key').decode()
        self.payload = {'id': 'a'*43, 'nonce': 'b'*43, 'devicePublicKey': self.key,'receipt':'c'*64,
            'acceptance': {'policyDigest': self.policy.digest, 'termsAccepted': True, 'biometricsAccepted': True}}
        self.proof = {'payload': base64.b64encode(json.dumps(self.payload).encode()).decode(),
            'assertion': 'synthetic-assertion', 'appPublicKey': 'synthetic-app-key'}

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN')
        try:
            yield self.db
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def store(self, receipt='c'*64):
        with self.transaction() as db: journal.store(db, receipt, self.key, self.policy, self.proof, NOW)

    def test_acceptance_precedes_identity_and_binds_only_once_to_the_matching_key(self):
        self.store()
        self.assertEqual(0, self.db.execute('SELECT count(*) FROM credentials').fetchone()[0])
        journal.require_pending(self.db, 'c'*64, self.key, NOW+1)
        with self.assertRaises(ValueError): journal.require_pending(self.db, 'c'*64, 'd3Jvbmc=', NOW+1)
        who = journal.subject(self.key)
        with self.transaction() as db:
            db.execute('INSERT INTO credentials VALUES(?)', (who,))
            journal.bind(db, who, 'c'*64, self.key, NOW+2)
        with self.assertRaises(ValueError): journal.require_pending(self.db, 'c'*64, self.key, NOW+3)
        with self.assertRaises(ValueError): self.store('d'*64)

    def test_bound_acceptance_is_rechecked_before_commit(self):
        self.store(); who = journal.subject(self.key)
        with self.transaction() as db:
            db.execute('INSERT INTO credentials VALUES(?)', (who,))
            journal.bind(db, who, 'c'*64, self.key, NOW+1)
            journal.require_bound(db, who, 'c'*64, NOW+2)
            for credential, receipt, now in [(who, 'c'*64, NOW+300),
                    ('d'*64, 'c'*64, NOW+2), (who, 'd'*64, NOW+2)]:
                with self.assertRaises(ValueError): journal.require_bound(db, credential, receipt, now)
            changed = fixture_policy(); changed['notice']['terms'] = 'Changed'
            db.execute('UPDATE enrollment_policies SET record=?', (json.dumps(changed),))
            with self.assertRaises(ValueError): journal.require_bound(db, who, 'c'*64, NOW+2)
            db.execute('UPDATE enrollment_policies SET record=?', (json.dumps(fixture_policy()),))
            journal.withdraw(db, 'c'*64, NOW+2)
            with self.assertRaises(ValueError): journal.require_bound(db, who, 'c'*64, NOW+3)

    def test_expired_withdrawn_unknown_and_future_receipts_never_authorize_processing(self):
        self.store()
        for ident, now in [('c'*64, NOW-1), ('c'*64, NOW+300), ('d'*64, NOW)]:
            with self.assertRaises(ValueError): journal.require_pending(self.db, ident, self.key, now)
        journal.withdraw(self.db, 'c'*64, NOW+10)
        journal.withdraw(self.db, 'c'*64, NOW+11)
        self.assertEqual(NOW+10, self.db.execute('SELECT withdrawn FROM enrollment_consents').fetchone()[0])
        with self.assertRaises(ValueError): journal.require_pending(self.db, 'c'*64, self.key, NOW+12)

    def test_failed_enrollment_does_not_consume_receipt_or_leave_a_partial_credential(self):
        self.store(); who = journal.subject(self.key)
        with self.assertRaises(RuntimeError):
            with self.transaction() as db:
                db.execute('INSERT INTO credentials VALUES(?)', (who,))
                journal.bind(db, who, 'c'*64, self.key, NOW+1)
                raise RuntimeError('simulated profile write failure')
        self.assertEqual(0, self.db.execute('SELECT count(*) FROM credentials').fetchone()[0])
        self.assertEqual(0, self.db.execute('SELECT count(*) FROM credential_consents').fetchone()[0])
        journal.require_pending(self.db, 'c'*64, self.key, NOW+2)

    def test_changed_archive_or_expired_notice_cannot_authorize_an_unused_receipt(self):
        self.store()
        changed = fixture_policy(); changed['notice']['terms'] = 'Changed'
        self.db.execute('UPDATE enrollment_policies SET record=?', (json.dumps(changed),))
        with self.assertRaises(ValueError): journal.require_pending(self.db, 'c'*64, self.key, NOW+1)

    def test_passport_fields_or_mismatched_choice_are_not_accepted_as_receipt_evidence(self):
        for extra in ({'dg1': 'not-permitted'}, {'devicePublicKey': 'd3Jvbmc='}, {'acceptance': {}}):
            self.proof['payload'] = base64.b64encode(json.dumps(self.payload | extra).encode()).decode()
            with self.assertRaises(ValueError): self.store()
        self.assertEqual(0, self.db.execute('SELECT count(*) FROM enrollment_consents').fetchone()[0])
        self.assertEqual(0, self.db.execute('SELECT count(*) FROM enrollment_policies').fetchone()[0])


if __name__ == '__main__': unittest.main()
