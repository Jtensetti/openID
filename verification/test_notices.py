import base64
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from notices import bind_contact, export_once, submit
from wallet import Wallet


class NoticeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.wallet = Wallet(Path(self.tmp.name)/'wallet.sqlite', 'https://example.invalid',
            clock=lambda: 1000, crypto=lambda *a, **k: None, notifications=True)
        self.ident = self.wallet.enroll(base64.b64encode(b'synthetic').decode())['id']

    def bind(self):
        with self.wallet.transaction() as db:
            bind_contact(db, self.ident, 'synthetic-contact-v1', 'synthetic-evidence-1')

    def test_unverified_contact_rolls_back_activation(self):
        with self.assertRaises(ValueError): self.wallet.activate(self.ident, 'synthetic-review')
        with self.wallet.transaction() as db:
            self.assertEqual('PENDING_REVIEW', self.wallet.credential(db, self.ident)['state'])
            self.assertEqual(0, db.execute('SELECT count(*) FROM notice_outbox').fetchone()[0])
            self.assertEqual(0, db.execute("SELECT count(*) FROM events WHERE kind='ACTIVATED'").fetchone()[0])

    def test_crash_rolls_back_both_activation_and_notice(self):
        self.bind()
        with self.assertRaises(RuntimeError), self.wallet.transaction() as db:
            self.wallet._activate(db, self.ident, 'synthetic-review')
            raise RuntimeError('crash')
        with self.wallet.transaction() as db:
            self.assertEqual(0, db.execute('SELECT count(*) FROM notice_outbox').fetchone()[0])
            self.assertEqual('PENDING_REVIEW', self.wallet.credential(db, self.ident)['state'])

    def test_contact_cannot_be_redirected(self):
        self.bind()
        with self.assertRaises(sqlite3.IntegrityError), self.wallet.transaction() as db:
            bind_contact(db, self.ident, 'another-contact-v1', 'synthetic-evidence-2')

    def test_queue_failure_then_retry_does_not_repeat_activation(self):
        self.bind()
        self.wallet.activate(self.ident, 'synthetic-review')
        attempts = []
        def fail(event):
            attempts.append(event)
            raise OSError('private provider detail')
        with self.wallet.transaction() as db: submit(db, fail)
        def succeed(event):
            attempts.append(event)
            return 'synthetic-queue-receipt'
        with self.wallet.transaction() as db: submit(db, succeed)
        with self.wallet.transaction() as db:
            submit(db, succeed)
            row = db.execute('SELECT * FROM notice_outbox').fetchone()
            self.assertEqual('QUEUED', row['status'])
            self.assertEqual(2, row['attempts'])
            self.assertEqual(1, db.execute("SELECT count(*) FROM events WHERE kind='ACTIVATED'").fetchone()[0])
        self.assertEqual(2, len(attempts))
        self.assertEqual(attempts[0], attempts[1])
        self.assertNotIn('credential', attempts[0])

    def test_retries_are_bounded(self):
        self.bind()
        self.wallet.activate(self.ident, 'synthetic-review')
        calls = []
        def fail(event):
            calls.append(event)
            raise OSError()
        for _ in range(7):
            with self.wallet.transaction() as db: submit(db, fail)
        self.assertEqual(5, len(calls))

    def test_export_does_not_hold_wallet_lock_during_delivery(self):
        self.bind()
        self.wallet.activate(self.ident, 'synthetic-review')
        entered = threading.Event(); release = threading.Event(); errors = []
        def delayed_send(_event):
            entered.set()
            if not release.wait(3): raise TimeoutError('test release')
            return 'synthetic-queue-receipt'
        def export():
            try: export_once(self.wallet, delayed_send)
            except BaseException as exc: errors.append(exc)
        worker = threading.Thread(target=export); worker.start()
        try:
            self.assertTrue(entered.wait(2))
            # This uses a different connection while the queue call is waiting.
            with self.wallet.transaction() as db:
                db.execute("INSERT INTO events(credential,kind,time) VALUES(?,?,?)",
                           (self.ident, 'SYNTHETIC_CONCURRENT_EVENT', 1000))
        finally:
            release.set(); worker.join(3)
        self.assertFalse(worker.is_alive()); self.assertFalse(errors)
        with self.wallet.transaction() as db:
            self.assertEqual('QUEUED', db.execute('SELECT status FROM notice_outbox').fetchone()[0])
            plan = db.execute("""EXPLAIN QUERY PLAN SELECT event FROM notice_outbox
                WHERE status='PENDING' AND attempts<5 ORDER BY created,event LIMIT 1""").fetchall()
        self.assertTrue(any('notice_outbox_pending' in row[3] for row in plan))


if __name__ == '__main__': unittest.main()
