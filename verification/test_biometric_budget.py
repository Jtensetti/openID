"""The budget is committed before a decision and shared by independent wallet instances."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest

from test_identity import document
from wallet import Wallet, BiometricAttemptLimit, EnrollmentQuarantine, BIOMETRIC_ATTEMPTS, BIOMETRIC_WINDOW


class BiometricBudgetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.time = 1792454400
        self.path = Path(self.tmp.name)/'wallet.sqlite'
        self.wallets = [Wallet(self.path, 'https://localhost:8765', clock=lambda: self.time) for _ in range(4)]
        self.wallets[0].vault.key(create=True)

    def test_parallel_instances_spend_exactly_five_and_restart_cannot_refund(self):
        def attempt(i):
            try: return self.wallets[i % len(self.wallets)].biometric_attempt(document())
            except BiometricAttemptLimit: return None
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(attempt, range(32)))
        self.assertEqual(list(range(BIOMETRIC_ATTEMPTS)), sorted(r for r in results if r is not None))
        restarted = Wallet(self.path, 'https://localhost:8765', clock=lambda: self.time)
        with self.assertRaises(BiometricAttemptLimit): restarted.biometric_attempt(document())
        self.assertEqual(4, restarted.biometric_attempt(document(documentNumber='TEST00009')))
        self.time += BIOMETRIC_WINDOW  # boundary is exclusive for old reservations
        self.assertEqual(4, restarted.biometric_attempt(document()))

    def test_lost_hmac_key_cannot_silently_reset_spent_budget_without_a_profile(self):
        self.wallets[0].biometric_attempt(document())
        self.wallets[0].vault.path.unlink()
        with self.assertRaises(FileNotFoundError): self.wallets[1].biometric_attempt(document())
        with self.assertRaises(FileNotFoundError): self.wallets[1].health()
        self.assertFalse(self.wallets[1].vault.path.exists())

    def test_unverified_document_cannot_spend_a_budget(self):
        with self.assertRaises(ValueError): self.wallets[0].biometric_attempt({})

    def test_old_backup_pauses_enrollment_for_a_full_window_and_keeps_index_key(self):
        from unittest.mock import patch,Mock
        from recovery import backup,bind_backup,restore
        from native import NativeSessions
        from test_wallet import crypt
        import json
        wallet=self.wallets[0]
        wallet.biometric_attempt(document())
        saved=backup(wallet,Path(self.tmp.name)/'saved')
        import hashlib
        binding=Path(self.tmp.name)/'binding.json'
        anchor=bind_backup(saved,wallet.vault.path,hashlib.sha256(wallet.vault.key()).hexdigest(),binding)
        for _ in range(BIOMETRIC_ATTEMPTS-1):wallet.biometric_attempt(document())
        with patch('recovery.time.time',return_value=self.time):
            target=restore(saved,Path(self.tmp.name)/'restored',wallet.vault.path,
                           binding=binding,binding_sha256=anchor)
        recovered=Wallet(target,wallet.origin,clock=lambda:self.time)
        self.assertEqual(wallet.vault.key(),recovered.vault.key())  # no profile existed at backup time
        key=json.loads(crypt(op='new'))['publicKey']
        for operation in (recovered.enrollment_available,lambda:recovered.biometric_attempt(document()),lambda:recovered.enroll(key)):
            with self.assertRaises(EnrollmentQuarantine):operation()
        restarted=Wallet(target,wallet.origin,clock=lambda:self.time)
        native=NativeSessions(Mock(),Mock(),Mock(),Mock(),wallet=restarted);self.addCleanup(native.close)
        with self.assertRaises(EnrollmentQuarantine):native.start()
        self.assertEqual({},native.pending)
        self.time+=BIOMETRIC_WINDOW-1
        with self.assertRaises(EnrollmentQuarantine):restarted.biometric_attempt(document())
        self.time+=1
        self.assertEqual(4,restarted.biometric_attempt(document()))
        self.assertEqual('PENDING_REVIEW',restarted.enroll(key)['state'])


if __name__ == '__main__': unittest.main()
