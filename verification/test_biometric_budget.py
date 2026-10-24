"""The budget is committed before a decision and shared by independent wallet instances."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest

from test_identity import document
from wallet import Wallet, BiometricAttemptLimit, BIOMETRIC_ATTEMPTS, BIOMETRIC_WINDOW


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
        self.assertFalse(self.wallets[1].vault.path.exists())

    def test_unverified_document_cannot_spend_a_budget(self):
        with self.assertRaises(ValueError): self.wallets[0].biometric_attempt({})


if __name__ == '__main__': unittest.main()
