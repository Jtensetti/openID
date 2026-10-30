"""Synthetic policy/acceptance boundaries; no adopted terms or actual participants."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from enrollment_policy import EnrollmentPolicy, read_policy


NOW = 2_000_000_000


def fixture_policy():
    return {'schema': 1, 'decisionReference': 'SYNTHETIC_DECISION_001', 'notice': {
        'version': 'SYNTHETIC_TERMS_001', 'locale': 'sv-SE',
        'notBefore': NOW-60, 'notAfter': NOW+600,
        'controller': 'Syntetisk testoperatör — inget verkligt avtal',
        'contact': 'privacy@example.invalid', 'terms': 'Syntetiska testvillkor.',
        'privacy': 'Endast genererade testuppgifter används i dessa prov.',
        'biometrics': 'Syntetiskt explicit val för biometriskt teständamål.',
        'withdrawal': 'Syntetisk beskrivning av återkallelse; ingen verklig tjänst.'}}


class EnrollmentPolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = NOW
        self.policy = EnrollmentPolicy(fixture_policy(), clock=lambda: self.now)

    def accept(self):
        return {'policyDigest': self.policy.digest, 'termsAccepted': True, 'biometricsAccepted': True}

    def test_distinct_choices_and_exact_text_version_are_required(self):
        self.assertEqual(self.accept(), self.policy.acceptance(self.accept()))
        invalid = [{}, self.accept() | {'policyDigest': '0'*64}, self.accept() | {'privacyAccepted': True}]
        for field in ('termsAccepted', 'biometricsAccepted'):
            for value in (False, 1, 'true', None): invalid.append(self.accept() | {field: value})
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError): self.policy.acceptance(value)

    def test_text_change_invalidates_an_old_acceptance_even_with_same_version_label(self):
        before = self.accept()
        for field in ('terms', 'privacy', 'biometrics', 'withdrawal', 'controller', 'contact'):
            value = fixture_policy(); value['notice'][field] += ' Ändrat.'
            changed = EnrollmentPolicy(value, clock=lambda: self.now)
            self.assertNotEqual(changed.digest, self.policy.digest)
            with self.assertRaises(ValueError): changed.acceptance(before)

    def test_expiry_is_checked_again_when_serving_and_accepting(self):
        self.now = NOW+600
        for action in (self.policy.public, lambda: self.policy.acceptance(self.accept())):
            with self.assertRaises(ValueError): action()
        self.now = NOW-61
        with self.assertRaises(ValueError): self.policy.public()

    def test_caller_or_client_cannot_mutate_archived_text(self):
        value = fixture_policy(); policy = EnrollmentPolicy(value, clock=lambda: NOW)
        digest = policy.digest
        value['notice']['terms'] = 'tampered'
        policy.public()['noticeJSON'] = 'tampered'
        policy.archived()['notice']['biometrics'] = 'tampered'
        self.assertEqual(digest, policy.digest)
        self.assertEqual(fixture_policy(), policy.archived())
        self.assertNotIn('decisionReference', policy.public())

    def test_incomplete_future_oversized_or_hidden_text_is_rejected(self):
        bad = []
        for field in ('controller', 'contact', 'terms', 'privacy', 'biometrics', 'withdrawal'):
            for text in ('', '  ', 'visat\u202etext', 'x'*16385):
                value = fixture_policy(); value['notice'][field] = text; bad.append(value)
        for at in (NOW+1, NOW+601, True):
            value = fixture_policy(); value['notice']['notBefore'] = at; bad.append(value)
        for change in ({'decisionReference': ''}, {'schema': True}, {'unknown': 1}):
            bad.append(fixture_policy() | change)
        value=fixture_policy(); del value['notice']['withdrawal']; bad.append(value)
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError): EnrollmentPolicy(value, clock=lambda: NOW)

    def test_file_boundary_rejects_duplicate_fields_links_and_shared_access(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); path = root/'policy.json'
            path.write_text(json.dumps(fixture_policy())); path.chmod(0o600)
            self.assertEqual(self.policy.digest, read_policy(path, clock=lambda: NOW).digest)
            for mode in (0o644, 0o640):
                path.chmod(mode)
                with self.assertRaises(ValueError): read_policy(path, clock=lambda: NOW)
            path.chmod(0o600)
            link = root/'link'; link.symlink_to(path)
            with self.assertRaises(OSError): read_policy(link, clock=lambda: NOW)
            link.unlink(); os.link(path, link)
            with self.assertRaises(ValueError): read_policy(path, clock=lambda: NOW)
            link.unlink()
            path.write_text(json.dumps(fixture_policy()).replace('"schema": 1', '"schema": 1, "schema": 1'))
            with self.assertRaises(ValueError): read_policy(path, clock=lambda: NOW)
            with self.assertRaises(ValueError): read_policy('relative.json', clock=lambda: NOW)


if __name__ == '__main__': unittest.main()
