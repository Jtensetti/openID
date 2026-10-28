"""Generated rejection cases for ACL source, key, test and package binding."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from candidate import (build, check_dsc, check_packages, check_public_keys,
                       check_results, fetch_inputs, load_lock)


class ACLCandidateTests(unittest.TestCase):
    def setUp(self):
        self.lock = load_lock()

    def dsc(self):
        lines = ['Format: 3.0 (quilt)', 'Source: acl',
                 'Version: ' + self.lock['packagingVersion'], 'Checksums-Sha256:']
        lines += [' ' + p['sha256'] + ' ' + str(p['bytes']) + ' ' + p['filename']
                  for p in self.lock['inputs'] if not p['filename'].endswith('.dsc')]
        return '\n'.join(lines) + '\n'

    def test_signed_source_binds_every_input_and_exact_identity(self):
        self.assertEqual(check_dsc(self.dsc(), self.lock)['Source'], 'acl')
        for bad in [self.dsc().replace('Source: acl', 'Source: other'),
                    self.dsc().replace('Version: 2.4.0-1', 'Version: 2.4.0-2'),
                    self.dsc().replace('384828', '384829'),
                    self.dsc() + self.dsc().splitlines()[-1] + '\n',
                    '\n'.join(self.dsc().splitlines()[:-1])]:
            with self.subTest(case=bad[-100:]), self.assertRaises(ValueError):
                check_dsc(bad, self.lock)

    def test_unexpected_or_unsafe_signed_input_rejected(self):
        for name in ('extra.tar', '../elsewhere', '/absolute'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                check_dsc(self.dsc() + ' ' + 'a' * 64 + ' 1 ' + name + '\n', self.lock)

    def test_exact_public_key_set_accepts_only_full_fingerprints(self):
        keys = self.lock['upstreamPrimaryFingerprints']
        listing = '\n'.join('pub:::::::::\nfpr:::::::::' + key + ':' for key in keys)
        self.assertEqual(check_public_keys(listing, keys), keys)
        for bad in [listing.replace('pub', 'sec', 1), listing + '\nssb:::::::::',
                    listing.replace(keys[0], keys[0][-16:]), listing.replace(keys[0], 'A' * 40),
                    listing + '\npub:::::::::\nfpr:::::::::' + keys[0] + ':',
                    listing + '\npub:::::::::']:
            with self.subTest(case=bad[-70:]), self.assertRaises(ValueError):
                check_public_keys(bad, keys)

    def write_results(self, root):
        for name in self.lock['requiredPassingTests'] + self.lock['environmentLimitedTests']:
            path = (root / name).with_suffix('.trs')
            path.parent.mkdir(parents=True, exist_ok=True)
            result = 'PASS' if name in self.lock['requiredPassingTests'] else 'SKIP'
            path.write_text(':test-result: ' + result + '\n:global-test-result: ' + result + '\n')

    def test_required_regressions_cannot_be_skipped_or_failed(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.write_results(root)
            self.assertEqual(len(check_results(root, self.lock)), 16)
            path = (root / self.lock['requiredPassingTests'][0]).with_suffix('.trs')
            for result in ('SKIP', 'XFAIL', 'FAIL', 'XPASS', 'ERROR'):
                path.write_text(':test-result: ' + result + '\n')
                with self.subTest(result=result), self.assertRaises(ValueError):
                    check_results(root, self.lock)

    def test_environment_limits_never_hide_failures_or_missing_results(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.write_results(root)
            path = (root / self.lock['environmentLimitedTests'][0]).with_suffix('.trs')
            for result in ('FAIL', 'XPASS', 'ERROR', 'PASS\n:test-result: SKIP'):
                path.write_text(':test-result: ' + result + '\n')
                with self.subTest(result=result), self.assertRaises(ValueError):
                    check_results(root, self.lock)
            path.unlink()
            with self.assertRaises(ValueError):
                check_results(root, self.lock)

    def test_test_result_links_are_rejected_even_when_target_passes(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.write_results(root)
            result = (root / self.lock['requiredPassingTests'][0]).with_suffix('.trs')
            target = root / 'external-result'
            result.rename(target)
            result.symlink_to(target)
            with self.assertRaises(ValueError):
                check_results(root, self.lock)

    def packages(self):
        return [{'Package': name, 'Version': self.lock['candidateVersion'],
                 'Source': 'acl (' + self.lock['candidateVersion'] + ')', 'Architecture': 'amd64',
                 'filename': name + '_' + self.lock['candidateVersion'] + '_amd64.deb',
                 'bytes': 100, 'sha256': 'a' * 64} for name in ('acl', 'libacl1', 'libacl1-dev')]

    def test_binary_group_requires_exact_versions_sources_and_architecture(self):
        packages = self.packages()
        self.assertEqual(len(check_packages(packages, self.lock['candidateVersion'])), 3)
        for field, value in [('Version', '2.4.0-1'), ('Source', 'other'), ('Architecture', 'arm64'),
                             ('filename', '../escaped.deb'), ('bytes', True), ('sha256', 'short')]:
            bad = copy.deepcopy(packages)
            bad[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check_packages(bad, self.lock['candidateVersion'])
        for bad in (packages[:-1], packages + [packages[0]]):
            with self.assertRaises(ValueError):
                check_packages(bad, self.lock['candidateVersion'])

    def test_developer_host_is_rejected_before_build_output(self):
        with tempfile.TemporaryDirectory() as name, patch('candidate.platform.system', return_value='Darwin'):
            output = Path(name) / 'output'
            with self.assertRaises(ValueError):
                build(Path(name), output, self.lock)
            self.assertFalse(output.exists())

    def test_fetch_rejects_foreign_origins_before_network_access(self):
        for field, value in [('url', 'https://example.invalid/source'), ('filename', '../escape'), ('bytes', True)]:
            with tempfile.TemporaryDirectory() as name, patch('candidate.urllib.request.urlopen') as network:
                lock = copy.deepcopy(self.lock)
                lock['inputs'][0][field] = value
                with self.assertRaises(ValueError):
                    fetch_inputs(Path(name) / 'inputs', lock)
                network.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
