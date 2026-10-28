"""Generated rejection cases; actual PGP/build evidence must come from Linux CI."""
import copy
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from bootstrap import check_deb, fields, package_index, sha, verify_archive
from build import (RUNTIME_PACKAGES, check_input, extract_regular, valid_signature,
                   validate_packages, primary_fingerprint, validate_key_refresh,
                   UPSTREAM_KEY_FILE, UPSTREAM_KEY_URL, fetch_inputs, load_lock,
                   verify_signature)


class CandidateInputTests(unittest.TestCase):
    def generated_packages(self):
        version = '2.41.6-0openid1'
        special = {'bsdutils': '1:2.41.6-0openid1',
                   'login': '1:4.16.0-2+really2.41.6-0openid1'}
        return [{'Package': name, 'Version': special.get(name, version),
                 'Source': 'util-linux (' + version + ')', 'Architecture': 'amd64',
                 'filename': name + '_' + special.get(name, version).split(':')[-1] + '_amd64.deb',
                 'bytes': 100, 'sha256': 'a' * 64} for name in sorted(RUNTIME_PACKAGES)]

    def test_complete_package_group_and_debian_epochs(self):
        packages = self.generated_packages()
        next(p for p in packages if p['Package'] == 'util-linux').pop('Source')
        debug = copy.deepcopy(next(p for p in packages if p['Package'] == 'login'))
        debug['Package'] = 'login-dbgsym'
        debug['filename'] = debug['filename'].replace('login_', 'login-dbgsym_', 1)
        packages.append(debug)
        selected = validate_packages(packages, '2.41.6-0openid1')
        self.assertEqual({p['Package'] for p in selected}, RUNTIME_PACKAGES)
        self.assertEqual(len(selected), 9)

    def test_package_group_rejects_missing_and_duplicate_members(self):
        packages = self.generated_packages()
        for bad in ([], packages[:-1], packages + [copy.deepcopy(packages[0])]):
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                validate_packages(bad, '2.41.6-0openid1')

    def test_package_identity_cannot_pass_by_version_substring(self):
        changes = [('Version', '1:2.41.6-0openid1-unreviewed'),
                   ('Version', '2.41.6-0openid1'),  # bsdutils must retain epoch 1.
                   ('Source', 'unrelated (2.41.6-0openid1)'),
                   ('Source', 'util-linux (2.41.5-0+deb13u1)'),
                   ('Architecture', 'arm64'), ('Architecture', 'all'),
                   ('filename', '../bsdutils.deb'), ('bytes', 0),
                   ('bytes', True), ('sha256', 'not-a-checksum')]
        for key, value in changes:
            with self.subTest(field=key, value=value):
                packages = self.generated_packages()
                packages[0][key] = value
                if key == 'Architecture':
                    packages[0]['filename'] = packages[0]['filename'].replace('_amd64.deb', '_' + value + '.deb')
                with self.assertRaises(ValueError):
                    validate_packages(packages, '2.41.6-0openid1')

    def test_archive_verifier_errors_or_changed_authenticated_payload_are_fatal(self):
        with tempfile.TemporaryDirectory() as name:
            evidence = Path(name)
            payload = evidence / 'Release.authenticated'
            payload.write_bytes(b'generated authenticated release')
            expected = sha(payload.read_bytes())
            success = subprocess.CompletedProcess(['sqv'], 0)
            failure = subprocess.CompletedProcess(['sqv'], 1)
            with patch('bootstrap.subprocess.run', return_value=success):
                verify_archive(evidence, expected)
                payload.write_bytes(b'changed release')
                with self.assertRaises(ValueError):
                    verify_archive(evidence, expected)
            # Even a matching pre-existing output must not excuse failed verification.
            payload.write_bytes(b'generated authenticated release')
            with patch('bootstrap.subprocess.run', return_value=failure):
                with self.assertRaises(subprocess.CalledProcessError):
                    verify_archive(evidence, expected)
            with patch('bootstrap.subprocess.run', side_effect=FileNotFoundError('sqv')):
                with self.assertRaises(FileNotFoundError):
                    verify_archive(evidence, expected)

    def test_debian_source_checksum_continuations_and_epoch(self):
        text = 'Version: 1:2.41.6-0openid1\nChecksums-Sha256:\n abc 123 upstream.tar\n def 456 debian.tar\n'
        actual = fields(text)
        self.assertEqual(actual['Version'], '1:2.41.6-0openid1')
        self.assertEqual([v.split() for v in actual['Checksums-Sha256'].splitlines() if v.strip()],
                         [['abc', '123', 'upstream.tar'], ['def', '456', 'debian.tar']])

    def test_authenticated_release_bytes_are_not_normalized(self):
        expected = b'Suite: stable\nSHA256:\n abc 12 main/Packages.xz'
        with tempfile.TemporaryDirectory() as name:
            evidence = Path(name)
            payload = evidence / 'Release.authenticated'
            with patch('bootstrap.subprocess.run', return_value=subprocess.CompletedProcess(['sqv'], 0)):
                payload.write_bytes(expected)
                verify_archive(evidence, sha(expected))
                for changed in (expected + b'\n', expected + b'\n\n', expected + b' ',
                                expected.replace(b'\n', b'\r\n'),
                                expected.replace(b'abc', b'def')):
                    with self.subTest(payload=changed), self.assertRaises(ValueError):
                        payload.write_bytes(changed)
                        verify_archive(evidence, sha(expected))
                payload.unlink()
                with self.assertRaises(FileNotFoundError):
                    verify_archive(evidence, sha(expected))

    def test_altered_or_linked_input_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'input'
            path.write_bytes(b'original')
            item = {'filename': 'input', 'bytes': 8, 'sha256': sha(b'original')}
            check_input(path, item)
            path.write_bytes(b'tampered')
            with self.assertRaises(ValueError):
                check_input(path, item)
            path.write_bytes(b'original')
            link = Path(name) / 'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                check_input(link, item)

    def test_locked_public_key_is_available_without_keyserver(self):
        item = next(item for item in load_lock()['inputs'] if item['url'] == UPSTREAM_KEY_URL)
        with tempfile.TemporaryDirectory() as name, patch('build.urllib.request.urlopen') as network:
            destination = Path(name) / 'inputs'
            fetch_inputs(destination, {'inputs': [item]})
            self.assertEqual((destination / item['filename']).read_bytes(), UPSTREAM_KEY_FILE.read_bytes())
            network.assert_not_called()

    def test_missing_changed_or_linked_public_key_has_no_network_fallback(self):
        item = next(item for item in load_lock()['inputs'] if item['url'] == UPSTREAM_KEY_URL)
        original = UPSTREAM_KEY_FILE.read_bytes()
        for kind in ('missing', 'changed', 'extra-newline', 'symlink', 'wrong-name'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                key = root / item['filename']
                bad_item = dict(item)
                if kind == 'changed':
                    key.write_bytes(b'X' + original[1:])
                elif kind == 'extra-newline':
                    key.write_bytes(original + b'\n')
                elif kind == 'symlink':
                    key.symlink_to(UPSTREAM_KEY_FILE)
                elif kind == 'wrong-name':
                    key.write_bytes(original)
                    bad_item['filename'] = 'unreviewed.asc'
                with patch('build.UPSTREAM_KEY_FILE', key), patch('build.urllib.request.urlopen') as network:
                    with self.assertRaises(ValueError):
                        fetch_inputs(root / 'inputs', {'inputs': [bad_item]})
                    network.assert_not_called()
                self.assertEqual(list((root / 'inputs').iterdir()), [])

    def test_network_sources_still_require_exact_bytes(self):
        raw = b'generated source'
        item = {'filename': 'source.tar', 'url':
                'https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/source.tar',
                'bytes': len(raw), 'sha256': sha(raw)}
        for content in (raw, raw[:-1], b'X' + raw[1:], raw + b'\n'):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as name:
                with patch('build.urllib.request.urlopen', return_value=io.BytesIO(content)):
                    if content == raw:
                        fetch_inputs(Path(name) / 'inputs', {'inputs': [item]})
                    else:
                        with self.assertRaisesRegex(ValueError, 'actual bytes=.* sha256='):
                            fetch_inputs(Path(name) / 'inputs', {'inputs': [item]})

    def test_only_valid_unexpired_signature_accepted(self):
        fingerprint = 'A' * 40
        good = '[GNUPG:] GOODSIG AAAAAAAA Developer\n[GNUPG:] VALIDSIG ' + fingerprint + ' 2026-10-27\n'
        self.assertEqual(valid_signature(good), fingerprint)
        for status in ('', '[GNUPG:] GOODSIG AAAAAAAA Developer', good + good,
                       '[GNUPG:] VALIDSIG ' + 'A' * 41 + ' 2026-10-27\n',
                       good + '[GNUPG:] EXPKEYSIG AAAAAAAA Developer\n',
                       good + '[GNUPG:] REVKEYSIG AAAAAAAA Developer\n',
                       good + '[GNUPG:] BADSIG AAAAAAAA Developer\n'):
            with self.subTest(status=status), self.assertRaises(ValueError):
                valid_signature(status)

    def test_binary_gpg_user_id_does_not_hide_signature_status(self):
        fingerprint = 'A' * 40
        good = (b'[GNUPG:] GOODSIG AAAAAAAA signer \x82 name\n'
                + b'[GNUPG:] VALIDSIG ' + fingerprint.encode('ascii') + b' 2026-10-27\n')
        self.assertEqual(valid_signature(good, fingerprint), fingerprint)
        for bad in (good + b'[GNUPG:] BADSIG AAAAAAAA signer \x82 name\n',
                    good + b'[GNUPG:] REVKEYSIG AAAAAAAA signer \x82 name\n',
                    good + b'[GNUPG:] VALIDSIG ' + fingerprint.encode('ascii') + b'\n',
                    good + b'[GNUPG:]BADSTATUS\n',
                    good + b'[GNUPG:] \x82\n',
                    good.replace(fingerprint.encode('ascii'), b'\x82' + b'A' * 39)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                valid_signature(bad, fingerprint)

    def test_human_diagnostics_cannot_forge_machine_status(self):
        fingerprint = 'A' * 40
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            log = directory / 'signature.log'
            def forged_output(command, stdout, stderr, timeout):
                self.assertEqual(command[:4], ['gpgv', '--homedir', str(directory), '--status-fd=1'])
                self.assertEqual(timeout, 1200)
                stderr.write(b'signer name\n[GNUPG:] VALIDSIG ' + fingerprint.encode('ascii') + b'\n')
                stdout.write(b'[GNUPG:] NO_PUBKEY 0000000000000000\n')
                return subprocess.CompletedProcess(command, 0)
            with patch('build.subprocess.run', side_effect=forged_output):
                with self.assertRaisesRegex(ValueError, 'rejected source signature'):
                    verify_signature(directory / 'sig', None, directory / 'ring', directory,
                                     log, fingerprint)
            self.assertIn(b'VALIDSIG', log.read_bytes())
            self.assertNotIn(b'VALIDSIG', (directory / 'signature-status.log').read_bytes())

    def test_duplicate_and_empty_package_indexes_rejected(self):
        record = b'Package: example\nVersion: 1:2.3\nArchitecture: amd64\nSHA256: abc\n'
        self.assertIn(('example', '1:2.3', 'amd64'), package_index(record))
        for bad in (b'', record + b'\n' + record):
            with self.assertRaises(ValueError):
                package_index(bad)

    def test_key_refresh_preserves_authenticated_primary_fingerprint(self):
        fingerprint = 'A' * 40
        listing = 'pub:e:4096:1:AAAAAAAAAAAAAAAA:1000:2000::::::\nfpr:::::::::' + fingerprint + ':\n'
        refreshed = listing.replace('pub:e:', 'pub:-:').replace(':2000:', ':3000:')
        self.assertEqual(primary_fingerprint(listing), fingerprint)
        validate_key_refresh(listing, refreshed, fingerprint)
        for original, new, expected in [(listing.replace(fingerprint, 'B' * 40), refreshed, fingerprint),
                                       (listing, refreshed.replace(fingerprint, 'B' * 40), fingerprint),
                                       (listing, refreshed, fingerprint[-16:])]:
            with self.subTest(original=original, new=new), self.assertRaises(ValueError):
                validate_key_refresh(original, new, expected)
        # Listing an expired original key is not signature approval.
        for status in ['KEYEXPIRED 2000', 'EXPKEYSIG AAAAAAAA Developer',
                       'REVKEYSIG AAAAAAAA Developer', 'KEYREVOKED', 'SIGEXPIRED 2000']:
            with self.subTest(status=status), self.assertRaises(ValueError):
                valid_signature('[GNUPG:] ' + status + '\n[GNUPG:] VALIDSIG ' + fingerprint + ' 2026-10-27\n')

    def test_valid_signature_cannot_substitute_another_signer(self):
        fingerprint = 'A' * 40
        status = '[GNUPG:] VALIDSIG ' + fingerprint + ' 2026-10-27\n'
        self.assertEqual(valid_signature(status, fingerprint), fingerprint)
        for expected in ('B' * 40, fingerprint[-16:], ''):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                valid_signature(status, expected)

    def test_key_listing_rejects_multiple_secret_or_missing_primary_keys(self):
        good = 'pub:-:4096:1:AAAAAAAAAAAAAAAA:1000:3000::::::\nfpr:::::::::' + 'A' * 40 + ':\n'
        for bad in ['', good + good, good.replace('pub:', 'sec:'), good.replace('pub:', 'sub:'),
                    good.replace('A' * 40, 'A' * 16), good.splitlines()[0],
                    good.replace('fpr:', 'uid:'), good + 'ssb:::\n']:
            with self.subTest(listing=bad), self.assertRaises(ValueError):
                primary_fingerprint(bad)

    def test_transitive_dependency_requires_exact_index_identity_and_hash(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'package.deb'
            path.write_bytes(b'generated package')
            key = ('example', '1:2.3', 'amd64')
            index = {key: {'SHA256': sha(path.read_bytes()), 'Filename': 'pool/example.deb'}}
            identity = 'Package: example\nVersion: 1:2.3\nArchitecture: amd64\n'
            with patch('bootstrap.subprocess.check_output', return_value=identity):
                self.assertEqual(check_deb(path, index)['version'], '1:2.3')
                path.write_bytes(b'altered package')
                with self.assertRaises(ValueError):
                    check_deb(path, index)
                with self.assertRaises(ValueError):
                    check_deb(path, {})

    def archive(self, root, members):
        path = root / 'source.tar'
        with tarfile.open(path, 'w') as archive:
            for name, kind, target in members:
                member = tarfile.TarInfo(name)
                member.mode = 0o755
                member.type = kind
                if kind == tarfile.REGTYPE:
                    member.size = 4
                    archive.addfile(member, io.BytesIO(b'test'))
                else:
                    member.linkname = target
                    archive.addfile(member)
        return path

    def test_regular_archive_preserves_executable_files(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            archive = self.archive(root, [('source/configure', tarfile.REGTYPE, '')])
            result = extract_regular(archive, root / 'out', 'source')
            self.assertEqual((result / 'configure').read_bytes(), b'test')
            self.assertEqual((result / 'configure').stat().st_mode & 0o777, 0o755)

    def test_archive_rejects_traversal_links_devices_and_duplicate_paths(self):
        cases = [[('../escape', tarfile.REGTYPE, '')], [('/absolute', tarfile.REGTYPE, '')],
                 [('other/file', tarfile.REGTYPE, '')], [('source/link', tarfile.SYMTYPE, '/tmp')],
                 [('source/link', tarfile.LNKTYPE, 'source/file')], [('source/dev', tarfile.CHRTYPE, '')],
                 [('source/file', tarfile.REGTYPE, ''), ('source/./file', tarfile.REGTYPE, '')]]
        for members in cases:
            with self.subTest(members=members), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                archive = self.archive(root, members)
                with self.assertRaises(ValueError):
                    extract_regular(archive, root / 'out', 'source')
                self.assertFalse((root / 'escape').exists())
                self.assertEqual(list((root / 'out').iterdir()), [])

    def test_empty_archive_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            archive = self.archive(root, [])
            with self.assertRaises(ValueError):
                extract_regular(archive, root / 'out', 'source')


if __name__ == '__main__':
    unittest.main()
