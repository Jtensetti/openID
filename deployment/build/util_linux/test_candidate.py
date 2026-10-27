"""Generated rejection cases; actual PGP/build evidence must come from Linux CI."""
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from bootstrap import check_deb, fields, package_index, sha
from build import check_input, extract_regular, valid_signature


class CandidateInputTests(unittest.TestCase):
    def test_debian_source_checksum_continuations_and_epoch(self):
        text = 'Version: 1:2.41.6-0openid1\nChecksums-Sha256:\n abc 123 upstream.tar\n def 456 debian.tar\n'
        actual = fields(text)
        self.assertEqual(actual['Version'], '1:2.41.6-0openid1')
        self.assertEqual([v.split() for v in actual['Checksums-Sha256'].splitlines() if v.strip()],
                         [['abc', '123', 'upstream.tar'], ['def', '456', 'debian.tar']])

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

    def test_duplicate_and_empty_package_indexes_rejected(self):
        record = b'Package: example\nVersion: 1:2.3\nArchitecture: amd64\nSHA256: abc\n'
        self.assertIn(('example', '1:2.3', 'amd64'), package_index(record))
        for bad in (b'', record + b'\n' + record):
            with self.assertRaises(ValueError):
                package_index(bad)

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
