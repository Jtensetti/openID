"""Reject malformed source and package identities before the Linux build."""
import copy
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from candidate import (PACKAGING_LINKS, check_dsc, check_key, check_packages,
                       extract_packaging, load_lock)
from inventory import sbom


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.lock = load_lock()

    def source_metadata(self):
        checksums = ''.join(' ' + item['sha256'] + ' ' + str(item['bytes'])
                            + ' ' + item['filename'] + '\n' for item in self.lock['inputs']
                            if not item['filename'].endswith('.dsc'))
        return ('Format: 3.0 (quilt)\nSource: ncurses\nVersion: '
                + self.lock['packagingVersion'] + '\nChecksums-Sha256:\n' + checksums)

    def packages(self):
        version = self.lock['candidateVersion']
        return [{'Package': name, 'Version': version, 'Source': 'ncurses (' + version + ')',
                 'Architecture': arch, 'filename': name + '_' + version + '_' + arch + '.deb',
                 'bytes': 123, 'sha256': 'a' * 64}
                for name, arch in self.lock['requiredPackages'].items()]

    def test_exact_signed_source_group(self):
        good = self.source_metadata()
        check_dsc(good, self.lock)
        for bad in (good.replace('Source: ncurses', 'Source: other'),
                    good.replace(self.lock['packagingVersion'], '0.0-1', 1),
                    good.replace('3.0 (quilt)', '1.0'),
                    good.replace(self.lock['inputs'][1]['sha256'], '0' * 64),
                    good + ' ' + self.lock['inputs'][1]['sha256'] + ' '
                    + str(self.lock['inputs'][1]['bytes']) + ' '
                    + self.lock['inputs'][1]['filename'] + '\n'):
            with self.subTest(case=bad[-75:]), self.assertRaises(ValueError):
                check_dsc(bad, self.lock)

    def test_upstream_primary_key_is_exact(self):
        signer = self.lock['upstreamSigner']
        listing = 'pub:-:4096:1:AAAAAAAAAAAAAAAA:1000:3000::::::\nfpr:::::::::' + signer + ':\n'
        check_key(listing, signer)
        for bad in ('', listing + listing, listing.replace('pub:', 'sec:'),
                    listing.replace(signer, 'A' * 40), listing.splitlines()[0]):
            with self.subTest(case=bad[-60:]), self.assertRaises(ValueError):
                check_key(bad, signer)

    def test_complete_binary_group_and_identity(self):
        packages = self.packages()
        selected = check_packages(packages, self.lock)
        self.assertEqual({p['Package'] for p in selected}, set(self.lock['runtimePackages']))
        for bad in (packages[:-1], packages + [copy.deepcopy(packages[0])]):
            with self.subTest(length=len(bad)), self.assertRaises(ValueError):
                check_packages(bad, self.lock)
        for field, value in (('Version', '0.0-1'), ('Source', 'other'),
                             ('Architecture', 'arm64'), ('filename', '../escape.deb'),
                             ('bytes', True), ('sha256', 'not-a-hash')):
            bad = copy.deepcopy(packages)
            bad[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check_packages(bad, self.lock)

    def test_inventory_rejects_partial_builder(self):
        packages = self.packages()
        data = sbom(self.lock, packages, 'sample\t1.0\tamd64\tinstalled')
        self.assertEqual(data['specVersion'], '1.6')
        self.assertEqual(len(data['components']), len(self.lock['inputs']) + len(packages) + 1)
        with self.assertRaises(ValueError):
            sbom(self.lock, packages, 'sample\t1.0\tamd64\thalf-configured')

    def test_only_exact_internal_symbol_aliases_are_extracted(self):
        def archive(path, change=None):
            with tarfile.open(path, 'w:xz') as output:
                directory = tarfile.TarInfo('debian')
                directory.type = tarfile.DIRTYPE
                output.addfile(directory)
                for target in sorted(set(PACKAGING_LINKS.values())):
                    raw = b'generated symbol list\n'
                    member = tarfile.TarInfo('debian/' + target)
                    member.size = len(raw)
                    output.addfile(member, io.BytesIO(raw))
                for name, target in PACKAGING_LINKS.items():
                    member = tarfile.TarInfo(name)
                    member.type = tarfile.SYMTYPE
                    member.linkname = '../outside' if change == name else target
                    output.addfile(member)
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            source = base / 'packaging.tar.xz'
            archive(source)
            result = extract_packaging(source, base / 'good')
            self.assertEqual({p.name for p in result.glob('*.symbols') if p.is_symlink()},
                             {Path(p).name for p in PACKAGING_LINKS})
            archive(source, next(iter(PACKAGING_LINKS)))
            with self.assertRaisesRegex(ValueError, 'unexpected ncurses packaging link'):
                extract_packaging(source, base / 'bad')


if __name__ == '__main__':
    unittest.main(verbosity=2)
