"""Runtime identity and vendor-feed regression tests; synthetic inputs only."""
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import apk_inventory
import build_runtime
import wolfi_advisories as vendor

NOW = datetime(2026, 10, 30, 8, tzinfo=timezone.utc)
PACKAGES = {('python-3.12', '3.12.16-r1', 'x86_64')}


def record(status='pending_upstream_fix', fixed=None, arch='x86_64'):
    events = [{'introduced': '0'}] + ([{'fixed': fixed}] if fixed else [])
    return {'id': 'CGA-test', 'schema_version': '1.7.5', 'modified': NOW.isoformat(),
            'affected': [{'package': {'ecosystem': 'Wolfi', 'name': 'python-3.12',
                'purl': 'pkg:apk/wolfi/python-3.12?arch='+arch},
                'ranges': [{'type': 'ECOSYSTEM', 'events': events}],
                'ecosystem_specific': {'components': [{'latest_event_status': status}]}}]}


def tar_bytes(members):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w:gz') as archive:
        for name, value in members:
            data = json.dumps(value).encode()
            member = tarfile.TarInfo(name); member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return raw.getvalue()


class VendorTests(unittest.TestCase):
    def test_unfixed_and_unresolved_statuses_block(self):
        for status in vendor.UNRESOLVED:
            for fixed in (None, '3.12.1-r0'):
                with self.subTest(status=status, fixed=fixed):
                    self.assertEqual(len(vendor.unresolved([record(status, fixed)], PACKAGES)), 1)
        # Even an inconsistent "fixed" status cannot hide an open range.
        self.assertEqual(len(vendor.unresolved([record('fixed')], PACKAGES)), 1)

    def test_fixed_ranges_remain_delegated_to_trivy(self):
        self.assertEqual(vendor.unresolved([record('fixed', '3.12.16-r0')], PACKAGES), [])
        self.assertEqual(vendor.unresolved([record('false_positive_determination', '0')], PACKAGES), [])

    def test_architecture_and_encoded_package_names(self):
        self.assertEqual(vendor.unresolved([record(arch='aarch64')], PACKAGES), [])
        value = record(); p = value['affected'][0]['package']
        p.update(name='libstdc++', purl='pkg:apk/wolfi/libstdc%2B%2B?arch=x86_64')
        self.assertEqual(len(vendor.unresolved([value], {('libstdc++', '16.2.0-r2', 'x86_64')})), 1)

    def test_unknown_status_schema_and_range_fail_closed(self):
        values = [record('new-unknown-status'), record()]
        values[1]['schema_version'] = '99'
        bad = record(); bad['affected'][0]['ranges'][0]['events'] = [{'last_affected': '1'}]; values.append(bad)
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                vendor.unresolved([value], PACKAGES)

    def collect(self, index, members):
        payloads = {'all.json': json.dumps(index).encode(), 'chainguard-osv.tar.gz': tar_bytes(members)}
        def fetch(name, limit, now):
            raw = payloads[name]
            return raw, {'url': vendor.BASE+name, 'lastModified': now.isoformat(),
                         'sha256': hashlib.sha256(raw).hexdigest()}
        with patch.object(vendor, 'fetch', side_effect=fetch):
            return vendor.collect(PACKAGES, NOW)

    def test_complete_archive_and_index_timestamp_precision(self):
        item = record(); item['modified'] = '2026-10-30T08:00:00Z'
        index = [{'id': item['id'], 'modified': '2026-10-30T08:00:00.64Z'}]
        result = self.collect(index, [('CGA-test.json', item), ('all.json', index)])
        self.assertEqual(result['recordCount'], 1)
        self.assertEqual(len(result['findings']), 1)

    def test_missing_duplicate_changed_record_and_index_are_rejected(self):
        item = record(); index = [{'id': item['id'], 'modified': item['modified']}]
        changed = copy.deepcopy(item); changed['modified'] = '2026-10-29T08:00:00Z'
        for members in ([('all.json', index)], [('CGA-test.json', item)],
                        [('all.json', index), ('CGA-test.json', item), ('duplicate.json', item)],
                        [('all.json', index), ('CGA-test.json', changed)],
                        [('all.json', []), ('CGA-test.json', item)]):
            with self.subTest(members=members), self.assertRaises(ValueError):
                self.collect(index, members)

    def test_stale_or_oversize_download_is_rejected(self):
        for modified, payload in [('Wed, 28 Oct 2026 08:00:00 GMT', b'{}'),
                                  ('Fri, 30 Oct 2026 08:00:00 GMT', b'too large')]:
            response = io.BytesIO(payload); response.headers = {'Last-Modified': modified}
            with patch.object(vendor.urllib.request, 'urlopen', return_value=response), self.assertRaises(ValueError):
                vendor.fetch('all.json', 2, NOW)


class InventoryTests(unittest.TestCase):
    RAW = 'P:python-3.12\nV:3.12.16-r1\nA:x86_64\no:python-3.12\nF:usr/bin\nR:python3.12\n'

    def test_exact_identity_and_owned_files(self):
        result = apk_inventory.parse(self.RAW)
        self.assertEqual(result['packages'][0]['version'], '3.12.16-r1')
        self.assertEqual(result['files'], ['/usr/bin/python3.12'])

    def test_ambiguous_package_and_unsafe_file_paths_rejected(self):
        for raw in (self.RAW+'P:other\n', self.RAW+'\n'+self.RAW,
                    self.RAW.replace('F:usr/bin', 'F:../escape'),
                    self.RAW.replace('F:usr/bin', 'F:/absolute'),
                    self.RAW.replace('R:python3.12', 'R:../escape'),
                    self.RAW.replace('A:x86_64', 'A:unknown'), ''):
            with self.subTest(raw=raw), self.assertRaises(ValueError): apk_inventory.parse(raw)


class ArchiveTests(unittest.TestCase):
    def test_wrong_platform_or_layer_hash_never_extracts(self):
        for platform in ('arm64', 'amd64'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); image = root/'runtime.tar'
                manifest = [{'Config': 'config.json', 'Layers': ['0'*64+'.tar.gz']}]
                image.write_bytes(tar_bytes([('manifest.json', manifest),
                    ('config.json', {'os': 'linux', 'architecture': platform}), ('0'*64+'.tar.gz', {})]))
                with patch.object(build_runtime.subprocess, 'run') as extract, self.assertRaises(ValueError):
                    build_runtime.unpack(image, root/'runtime')
                extract.assert_not_called()


if __name__ == '__main__':
    unittest.main()
