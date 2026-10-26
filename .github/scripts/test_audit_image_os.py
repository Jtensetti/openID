from datetime import datetime, timedelta, timezone
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import audit_image_os as audit

spec = importlib.util.spec_from_file_location('patch_bookworm', audit.ROOT / 'deployment/build/patch_bookworm.py')
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)

NOW = datetime(2026, 10, 26, 20, 0, tzinfo=timezone.utc)
IMAGE = 'sha256:' + 'a' * 64
TSV = 'libc6\t2.36-9+deb12u13\tamd64\tinstalled\ntzdata\t2025b-0+deb12u2\tall\tinstalled\n'


def report():
    return {'SchemaVersion': 2, 'Trivy': {'Version': '0.76.1'},
            'CreatedAt': NOW.isoformat(), 'ArtifactType': 'container_image',
            'Metadata': {'ImageID': IMAGE, 'OS': {'Family': 'debian', 'Name': '12.15'}},
            'Results': [{'Class': 'os-pkgs', 'Type': 'debian', 'Packages': [
                {'Name': 'libc6', 'Version': '2.36-9+deb12u13', 'Arch': 'amd64'},
                {'Name': 'tzdata', 'Version': '2025b-0+deb12u2', 'Arch': 'all'}]}]}


class ImageAuditTests(unittest.TestCase):
    def assess(self, value):
        return audit.assess(value, audit.installed_packages(TSV), IMAGE, '0.76.1', NOW)

    def test_complete_empty_findings_need_exact_installed_inventory(self):
        value = self.assess(report())
        self.assertEqual(value['packageCount'], 2)
        self.assertEqual(value['findingCount'], 0)

    def test_low_unfixed_and_unknown_findings_are_not_hidden(self):
        value = report()
        value['Results'][0]['Vulnerabilities'] = [
            {'VulnerabilityID': 'CVE-TEST-1', 'PkgName': 'libc6',
             'InstalledVersion': '2.36-9+deb12u13', 'Severity': 'LOW', 'Status': 'affected'},
            {'VulnerabilityID': 'CVE-TEST-2', 'PkgName': 'tzdata',
             'InstalledVersion': '2025b-0+deb12u2', 'Severity': 'UNKNOWN'}]
        self.assertEqual(self.assess(value)['findingCount'], 2)
        self.assertEqual(self.assess(value)['severityCounts'], {'LOW': 1, 'UNKNOWN': 1})

    def test_wrong_image_tool_schema_or_artifact_is_rejected(self):
        for field, change in [('SchemaVersion', 3), ('ArtifactType', 'filesystem'),
                              ('Trivy', {'Version': '0.1'})]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.assess(dict(report(), **{field: change}))
        value = report()
        value['Metadata']['ImageID'] = 'sha256:' + 'b' * 64
        with self.assertRaises(ValueError): self.assess(value)

    def test_stale_future_or_naive_scan_is_rejected(self):
        for time in [NOW-timedelta(hours=2), NOW+timedelta(minutes=6), NOW.replace(tzinfo=None)]:
            with self.subTest(time=time), self.assertRaises(ValueError):
                self.assess(dict(report(), CreatedAt=time.isoformat()))

    def test_unknown_wrong_or_unsupported_os_is_rejected(self):
        for system in [{}, {'Family': 'ubuntu', 'Name': '12'},
                       {'Family': 'debian', 'Name': '13'},
                       {'Family': 'debian', 'Name': '12.15', 'EOSL': True}]:
            value = report(); value['Metadata']['OS'] = system
            with self.subTest(system=system), self.assertRaises(ValueError): self.assess(value)

    def test_missing_extra_and_duplicate_targets_are_rejected(self):
        for results in [[], report()['Results']*2, [{'Class': 'lang-pkgs', 'Type': 'python-pkg'}]]:
            with self.subTest(results=results), self.assertRaises(ValueError):
                self.assess(dict(report(), Results=results))

    def test_missing_extra_duplicate_or_changed_package_is_rejected(self):
        packages = report()['Results'][0]['Packages']
        cases = [[], packages[:1], packages*2,
                 packages + [{'Name': 'extra', 'Version': '1', 'Arch': 'amd64'}],
                 [dict(packages[0], Version='2.36-9'), packages[1]],
                 [dict(packages[0], Arch='arm64'), packages[1]]]
        for changed in cases:
            value = report(); value['Results'][0]['Packages'] = changed
            with self.subTest(packages=changed), self.assertRaises(ValueError): self.assess(value)

    def test_split_debian_version_retains_revision_epoch_and_rebuild_suffix(self):
        value = report()
        value['Results'][0]['Packages'] = [
            {'Name': 'libc6', 'Version': '2.36', 'Release': '9+deb12u13', 'Arch': 'amd64'},
            {'Name': 'tzdata', 'Version': '2025b', 'Release': '0+deb12u2', 'Arch': 'all'}]
        self.assertEqual(self.assess(value)['packageCount'], 2)
        value['Results'][0]['Packages'][0]['Release'] = '9+deb12u12'
        with self.assertRaises(ValueError): self.assess(value)
        value['Results'][0]['Packages'][0]['Release'] = '9+deb12u13'
        value['Results'][0]['Packages'][0]['Epoch'] = 1
        with self.assertRaises(ValueError): self.assess(value)
        self.assertEqual(audit.package_version({'Version': '1.2.3', 'Epoch': 2,
                                              'Release': '4+deb12u1+b2'}), '2:1.2.3-4+deb12u1+b2')
        for epoch in [True, -1, '1']:
            with self.subTest(epoch=epoch), self.assertRaises(ValueError):
                audit.package_version({'Version': '1', 'Epoch': epoch})

    def test_suppressed_and_invalid_findings_are_rejected(self):
        value = report(); value['Results'][0]['ExperimentalModifiedFindings'] = [{'Vulnerability': {}}]
        with self.assertRaises(ValueError): self.assess(value)
        for finding in [{}, {'VulnerabilityID': 'CVE-X', 'PkgName': 'unknown',
                            'InstalledVersion': '1', 'Severity': 'LOW'},
                        {'VulnerabilityID': 'CVE-X', 'PkgName': 'libc6',
                         'InstalledVersion': '2.36-9+deb12u13', 'Severity': 'NONE'}]:
            value = report(); value['Results'][0]['Vulnerabilities'] = [finding]
            with self.subTest(finding=finding), self.assertRaises(ValueError): self.assess(value)

    def test_inventory_empty_duplicates_partial_states_and_bad_arch_rejected(self):
        for raw in ['', TSV*2, TSV.replace('installed', 'half-configured'),
                    TSV.replace('amd64', 'arm64'), TSV.replace('\tinstalled', ''),
                    TSV + 'libc6\t1\tamd64\tinstalled\n']:
            with self.subTest(raw=raw), self.assertRaises(ValueError): audit.installed_packages(raw)

    def test_database_age_future_schema_and_missing_dates(self):
        good = {'Version': 2, 'UpdatedAt': (NOW-timedelta(hours=2)).isoformat(),
                'DownloadedAt': NOW.isoformat(), 'NextUpdate': (NOW+timedelta(hours=22)).isoformat()}
        audit.check_database(good, NOW)
        for field, value in [('Version', 1), ('UpdatedAt', (NOW-timedelta(hours=25)).isoformat()),
                             ('UpdatedAt', (NOW+timedelta(minutes=6)).isoformat()),
                             ('DownloadedAt', (NOW-timedelta(hours=2)).isoformat()),
                             ('NextUpdate', good['UpdatedAt']), ('UpdatedAt', None)]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                audit.check_database(dict(good, **{field: value}), NOW)

    def test_go_nanoseconds_are_accepted_without_losing_timezone(self):
        self.assertEqual(audit.timestamp('2026-10-26T20:00:00.000000123Z'), NOW)

    def test_distribution_wrong_hash_oversize_and_wrong_origin_rejected(self):
        item = {'url': 'https://github.com/aquasecurity/trivy/releases/download/v0.76.1/test',
                'sha256': hashlib.sha256(b'ok').hexdigest(), 'maxBytes': 2}
        with patch.object(audit.urllib.request, 'urlopen', return_value=io.BytesIO(b'ok')):
            self.assertEqual(audit.fetch_locked(item), b'ok')
        for raw in [b'no', b'oversize']:
            with patch.object(audit.urllib.request, 'urlopen', return_value=io.BytesIO(raw)):
                with self.assertRaises(ValueError): audit.fetch_locked(item)
        with self.assertRaises(ValueError): audit.fetch_locked(dict(item, url='https://unknown.invalid/file'))

    def test_archive_symlink_or_duplicate_binary_rejected(self):
        for kind in ['symlink', 'duplicate', 'missing']:
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w:gz') as archive:
                member = tarfile.TarInfo('trivy' if kind != 'missing' else '../trivy')
                if kind == 'symlink': member.type = tarfile.SYMTYPE; member.linkname = '/tmp/other'
                else: member.size = 1
                archive.addfile(member, io.BytesIO(b'x'))
                if kind == 'duplicate': archive.addfile(member, io.BytesIO(b'x'))
            with tempfile.TemporaryDirectory() as directory:
                with patch.object(audit, 'fetch_locked', return_value=data.getvalue()):
                    with self.subTest(kind=kind), self.assertRaises(ValueError):
                        audit.install({'linuxAmd64': {}}, Path(directory), Path(directory))

    def test_scanner_error_cannot_create_passing_assessment(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'evidence'
            with patch.object(audit.platform, 'system', return_value='Linux'), \
                 patch.object(audit.platform, 'machine', return_value='x86_64'), \
                 patch.object(audit.subprocess, 'check_output', side_effect=[('a'*40)+'\n', TSV]), \
                 patch.object(audit, 'install', side_effect=OSError('unavailable')):
                self.assertEqual(audit.audit(IMAGE, out), 2)
            assessment = json.loads((out / 'assessment.json').read_text())
            self.assertFalse(assessment['complete'])
            self.assertFalse(assessment['passed'])
            self.assertIn('system-packages.tsv', assessment['files'])

    def test_debian_patch_download_requires_exact_hash_and_official_source(self):
        item = {'url': 'https://security.debian.org/debian-security/pool/updates/main/test.deb',
                'sha256': hashlib.sha256(b'package').hexdigest()}
        with patch.object(patcher.urllib.request, 'urlopen', return_value=io.BytesIO(b'package')):
            self.assertEqual(patcher.download(item), b'package')
        with patch.object(patcher.urllib.request, 'urlopen', return_value=io.BytesIO(b'changed')):
            with self.assertRaises(ValueError): patcher.download(item)
        with self.assertRaises(ValueError): patcher.download(dict(item, url='https://unknown.invalid/test.deb'))

    def test_existing_output_cannot_reuse_a_previous_success(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileExistsError): audit.audit(IMAGE, Path(directory))


if __name__ == '__main__': unittest.main()
