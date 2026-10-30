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

NOW = datetime(2026, 10, 26, 20, 0, tzinfo=timezone.utc)
IMAGE = 'sha256:' + 'a' * 64
TSV = 'glibc\t2.44-r11\tx86_64\tinstalled\ntzdata\t2026f-r0\tnoarch\tinstalled\n'


def report():
    return {'SchemaVersion': 2, 'Trivy': {'Version': '0.76.1'},
            'CreatedAt': NOW.isoformat(), 'ArtifactType': 'container_image',
            'Metadata': {'ImageID': IMAGE, 'OS': {'Family': 'wolfi', 'Name': '20230201'}},
            'Results': [{'Class': 'os-pkgs', 'Type': 'wolfi', 'Packages': [
                {'Name': 'glibc', 'Version': '2.44-r11', 'Arch': 'x86_64'},
                {'Name': 'tzdata', 'Version': '2026f-r0', 'Arch': 'noarch'}]}]}


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
            {'VulnerabilityID': 'CVE-TEST-1', 'PkgName': 'glibc',
             'InstalledVersion': '2.44-r11', 'Severity': 'LOW', 'Status': 'affected'},
            {'VulnerabilityID': 'CVE-TEST-2', 'PkgName': 'tzdata',
             'InstalledVersion': '2026f-r0', 'Severity': 'UNKNOWN'}]
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
                       {'Family': 'debian', 'Name': '12'}, {'Family': 'debian', 'Name': '14'},
                       {'Family': 'wolfi', 'Name': '20230201', 'EOSL': True}]:
            value = report(); value['Metadata']['OS'] = system
            with self.subTest(system=system), self.assertRaises(ValueError): self.assess(value)

    def test_missing_extra_and_duplicate_targets_are_rejected(self):
        for results in [[], report()['Results']*2, [{'Class': 'lang-pkgs', 'Type': 'python-pkg'}]]:
            with self.subTest(results=results), self.assertRaises(ValueError):
                self.assess(dict(report(), Results=results))

    def test_missing_extra_duplicate_or_changed_package_is_rejected(self):
        packages = report()['Results'][0]['Packages']
        cases = [[], packages[:1], packages*2,
                 packages + [{'Name': 'extra', 'Version': '1', 'Arch': 'x86_64'}],
                 [dict(packages[0], Version='2.44-r10'), packages[1]],
                 [dict(packages[0], Arch='arm64'), packages[1]]]
        for changed in cases:
            value = report(); value['Results'][0]['Packages'] = changed
            with self.subTest(packages=changed), self.assertRaises(ValueError): self.assess(value)

    def test_apk_version_includes_revision_and_rejects_dpkg_fields(self):
        self.assertEqual(audit.package_version({'Version': '2.44-r11'}), '2.44-r11')
        for change in ({'Release': '11'}, {'Epoch': 1}, {'Version': ''}, {'Version': '2.44 r11'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                audit.package_version(dict({'Version': '2.44-r11'}, **change))

    def test_suppressed_and_invalid_findings_are_rejected(self):
        value = report(); value['Results'][0]['ExperimentalModifiedFindings'] = [{'Vulnerability': {}}]
        with self.assertRaises(ValueError): self.assess(value)
        for finding in [{}, {'VulnerabilityID': 'CVE-X', 'PkgName': 'unknown',
                            'InstalledVersion': '1', 'Severity': 'LOW'},
                        {'VulnerabilityID': 'CVE-X', 'PkgName': 'glibc',
                         'InstalledVersion': '2.44-r11', 'Severity': 'NONE'}]:
            value = report(); value['Results'][0]['Vulnerabilities'] = [finding]
            with self.subTest(finding=finding), self.assertRaises(ValueError): self.assess(value)

    def test_inventory_empty_duplicates_partial_states_and_bad_arch_rejected(self):
        for raw in ['', TSV*2, TSV.replace('installed', 'half-configured'),
                    TSV.replace('x86_64', 'arm64'), TSV.replace('\tinstalled', ''),
                    TSV + 'glibc\t1\tx86_64\tinstalled\n']:
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
                 patch.object(audit.subprocess, 'check_output', side_effect=[('a'*40)+'\n', 'synthetic APK database']), \
                 patch.object(audit.apk_inventory, 'parse', return_value={'packages': [
                     {'name':'glibc','version':'2.44-r11','architecture':'x86_64'},
                     {'name':'tzdata','version':'2026f-r0','architecture':'noarch'}]}), \
                 patch.object(audit, 'install', side_effect=OSError('unavailable')):
                self.assertEqual(audit.audit(IMAGE, out), 2)
            assessment = json.loads((out / 'assessment.json').read_text())
            self.assertFalse(assessment['complete'])
            self.assertFalse(assessment['passed'])
            self.assertIn('system-packages.tsv', assessment['files'])

    def test_audit_exit_and_saved_evidence_for_a_second_image(self):
        """The orchestration must not convert findings or wrong-image data to success."""
        second_image = 'sha256:' + 'b' * 64

        class FixedClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return NOW

        for case, expected in [('clean', 0), ('finding', 1), ('wrong-image', 2)]:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                out = Path(directory) / 'evidence'
                value = report()
                value['Metadata']['ImageID'] = IMAGE if case == 'wrong-image' else second_image
                if case == 'finding':
                    value['Results'][0]['Vulnerabilities'] = [{
                        'VulnerabilityID': 'CVE-TEST-REGISTRY', 'PkgName': 'glibc',
                        'InstalledVersion': '2.44-r11', 'Severity': 'LOW'}]

                def run(command, **kwargs):
                    if '--download-db-only' in command:
                        database = Path(command[command.index('--cache-dir') + 1]) / 'db'
                        database.mkdir(parents=True)
                        (database / 'trivy.db').write_bytes(b'generated database fixture')
                        audit.save(database / 'metadata.json', {
                            'Version': 2, 'UpdatedAt': NOW.isoformat(),
                            'DownloadedAt': NOW.isoformat(),
                            'NextUpdate': (NOW + timedelta(hours=6)).isoformat()})
                    elif 'convert' in command:
                        audit.save(Path(command[command.index('--output') + 1]), {})
                    else:
                        self.assertEqual(command[-1], second_image)
                        self.assertEqual(command[command.index('--image-src') + 1], 'docker')
                        audit.save(Path(command[command.index('--output') + 1]), value)

                with patch.object(audit, 'datetime', FixedClock), \
                     patch.object(audit.platform, 'system', return_value='Linux'), \
                     patch.object(audit.platform, 'machine', return_value='x86_64'), \
                     patch.object(audit.subprocess, 'check_output', side_effect=[('a'*40)+'\n', 'synthetic APK database']), \
                     patch.object(audit.apk_inventory, 'parse', return_value={'packages': [
                         {'name':'glibc','version':'2.44-r11','architecture':'x86_64'},
                         {'name':'tzdata','version':'2026f-r0','architecture':'noarch'}]}), \
                     patch.object(audit.wolfi_advisories, 'collect', return_value={'findings': []}), \
                     patch.object(audit, 'install', side_effect=lambda lock, work, output: work/'trivy'), \
                     patch.object(audit.subprocess, 'run', side_effect=run):
                    self.assertEqual(audit.audit(second_image, out), expected)
                assessment = json.loads((out / 'assessment.json').read_text())
                self.assertEqual(assessment['imageID'], second_image)
                self.assertEqual(assessment['complete'], case != 'wrong-image')
                self.assertEqual(assessment['passed'], case == 'clean')
                self.assertEqual(json.loads((out / 'trivy-os.json').read_text()), value)
                for name, sha in assessment['files'].items():
                    self.assertEqual(hashlib.sha256((out / name).read_bytes()).hexdigest(), sha)
                if case == 'finding':
                    self.assertEqual(assessment['findingCount'], 1)
                if case == 'wrong-image':
                    self.assertEqual(assessment['error'], 'report belongs to another image')

    def test_existing_output_cannot_reuse_a_previous_success(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileExistsError): audit.audit(IMAGE, Path(directory))


if __name__ == '__main__': unittest.main()
