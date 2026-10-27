"""Trial-installation boundary tests, without installing or invoking APT."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bootstrap import sha
from build import RUNTIME_PACKAGES, load_lock
from trial_install import (check_image, check_plan, check_transition, installed_packages,
                           protected_files, prepare_apt_cache, main)


class TrialInstallationTests(unittest.TestCase):
    def cache_fixture(self, root):
        directory = root / 'inputs';directory.mkdir()
        workspace = root / 'apt';workspace.mkdir()
        runtime = []
        version = load_lock()['candidateVersion']
        for name in sorted(RUNTIME_PACKAGES):
            selected = {'bsdutils': '1:', 'login': '1:4.16.0-2+really'}.get(name, '') + version
            filename = name + '_' + selected.split(':')[-1] + '_amd64.deb'
            raw = ('Generated package bytes, not installable: ' + name).encode()
            (directory / filename).write_bytes(raw)
            runtime.append({'Package': name, 'Version': selected, 'Architecture': 'amd64',
                            'Source': 'util-linux (' + version + ')', 'filename': filename,
                            'bytes': len(raw), 'sha256': sha(raw)})
        return directory, workspace, runtime

    def test_local_archives_are_staged_with_epochs_and_isolated_from_system_apt_sources(self):
        with tempfile.TemporaryDirectory() as name:
            directory, workspace, runtime = self.cache_fixture(Path(name))
            command, records = prepare_apt_cache(directory, runtime, workspace)
            expected = {p['Package'] + '_' + p['Version'].replace(':', '%3a') + '_amd64.deb'
                        for p in runtime}
            self.assertEqual({p.name for p in (workspace / 'archives').iterdir()}, expected | {'partial'})
            # These exact names address the real APT 3.0.3 CI85 failure; dpkg's
            # exported filenames omit epochs and cannot serve as cache names.
            self.assertIn('bsdutils_1%3a2.41.6-0openid1_amd64.deb', expected)
            self.assertIn('login_1%3a4.16.0-2+really2.41.6-0openid1_amd64.deb', expected)
            for record in records:
                cached = workspace / 'archives' / record['archive']
                self.assertEqual(cached.read_bytes(), (directory / record['source']).read_bytes())
                self.assertEqual(sha(cached.read_bytes()), record['sha256'])
            self.assertIn('--no-download', command)
            self.assertIn('--no-remove', command)
            self.assertIn('Dir::Cache::archives=' + str(workspace / 'archives'), command)
            self.assertIn('Dir::State::lists=' + str(workspace / 'lists'), command)
            self.assertIn('Dir::Etc::sourcelist=' + str(workspace / 'sources.list'), command)
            self.assertIn('Dir::Etc::sourceparts=' + str(workspace / 'sourceparts'), command)
            self.assertEqual((workspace / 'sources.list').read_bytes(), b'')
            self.assertEqual(list((workspace / 'sourceparts').iterdir()), [])
            self.assertEqual(list((workspace / 'lists').iterdir()), [])
            self.assertEqual(command[command.index('install') + 1:],
                             [str(directory / p['filename']) for p in runtime])

    def test_apt_cache_rejects_modified_missing_linked_or_extra_package_bytes(self):
        for change in ('same-size', 'truncated', 'missing', 'linked', 'extra', 'missing-member', 'duplicate'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                directory, workspace, runtime = self.cache_fixture(root)
                path = directory / runtime[0]['filename']
                if change == 'same-size':
                    path.write_bytes(b'X' * path.stat().st_size)
                elif change == 'truncated':
                    path.write_bytes(path.read_bytes()[:-1])
                elif change == 'missing':
                    path.unlink()
                elif change == 'linked':
                    outside = root / 'outside';path.rename(outside);path.symlink_to(outside)
                elif change == 'extra':
                    (directory / 'unselected.deb').write_bytes(b'extra')
                elif change == 'missing-member':
                    runtime.pop()
                else:
                    runtime.append(copy.deepcopy(runtime[0]))
                with self.assertRaises(ValueError):
                    prepare_apt_cache(directory, runtime, workspace)

    def test_apt_cache_never_reuses_or_overwrites_existing_staging_content(self):
        for change in ('populated', 'linked-workspace', 'linked-inputs'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                directory, workspace, runtime = self.cache_fixture(root)
                outside = root / 'existing';outside.mkdir()
                sentinel = outside / 'sources.list';sentinel.write_bytes(b'preserve')
                if change == 'populated':
                    (workspace / 'sources.list').symlink_to(sentinel)
                elif change == 'linked-workspace':
                    workspace.rmdir();workspace.symlink_to(outside, target_is_directory=True)
                else:
                    linked = root / 'linked';linked.symlink_to(directory, target_is_directory=True)
                    directory = linked
                with self.assertRaises(ValueError):
                    prepare_apt_cache(directory, runtime, workspace)
                self.assertEqual(sentinel.read_bytes(), b'preserve')

    def test_image_requires_exact_parent_layers_and_unchanged_runtime_configuration(self):
        reference = {'Id': 'sha256:' + '1' * 64, 'Os': 'linux', 'Architecture': 'amd64',
                     'RootFS': {'Type': 'layers', 'Layers': ['sha256:' + 'a' * 64]},
                     'Config': {'User': '10001:10001', 'Env': ['EXAMPLE=value'],
                                'Entrypoint': ['python', 'serve.py'], 'Cmd': ['--config', '/test.json'],
                                'WorkingDir': '/app/verification', 'Labels': {'source': 'generated'}}}
        candidate = copy.deepcopy(reference)
        candidate['Id'] = 'sha256:' + '2' * 64
        candidate['RootFS']['Layers'].append('sha256:' + 'b' * 64)
        candidate['Config']['Labels'].update({'io.openid.candidate-only': 'true', 'io.openid.evaluation': 'util-linux'})
        self.assertEqual(check_image(reference, candidate)['preservedReferenceLayers'], 1)
        mutations = [('Config', 'User', '0:0'), ('Config', 'Env', ['EXAMPLE=other']),
                     ('Config', 'Entrypoint', ['other']), ('Config', 'Labels', {}),
                     ('RootFS', 'Layers', ['sha256:' + 'c' * 64, 'sha256:' + 'b' * 64])]
        for section, key, value in mutations:
            bad = copy.deepcopy(candidate);bad[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                check_image(reference, bad)
        with self.assertRaises(ValueError):
            check_image(reference, reference)

    def test_inventory_rejects_empty_duplicate_partial_and_foreign_architecture(self):
        row = 'bsdutils\t1:2.41.5-0+deb13u1\tamd64\tinstalled\n'
        self.assertEqual(installed_packages(row)['bsdutils']['Version'], '1:2.41.5-0+deb13u1')
        for text in ('', row + row, row.replace('installed', 'unpacked'), row.replace('amd64', 'arm64')):
            with self.subTest(text=text), self.assertRaises(ValueError):
                installed_packages(text)

    def test_apt_plan_accepts_only_the_expected_upgrades(self):
        expected = {'bsdutils': '1:2.41.6-0openid1', 'libmount1': '2.41.6-0openid1'}
        lines = ('Inst bsdutils [1:2.41.5-0+deb13u1] (1:2.41.6-0openid1 local-deb [amd64])\n'
                 'Inst libmount1:amd64 [2.41.5-0+deb13u1] (2.41.6-0openid1 local-deb [amd64])\n')
        self.assertEqual(check_plan('Reading package lists...\n' + lines, expected), expected)
        for text in ('', lines.splitlines()[0], lines + lines, lines + 'Remv libc6 [2.41]\n',
                     lines + 'Purg unwanted\n', lines + 'Inst unknown (1 local-deb [amd64])\n',
                     lines.replace('local-deb [amd64])', 'malformed'),
                     lines.replace('2.41.6-0openid1', '2.41.6-0openid1-extra')):
            with self.subTest(text=text), self.assertRaises(ValueError):
                check_plan(text, expected)

    def test_post_install_state_must_preserve_every_unselected_package(self):
        before = {'libc6': {'Version': '2.41-12', 'Architecture': 'amd64'},
                  'libmount1': {'Version': '2.41.5-0+deb13u1', 'Architecture': 'amd64'}}
        expected = {'libmount1': '2.41.6-0openid1'}
        after = copy.deepcopy(before)
        after['libmount1']['Version'] = expected['libmount1']
        self.assertEqual(check_transition(before, after, expected), ['libmount1'])
        extra = copy.deepcopy(after);extra['extra'] = {'Version': '1', 'Architecture': 'all'}
        removed = copy.deepcopy(after);del removed['libc6']
        unrelated = copy.deepcopy(after);unrelated['libc6']['Version'] = '2.42'
        foreign = copy.deepcopy(after);foreign['libmount1']['Architecture'] = 'all'
        wrong = copy.deepcopy(after);wrong['libmount1']['Version'] = '2.41.6-0openid1-extra'
        for candidate in (extra, removed, unrelated, foreign, wrong, before):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                check_transition(before, candidate, expected)

    def test_apt_transient_annotations_do_not_change_selected_versions(self):
        expected = {'libblkid1': '2.41.6-0openid1', 'libmount1': '2.41.6-0openid1'}
        # Formats emitted by APT 3.0.3 RealInstall and ShortBreaks, not a CI83 transcript.
        lines = ('Inst libblkid1 [2.41.5-0+deb13u1] (2.41.6-0openid1 local-deb [amd64]) '
                 '[libmount1:amd64 on libblkid1:amd64] [libmount1:amd64 ]\n'
                 'Inst libmount1:amd64 [2.41.5-0+deb13u1] (2.41.6-0openid1 local-deb [amd64]) []\n')
        self.assertEqual(check_plan(lines, expected), expected)
        for bad in (lines + lines, lines + 'Conf libmount1:amd64 broken\n',
                    lines + 'Inst extra (1 local-deb [amd64]) []\n',
                    lines.replace(' []', ' [unterminated'),
                    lines.replace(' []', ' [] Inst extra (1)'),
                    lines.replace('2.41.6-0openid1', '2.41.6-0openid1-extra')):
            with self.subTest(output=bad), self.assertRaises(ValueError):
                check_plan(bad, expected)

    def test_protected_files_detect_content_mode_addition_removal_and_link_changes(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / 'app';root.mkdir()
            file = root / 'main.py';file.write_text('generated application')
            file.chmod(0o644)
            outside = Path(name) / 'outside';outside.mkdir()
            (outside / 'not-in-scope').write_text('generated external file')
            link = root / 'link';link.symlink_to(outside, target_is_directory=True)
            original = protected_files([root])
            self.assertFalse(any('not-in-scope' in p for p in original))
            file.write_text('changed application');self.assertNotEqual(protected_files([root]), original)
            file.write_text('generated application');self.assertEqual(protected_files([root]), original)
            file.chmod(0o755);self.assertNotEqual(protected_files([root]), original)
            file.chmod(0o644)
            extra = root / 'injected.py';extra.write_text('generated extra')
            self.assertNotEqual(protected_files([root]), original);extra.unlink()
            file.unlink();self.assertNotEqual(protected_files([root]), original)
            file.write_text('generated application');file.chmod(0o644)
            link.unlink();link.symlink_to(outside / 'different')
            self.assertNotEqual(protected_files([root]), original)
            with self.assertRaises(ValueError):
                protected_files([link])
            with self.assertRaises(ValueError):
                protected_files([root / 'missing'])

    def test_trial_entrypoint_rejects_developer_host_before_writes(self):
        with patch('trial_install.platform.system', return_value='Darwin'), \
                patch('trial_install.Path.mkdir') as mkdir:
            with self.assertRaises(ValueError):
                main()
            mkdir.assert_not_called()


if __name__ == '__main__':
    unittest.main()
