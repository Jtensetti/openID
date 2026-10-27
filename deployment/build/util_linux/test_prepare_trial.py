"""Generated evidence tests; no Docker, APT or signature verification is run."""
import json
from pathlib import Path
import tempfile
import unittest

from bootstrap import sha
from build import load_lock
from prepare_trial import prepare


class TrialContextTests(unittest.TestCase):
    revision = 'a' * 40

    def fixture(self, root):
        candidate = root / 'candidate'
        evidence = candidate / 'evidence'
        packages = evidence / 'runtime-packages'
        packages.mkdir(parents=True)
        (candidate / 'tested-revision.txt').write_text(self.revision + '\n')
        lock = load_lock()
        (evidence / 'candidate.lock.json').write_text(json.dumps(lock))
        (evidence / 'build.log').write_text('Generated successful build evidence, not a real build.\n')
        names = ['bsdutils', 'libblkid1', 'liblastlog2-2', 'libmount1',
                 'libsmartcols1', 'libuuid1', 'login', 'mount', 'util-linux']
        metadata = []
        for name in names:
            prefix = {'bsdutils': '1:', 'login': '1:4.16.0-2+really'}.get(name, '')
            version = prefix + lock['candidateVersion']
            filename = name + '_' + version.split(':')[-1] + '_amd64.deb'
            raw = ('Generated package fixture: ' + name).encode()
            (packages / filename).write_bytes(raw)
            metadata.append({'Package': name, 'Version': version, 'Architecture': 'amd64',
                             'Source': 'util-linux (' + lock['candidateVersion'] + ')',
                             'filename': filename, 'bytes': len(raw), 'sha256': sha(raw)})
        assessment = {'complete': True, 'passed': True, 'runtimeInstalled': False,
                      'candidateVersion': lock['candidateVersion'], 'packages': metadata,
                      'exportedRuntimePackages': sorted(names),
                      'files': {str(p.relative_to(evidence)): sha(p.read_bytes())
                                for p in evidence.rglob('*') if p.is_file()}}
        self.save(evidence, assessment)
        return candidate, evidence, assessment

    def save(self, evidence, assessment):
        (evidence / 'assessment.json').write_text(json.dumps(assessment))

    def test_context_copies_only_selected_inputs_and_preserves_verified_bytes(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            candidate, evidence, assessment = self.fixture(root)
            destination = root / 'context'
            result = prepare(candidate, destination, self.revision)
            self.assertTrue(result['preparedOnly'])
            self.assertFalse(result['runtimeInstalled'])
            self.assertEqual(result['testedRevision'], self.revision)
            self.assertEqual(result['buildAssessmentSHA256'], sha((evidence / 'assessment.json').read_bytes()))
            self.assertEqual(result['candidateEvidenceFilesVerified'], len(assessment['files']))
            self.assertFalse((destination / 'inputs/build.log').exists())
            self.assertEqual(len(list((destination / 'inputs/runtime-packages').iterdir())), 9)
            copied = {str(p.relative_to(destination)) for p in destination.rglob('*') if p.is_file()}
            self.assertEqual(copied, set(result['files']) | {'context-manifest.json'})
            for relative, expected in result['files'].items():
                self.assertEqual(sha((destination / relative).read_bytes()), expected)
            self.assertEqual(json.loads((destination / 'context-manifest.json').read_text()), result)

    def test_failed_incomplete_installed_or_wrong_revision_never_creates_context(self):
        for field, value in [('passed', False), ('complete', False), ('runtimeInstalled', True),
                             ('candidateVersion', 'unreviewed'), ('revision', 'b' * 40)]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                candidate, evidence, assessment = self.fixture(root)
                if field == 'revision':
                    (candidate / 'tested-revision.txt').write_text(value)
                else:
                    assessment[field] = value
                    self.save(evidence, assessment)
                with self.assertRaises(ValueError):
                    prepare(candidate, root / 'context', self.revision)
                self.assertFalse((root / 'context').exists())

    def test_changed_package_or_unselected_evidence_is_rejected(self):
        for which in ('package', 'log', 'lock', 'missing-group', 'extra-package'):
            with self.subTest(which=which), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                candidate, evidence, assessment = self.fixture(root)
                if which == 'package':
                    next((evidence / 'runtime-packages').iterdir()).write_bytes(b'changed')
                elif which == 'log':
                    (evidence / 'build.log').write_text('changed provenance')
                elif which == 'lock':
                    path = evidence / 'candidate.lock.json'
                    lock = json.loads(path.read_text());lock['candidateVersion'] = 'unreviewed'
                    path.write_text(json.dumps(lock));assessment['files']['candidate.lock.json'] = sha(path.read_bytes())
                elif which == 'missing-group':
                    assessment['packages'].pop()
                else:
                    (evidence / 'runtime-packages/extra.deb').write_bytes(b'undeclared')
                self.save(evidence, assessment)
                with self.assertRaises(ValueError):
                    prepare(candidate, root / 'context', self.revision)
                self.assertFalse((root / 'context').exists())

    def test_manifest_traversal_and_symlink_paths_are_rejected(self):
        for which in ('traversal', 'absolute', 'noncanonical', 'file-link', 'directory-link'):
            with self.subTest(which=which), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                candidate, evidence, assessment = self.fixture(root)
                outside = root / 'outside';outside.mkdir()
                (outside / 'generated').write_bytes(b'not in candidate')
                if which == 'file-link':
                    (evidence / 'alias').symlink_to(outside / 'generated')
                    assessment['files']['alias'] = sha(b'not in candidate')
                elif which == 'directory-link':
                    (evidence / 'alias').symlink_to(outside, target_is_directory=True)
                    assessment['files']['alias/generated'] = sha(b'not in candidate')
                else:
                    path = {'traversal': '../../outside/generated', 'absolute': str(outside / 'generated'),
                            'noncanonical': './build.log'}[which]
                    assessment['files'][path] = sha(b'not in candidate')
                self.save(evidence, assessment)
                with self.assertRaises(ValueError):
                    prepare(candidate, root / 'context', self.revision)
                self.assertFalse((root / 'context').exists())

    def test_existing_context_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            candidate, _, _ = self.fixture(root)
            destination = root / 'context';destination.mkdir()
            sentinel = destination / 'existing';sentinel.write_bytes(b'preserve')
            with self.assertRaises(FileExistsError):
                prepare(candidate, destination, self.revision)
            self.assertEqual(sentinel.read_bytes(), b'preserve')
            self.assertEqual(list(destination.iterdir()), [sentinel])


if __name__ == '__main__':
    unittest.main()
