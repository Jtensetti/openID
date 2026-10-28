"""Reject altered candidate bytes and unsafe trial-image bindings."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from candidate import load_lock
from prepare_trial import prepare
from trial_install import check_image


REVISION = 'a' * 40


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixture(root):
    lock = load_lock()
    evidence = root / 'evidence'
    evidence.mkdir()
    (root / 'tested-revision.txt').write_text(REVISION + '\n')
    locked = json.dumps(lock).encode()
    (evidence / 'candidate.lock.json').write_bytes(locked)
    files = {'candidate.lock.json': sha(locked)}
    packages = []
    for name in ('acl', 'libacl1', 'libacl1-dev'):
        arch = 'amd64'
        filename = f'{name}_{lock["candidateVersion"]}_{arch}.deb'
        data = f'{name}-authenticated-fixture'.encode()
        item = {'Package': name, 'Version': lock['candidateVersion'], 'Architecture': arch,
                'Source': 'acl',
                'filename': filename, 'bytes': len(data), 'sha256': sha(data)}
        packages.append(item)
        target = evidence / 'candidate-packages' / filename
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(data)
        files['candidate-packages/' + filename] = sha(data)
    assessment = {'complete': True, 'passed': True, 'runtimeInstalled': False,
                  'candidateVersion': lock['candidateVersion'], 'packages': packages,
                  'exportedPackages': ['acl', 'libacl1', 'libacl1-dev'], 'files': files}
    (evidence / 'assessment.json').write_text(json.dumps(assessment))
    return evidence, assessment


class TrialEvidenceTests(unittest.TestCase):
    def test_accepts_complete_bound_group_and_rejects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            evidence, assessment = fixture(root)
            result = prepare(root, root / 'context', REVISION)
            self.assertEqual(result['candidateEvidenceFilesVerified'], len(assessment['files']))
            package = next((evidence / 'candidate-packages').iterdir())
            package.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'candidate evidence bytes differ'):
                prepare(root, root / 'other-context', REVISION)

    def test_rejects_wrong_revision_and_incomplete_assessment(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            evidence, assessment = fixture(root)
            with self.assertRaisesRegex(ValueError, 'another revision'):
                prepare(root, root / 'wrong-context', 'b' * 40)
            assessment['passed'] = False
            (evidence / 'assessment.json').write_text(json.dumps(assessment))
            with self.assertRaisesRegex(ValueError, 'failed, incomplete'):
                prepare(root, root / 'failed-context', REVISION)

    def test_rejects_linked_package(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            evidence, _ = fixture(root)
            package = next((evidence / 'candidate-packages').iterdir())
            content = package.read_bytes()
            package.unlink()
            replacement = root / 'replacement'
            replacement.write_bytes(content)
            package.symlink_to(replacement)
            with self.assertRaisesRegex(ValueError, 'linked evidence path'):
                prepare(root, root / 'linked-context', REVISION)


class TrialImageTests(unittest.TestCase):
    def test_requires_exact_reference_layers_and_runtime_configuration(self):
        reference = {'Id': 'sha256:' + 'a' * 64, 'Os': 'linux', 'Architecture': 'amd64',
                     'RootFS': {'Type': 'layers', 'Layers': ['layer1']},
                     'Config': {'User': '10001:10001', 'Labels': {}}}
        candidate = json.loads(json.dumps(reference))
        candidate['Id'] = 'sha256:' + 'b' * 64
        candidate['RootFS']['Layers'].append('layer2')
        candidate['Config']['Labels'] = {'io.openid.candidate-only': 'true',
                                         'io.openid.evaluation': 'acl'}
        self.assertEqual(check_image(reference, candidate)['referenceImage'], reference['Id'])
        candidate['RootFS']['Layers'][0] = 'different'
        with self.assertRaisesRegex(ValueError, 'exact reference'):
            check_image(reference, candidate)


if __name__ == '__main__':
    unittest.main()
