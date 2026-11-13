"""Unit fixtures test binding/rejection; real image collection runs in Linux CI."""
import copy
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

import delivery_inventory as inventory
from contract import IDENTITIES, VENDORS

REVISION = 'b' * 40
TREE = 'c' * 40
IMAGE = 'sha256:' + 'a' * 64


def runtime():
    return {'schema': 'tjipp-production-composition-v1', 'status': 'PASS', 'phase': 'complete',
            'sourceRevision': REVISION, 'synthetic': True, 'productionApproved': False,
            'applicationImage': IMAGE, 'vendorImages': {k: v['id'] for k, v in VENDORS.items()},
            'checks': sorted(inventory.CHECKS), 'serviceBoundaries': [
                {'service': name, 'uid': int(identity.split(':')[0]), 'gid': int(identity.split(':')[1]),
                 'actual_container_inspected': True,
                 'imds_ipv4': 'trusted_rotator' if name == 'credential-rotator' else 'blocked',
                 'imds_ipv6': 'trusted_rotator' if name == 'credential-rotator' else 'blocked'}
                for name, identity in IDENTITIES.items()]}


def payload(manager='dpkg', packages=None):
    if packages is None:
        packages = 'libc6\t2.41-1\tamd64\tinstalled\n'
    return ('os-release\0ID=debian\nVERSION_ID="13"\nNAME="Debian GNU/Linux"\n\0manager\0'
            + manager + '\0packages\0' + packages + '\0versions\0fixture-binary 1.0\n').encode()


class FakeDocker:
    """No Docker call is made by these parser/negative fixtures."""
    def __init__(self):
        self.calls = []
        self.inspection = {}
        self.contents = {}
        for name, image in [('application', IMAGE), *[(k, v['id']) for k, v in VENDORS.items()]]:
            source = VENDORS[name]['source'] if name in VENDORS else image
            repository, sha = source.split('@') if '@' in source else ('', '')
            refs = [repository.rsplit(':', 1)[0] + '@' + sha] if sha else []
            self.inspection[source] = [{'Id': image, 'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': refs}]
            self.contents[image] = payload()

    def __call__(self, args):
        self.calls.append(args)
        if args[:3] == ['docker', 'image', 'inspect']:
            return json.dumps(self.inspection[args[3]]).encode()
        if args[args.index('--entrypoint') + 2] == IMAGE:
            if args[args.index('--entrypoint') + 1] != 'python':
                raise ValueError('hardened application has no shell')
        return self.contents[args[args.index('--entrypoint') + 2]]


class RuntimeBindingTests(unittest.TestCase):
    def test_same_complete_canonical_source_and_three_images_required(self):
        inventory.runtime_binding(runtime(), REVISION, IMAGE)
        for field, replacement in [('sourceRevision', 'd' * 40), ('applicationImage', 'sha256:'+'e'*64),
                                   ('phase', 'partial'), ('status', 'FAIL'), ('synthetic', False),
                                   ('productionApproved', True), ('vendorImages', {})]:
            value = runtime(); value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                inventory.runtime_binding(value, REVISION, IMAGE)

    def test_missing_duplicate_or_renamed_check_cannot_claim_complete(self):
        for changed in [sorted(inventory.CHECKS)[:-1], ['duplicate'] * len(inventory.CHECKS), [{}]]:
            value = runtime(); value['checks'] = changed
            with self.subTest(checks=changed), self.assertRaises(ValueError):
                inventory.runtime_binding(value, REVISION, IMAGE)

    def test_uninspected_wrong_uid_or_unblocked_service_rejected(self):
        for field, replacement in [('actual_container_inspected', False), ('uid', 0), ('imds_ipv6', 'allowed')]:
            value = runtime(); value['serviceBoundaries'][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                inventory.runtime_binding(value, REVISION, IMAGE)
        value = runtime(); value['serviceBoundaries'][-1] = copy.deepcopy(value['serviceBoundaries'][0])
        with self.assertRaises(ValueError): inventory.runtime_binding(value, REVISION, IMAGE)


class ImageInventoryTests(unittest.TestCase):
    def test_three_images_measured_but_vendor_assessments_remain_missing(self):
        runner = FakeDocker()
        with tempfile.TemporaryDirectory() as temp:
            report = inventory.collect(json.dumps(runtime()).encode(), REVISION, TREE, IMAGE, Path(temp), runner)
        self.assertTrue(report['inventoryComplete'])
        self.assertEqual(report['status'], 'INVENTORIED')
        self.assertFalse(report['releaseReady'])
        self.assertEqual(report['releaseStatus'], 'BLOCKED')
        self.assertEqual([i['role'] for i in report['images']], ['application', 'postgres', 'openbao'])
        self.assertTrue(all(i['assessment']['state'] == 'missing' for i in report['images']))
        for call in runner.calls:
            if call[:2] == ['docker', 'run']:
                self.assertEqual(call[call.index('--pull')+1], 'never')
                self.assertEqual(call[call.index('--network')+1], 'none')
                self.assertIn('--read-only', call)
                self.assertNotIn('--mount', call)
                self.assertNotIn('-v', call)
                self.assertNotIn('--privileged', call)

    def test_wrong_id_platform_or_repository_digest_rejected(self):
        source = VENDORS['postgres']['source']
        for field, replacement in [('Id', IMAGE), ('Architecture', 'arm64'), ('Os', 'windows'),
                                   ('RepoDigests', ['other/repository@' + source.split('@')[1]])]:
            runner = FakeDocker(); runner.inspection[source][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                inventory.image_inventory('postgres', VENDORS['postgres']['id'], runner)

    def test_missing_image_preserves_other_inventories_without_release(self):
        runner = FakeDocker(); runner.inspection[VENDORS['openbao']['source']] = []
        with tempfile.TemporaryDirectory() as temp:
            report = inventory.collect(json.dumps(runtime()).encode(), REVISION, TREE, IMAGE, Path(temp), runner)
        self.assertFalse(report['inventoryComplete'])
        self.assertFalse(report['releaseReady'])
        self.assertEqual([i['inventoryComplete'] for i in report['images']], [True, True, False])

    def test_apk_inventory_requires_actual_name_version_architecture_records(self):
        packages = 'P:busybox\nV:1.37.0-r1\nA:x86_64\nF:bin\nR:sh\n\nP:ca-certificates\nV:2026-r0\nA:x86_64\n'
        result = inventory.parse_inventory(payload('apk', packages))
        self.assertEqual(result['packageManager'], 'apk')
        self.assertEqual(len(result['packages']), 2)
        for bad in ['P:busybox\nV:1\n', packages + '\n\nP:busybox\nV:1\nA:x86_64\n', '']:
            with self.subTest(package=bad), self.assertRaises(ValueError):
                inventory.parse_inventory(payload('apk', bad))

    def test_partial_package_database_and_missing_os_or_binary_evidence_rejected(self):
        for raw in [payload(packages='libc6\t2\tamd64\thalf-configured\n'),
                    payload(packages='libc6\t2\tamd64\tinstalled\n'*2), payload(packages=''),
                    payload().replace(b'VERSION_ID="13"\n', b''), payload().split(b'\0versions')[0]]:
            with self.subTest(raw=raw), self.assertRaises(ValueError): inventory.parse_inventory(raw)


class AssessmentTests(unittest.TestCase):
    def test_source_bound_incomplete_failed_and_forged_pass_are_different(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); path = directory/'assessment.json'
            original = {'imageID': IMAGE, 'sourceRevision': REVISION, 'complete': False, 'passed': False}
            path.write_text(json.dumps(original))
            self.assertEqual(inventory.application_assessment(directory, IMAGE, REVISION)['state'], 'incomplete')
            path.write_text(json.dumps(original | {'complete': True}))
            self.assertEqual(inventory.application_assessment(directory, IMAGE, REVISION)['state'], 'failed')
            path.write_text(json.dumps(original | {'complete': True, 'passed': True}))
            self.assertEqual(inventory.application_assessment(directory, IMAGE, REVISION)['state'], 'rejected')
            path.write_text(json.dumps(original | {'sourceRevision': 'd'*40}))
            self.assertEqual(inventory.application_assessment(directory, IMAGE, REVISION)['state'], 'rejected')

    def test_successful_application_verifier_never_approves_vendor_images(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(inventory, 'application_assessment', return_value={'state': 'passed'}):
            report = inventory.collect(json.dumps(runtime()).encode(), REVISION, TREE, IMAGE, Path(temp), FakeDocker())
        self.assertEqual(report['images'][0]['assessment']['state'], 'passed')
        self.assertEqual([i['assessment']['state'] for i in report['images'][1:]], ['missing', 'missing'])
        self.assertFalse(report['releaseReady'])

    def test_packaging_requires_three_separately_verified_assessments(self):
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(inventory, 'application_assessment', return_value={'state':'passed'}), \
                patch.object(inventory, 'vendor_assessment', return_value={'state':'passed'}) as vendors:
            report = inventory.collect(json.dumps(runtime()).encode(), REVISION, TREE, IMAGE, Path(temp), FakeDocker())
        self.assertEqual(vendors.call_count, 2)
        self.assertTrue(report['releaseReady'])
        self.assertEqual(report['releaseStatus'], 'READY_FOR_PACKAGING')
        self.assertEqual(report['blockers'], [])


class CommandTests(unittest.TestCase):
    def test_cli_keeps_inventory_but_denies_release_readiness(self):
        original = inventory.collect
        def collect(*args): return original(*args, runner=FakeDocker())
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); runtime_file = directory/'runtime.json'; output = directory/'inventory.json'
            runtime_file.write_text(json.dumps(runtime()))
            args = ['delivery_inventory', '--image', IMAGE, '--runtime', str(runtime_file),
                    '--os-audit', str(directory), '--output', str(output), '--require-release-ready']
            with patch.object(sys, 'argv', args), patch.object(inventory, 'collect', side_effect=collect), \
                    patch.object(inventory, 'command', side_effect=[b'', REVISION.encode(), TREE.encode()]):
                self.assertEqual(inventory.main(), 2)
            report = json.loads(output.read_text())
            self.assertTrue(report['inventoryComplete'])
            self.assertFalse(report['releaseReady'])
            self.assertEqual(report['releaseStatus'], 'BLOCKED')

    def test_partial_runtime_still_writes_failed_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); runtime_file = directory/'runtime.json'; output = directory/'inventory.json'
            runtime_file.write_text('{"status":"PASS"}')
            args = ['delivery_inventory', '--image', IMAGE, '--runtime', str(runtime_file),
                    '--os-audit', str(directory), '--output', str(output)]
            with patch.object(sys, 'argv', args), \
                    patch.object(inventory, 'command', side_effect=[b'', REVISION.encode(), TREE.encode()]):
                self.assertEqual(inventory.main(), 1)
            self.assertFalse(json.loads(output.read_text())['inventoryComplete'])


if __name__ == '__main__': unittest.main()
