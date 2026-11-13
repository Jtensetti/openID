"""A changed source input or output must stop before a vendor image can be used."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import vendor_images as images


class DerivedSourceTests(unittest.TestCase):
    def test_exact_inputs_and_reject_missing_changed_or_linked_sources(self):
        for role, vendor in images.VENDORS.items():
            images.check_inputs(role)
            changed = copy.deepcopy(vendor)
            changed['build']['builderImage'] = 'moby/buildkit:latest'
            with self.subTest(role=role, mutation='builder'), self.assertRaises(ValueError):
                images.check_inputs(role, changed)
            with tempfile.TemporaryDirectory() as temp:
                context = Path(temp)
                for name in vendor['build']['inputs']:
                    target = context/name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(images.CONTEXT/name, target)
                target = context/vendor['build']['recipe']
                original = target.read_bytes()
                for mutation in ('changed', 'missing', 'linked', 'unlisted'):
                    changed = copy.deepcopy(vendor)
                    if mutation == 'changed': target.write_bytes(original+b'changed')
                    elif mutation == 'missing': target.unlink()
                    elif mutation == 'linked':
                        target.unlink(); target.symlink_to(images.CONTEXT/target.name)
                    else: changed['build']['inputs']['../unlisted'] = '0'*64
                    with self.subTest(role=role, mutation=mutation), self.assertRaises(ValueError):
                        images.check_inputs(role, changed, context)
                    target.unlink(missing_ok=True); target.write_bytes(original)

    def test_wrong_base_stops_build_and_wrong_output_cannot_pass(self):
        vendor = images.VENDORS['postgres']
        base = {'Id': vendor['baseID'], 'Os': 'linux', 'Architecture': 'amd64'}
        wrong = dict(base, Id='sha256:'+'e'*64)
        with patch.object(images.subprocess, 'run') as run, \
                patch.object(images.subprocess, 'check_output', return_value=json.dumps([wrong])):
            with self.assertRaises(ValueError): images.build('postgres')
            self.assertEqual(run.call_count, 1)  # Pull only; never compile against a changed base.
        with patch.object(images.subprocess, 'run'), \
                patch.object(images.subprocess, 'check_output', side_effect=[json.dumps([base]), json.dumps([wrong])]):
            with self.assertRaises(ValueError): images.build('postgres')


if __name__ == '__main__': unittest.main()
