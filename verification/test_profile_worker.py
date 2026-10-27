import base64
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from bounded_process import WorkerOutputLimit
from identity import VerifiedDocument
from profile_worker import thumbnail, limit_resources


class ProfileWorkerTests(unittest.TestCase):
    def test_disallowed_input_never_starts_worker(self):
        for raw in (b'', b'PNG', b'\xff\xd8\xff'+b'x'*2_000_000):
            with patch('profile_worker.run_bounded') as run, self.assertRaises(ValueError):
                thumbnail(raw)
            run.assert_not_called()

    def test_only_portrait_bytes_cross_worker_boundary(self):
        raw = b'\xff\xd8\xffsynthetic-input'
        jpeg = b'\xff\xd8\xffsynthetic-output\xff\xd9'
        doc = VerifiedDocument(raw, {'givenNames':'ALICE','familyName':'SYNTHETIC','documentNumber':'TEST00001'})
        with patch('profile_worker.run_bounded', return_value=subprocess.CompletedProcess([], 0, jpeg)) as run:
            result = doc.profile()
        self.assertEqual(run.call_args.kwargs['input'], raw)
        self.assertEqual((15, 2_000_000, 24_000), tuple(run.call_args.kwargs[k] for k in ('timeout','max_input','max_output')))
        self.assertEqual(result['displayName'], 'ALICE SYNTHETIC')
        self.assertNotIn('documentNumber', result)
        self.assertEqual(base64.b64decode(result['portraitJpeg']), jpeg)
        self.assertNotIn('ALICE', repr(run.call_args.args))

    def test_failure_partial_and_invalid_output_never_make_profile(self):
        for code, output in ((2,b'\xff\xd8\xffpartial\xff\xd9'),(-9,b'partial'),(0,b''),
                             (0,b'PNG'),(0,b'\xff\xd8\xfftruncated'),
                             (0,b'\xff\xd8\xff'+b'x'*24_000+b'\xff\xd9')):
            with self.subTest(code=code), patch('profile_worker.run_bounded', return_value=subprocess.CompletedProcess([],code,output)), self.assertRaises(ValueError):
                thumbnail(b'\xff\xd8\xff')

    def test_timeout_and_output_limit_are_not_converted_to_a_profile(self):
        for error in (subprocess.TimeoutExpired('worker',15),WorkerOutputLimit('worker output limit exceeded')):
            with patch('profile_worker.run_bounded', side_effect=error), self.assertRaises(type(error)):
                thumbnail(b'\xff\xd8\xff')

    def test_resource_limits_never_raise_existing_lower_limits(self):
        import resource
        with patch('profile_worker.sys.platform','linux'), patch('profile_worker.resource.getrlimit', return_value=(5,8)), patch('profile_worker.resource.setrlimit') as setlimit:
            limit_resources()
        self.assertEqual(setlimit.call_args_list[0].args,(resource.RLIMIT_CPU,(5,5)))
        self.assertEqual(setlimit.call_args_list[1].args,(resource.RLIMIT_AS,(5,5)))

    def test_real_worker_rejects_invalid_input_without_output(self):
        import profile_worker
        result=subprocess.run([sys.executable,str(Path(profile_worker.__file__).resolve())],
            input=b'not an image',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        self.assertEqual((2,b'',b''),(result.returncode,result.stdout,result.stderr))


if __name__ == '__main__': unittest.main()
