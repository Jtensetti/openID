import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from bounded_process import WorkerOutputLimit, image_worker_environment, run_bounded


class BoundedProcessTests(unittest.TestCase):
    def test_image_worker_environment_excludes_secrets_and_loader_overrides(self):
        with patch.dict(os.environ, {'AWS_SECRET_ACCESS_KEY':'synthetic-secret',
                'SERVICE_TOKEN':'synthetic-token','LD_PRELOAD':'untrusted.so',
                'PYTHONPATH':'/opt/openid-opencv/python:/app/verification'}, clear=True):
            environment=image_worker_environment()
        self.assertEqual(set(environment),{'PATH','LANG','LC_ALL','OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','PYTHONDONTWRITEBYTECODE','PYTHONPATH'})
        self.assertEqual(environment['PYTHONPATH'],'/opt/openid-opencv/python:/app/verification')
        self.assertEqual(environment['OMP_NUM_THREADS'],'1')

    def run_worker(self, code, data=b'', timeout=5, limit=4096):
        return run_bounded([sys.executable, '-c', code], input=data,
            timeout=timeout, max_input=2_000_000, max_output=limit)

    def test_large_input_and_output_are_drained_concurrently(self):
        import hashlib
        data = b'x'*1_000_000
        result = self.run_worker("import sys,hashlib; sys.stdout.buffer.write(b'a'*70000); sys.stdout.flush(); print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest(),end='')", data, limit=70064)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'a'*70000+hashlib.sha256(data).hexdigest().encode())

    def test_exact_output_limit_and_one_byte_over(self):
        self.assertEqual(self.run_worker("print('a'*64,end='')", limit=64).stdout, b'a'*64)
        with self.assertRaises(WorkerOutputLimit):
            self.run_worker("print('a'*65,end='')", limit=64)

    def test_unbounded_output_is_killed_and_reaped_without_returning_payload(self):
        launched = []
        real = subprocess.Popen
        def start(*args, **kwargs):
            process = real(*args, **kwargs); launched.append(process); return process
        with patch('bounded_process.subprocess.Popen', side_effect=start), self.assertRaises(WorkerOutputLimit) as caught:
            self.run_worker("import os\nwhile True: os.write(1,b'PRIVATE'*2000)", limit=64)
        self.assertNotIn('PRIVATE', str(caught.exception))
        self.assertIsNotNone(launched[0].returncode)
        self.assertLess(launched[0].returncode, 0)

    def test_timeout_when_input_is_not_consumed(self):
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            self.run_worker('import time; time.sleep(30)', b'PRIVATE'*100_000, timeout=.2)
        self.assertIsNone(caught.exception.output)

    def test_timeout_after_output_pipe_closes(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_worker('import os,time; os.close(1); time.sleep(30)', timeout=.2)

    def test_early_success_cannot_skip_large_input(self):
        with self.assertRaises(OSError):
            self.run_worker('import os; os.close(0); os.write(1,b"ok")', b'x'*1_000_000)

    def test_failure_code_and_partial_output_are_not_success(self):
        result = self.run_worker('import os; os.write(1,b"partial"); os.write(2,b"PRIVATE"); os._exit(7)')
        self.assertEqual((7, b'partial'), (result.returncode, result.stdout))
        self.assertIsNone(result.stderr)

    def test_invalid_limits_and_oversized_input_do_not_start_process(self):
        for changes in ({'input': b'x'*3, 'max_input': 2}, {'timeout': float('inf')},
                        {'timeout': True}, {'max_output': 0}, {'input': 'text'}):
            values = dict(input=b'', timeout=1, max_input=2, max_output=10); values.update(changes)
            with self.subTest(changes=list(changes)), patch('bounded_process.subprocess.Popen') as start:
                with self.assertRaises(ValueError): run_bounded([sys.executable], **values)
                start.assert_not_called()


if __name__ == '__main__': unittest.main()
