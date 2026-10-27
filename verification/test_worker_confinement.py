import contextlib
import ctypes
import errno
import io
import json
import os
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import worker_confinement as policy
from bounded_process import image_worker_environment


def evaluate(number, args=(), arch=0xc000003e):
    """Evaluate emitted classic BPF against adversarial seccomp_data, not a kernel test."""
    data = struct.pack('<IIQ6Q', number, arch, 0, *(list(args) + [0] * (6 - len(args))))
    code, pc, accumulator = policy.syscall_filter(1234), 0, 0
    while pc < len(code):
        op, yes, no, value = code[pc]
        if op == policy.LD:
            accumulator = struct.unpack_from('<I', data, value)[0]
        elif op == policy.JEQ:
            pc += yes if accumulator == value else no
        elif op == policy.RET:
            return value
        else:
            raise AssertionError('unknown opcode')
        pc += 1
    raise AssertionError('unterminated filter')


class ConfinementPolicyTests(unittest.TestCase):
    def test_syscall_allowlist_blocks_sensitive_calls_and_new_abis(self):
        for number in (41, 42, 53, 56, 57, 58, 59, 62, 101, 157, 165, 200,
                       246, 272, 298, 310, 311, 317, 321, 322, 425, 426, 427,
                       434, 435, 438, 9999):
            with self.subTest(number=number):
                self.assertEqual(evaluate(number), policy.DENY)
        for number in policy.SYSCALLS.values():
            self.assertEqual(evaluate(number | 0x40000000), policy.DENY)
            self.assertEqual(evaluate(number, arch=0x40000003), policy.KILL)
        for number in (0, 1, 3, 9, 202, 318):
            self.assertEqual(evaluate(number), policy.ALLOW)

    def test_cannot_signal_parent_or_change_dumpability_or_resource_limits(self):
        self.assertEqual(evaluate(234, (1234, 1234, 0)), policy.ALLOW)
        for args in ((1235, 1234, 0), ((1 << 32) + 1234, 1234, 0)):
            self.assertEqual(evaluate(234, args), policy.DENY)
        self.assertEqual(evaluate(157, (3,)), policy.ALLOW)
        self.assertEqual(evaluate(157, (4, 1)), policy.DENY)
        self.assertEqual(evaluate(157, ((1 << 32) + 3,)), policy.DENY)
        self.assertEqual(evaluate(302, (0, 0, 0, 123)), policy.ALLOW)
        for args in ((1235, 0, 0, 123), (0, 0, 123, 123), (0, 0, 1 << 32, 123)):
            self.assertEqual(evaluate(302, args), policy.DENY)
        self.assertEqual(evaluate(72, (1, 3)), policy.ALLOW)
        self.assertEqual(evaluate(72, (1, 8, 1235)), policy.DENY)  # F_SETOWN

    def test_native_struct_layouts_match_linux_uapi(self):
        self.assertEqual(ctypes.sizeof(policy.Ruleset), 8)
        self.assertEqual(ctypes.sizeof(policy.PathRule), 12)
        self.assertEqual(ctypes.sizeof(policy.Instruction), 8)

    def test_macos_does_not_claim_linux_protection(self):
        with patch.object(policy.sys, 'platform', 'darwin'):
            self.assertFalse(policy.confine_image_worker())

    def test_unsupported_linux_architecture_fails_closed(self):
        with patch.object(policy.sys, 'platform', 'linux'), \
                patch.object(policy.os, 'uname') as uname:
            uname.return_value.machine = 'aarch64'
            with self.assertRaises(policy.ConfinementUnavailable):
                policy.confine_image_worker()

    def test_missing_landlock_and_rejected_seccomp_are_not_optional(self):
        from unittest.mock import Mock
        for abi in (-1, 0, 1, 2):
            libc = Mock()
            libc.syscall.return_value = abi
            with self.subTest(abi=abi), self.assertRaises(policy.ConfinementUnavailable):
                policy._landlock(libc, [])
        for outcomes in ((-1,), (0, 0), (0, 1, -1), (0, 1, 0, 0)):
            libc = Mock()
            libc.prctl.side_effect = outcomes
            with self.subTest(outcomes=outcomes), patch.object(policy.sys, 'platform', 'linux'), \
                    patch.object(policy.os, 'uname') as uname, \
                    patch.object(policy.os, 'listdir', return_value=['1']), \
                    patch.object(policy.ctypes, 'sizeof', return_value=8), \
                    patch.object(policy, 'read_paths', return_value=[]), \
                    patch.object(policy, '_landlock'), \
                    patch.object(policy.ctypes, 'CDLL', return_value=libc):
                uname.return_value.machine = 'x86_64'
                with self.assertRaises(policy.ConfinementUnavailable):
                    policy.confine_image_worker()

    def test_read_policy_cannot_be_expanded_by_env_or_source_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            source.mkdir()
            secret = Path(directory) / 'secret'
            secret.write_text('synthetic only')
            (source / 'injected.py').symlink_to(secret)
            with patch.object(policy, '__file__', str(source / 'worker_confinement.py')), \
                    patch.dict(os.environ, {'PYTHONPATH': str(secret), 'HOME': directory}):
                self.assertNotIn(secret.resolve(), policy.read_paths())
                (source / 'models').symlink_to(directory, target_is_directory=True)
                with self.assertRaises(policy.ConfinementUnavailable):
                    policy.read_paths()

    def test_entrypoints_stop_before_input_and_native_imports_when_policy_fails(self):
        import builtins
        for worker in ('profile_worker', 'biometric_worker'):
            output, errors = io.StringIO(), io.StringIO()
            with self.subTest(worker=worker), \
                    patch('bounded_process.disable_worker_core_dumps'), \
                    patch('resource.setrlimit'), \
                    patch.object(policy, 'confine_image_worker', side_effect=OSError('PRIVATE')), \
                    patch('sys.stdin') as input_stream, \
                    patch('builtins.__import__', wraps=builtins.__import__) as imports, \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                with self.assertRaises(SystemExit) as caught:
                    runpy.run_module(worker, run_name='__main__')
            self.assertEqual(caught.exception.code, 2)
            input_stream.buffer.read.assert_not_called()
            self.assertFalse(any(call.args[0] in ('cv2', 'face', 'pad', 'numpy') for call in imports.call_args_list))
            self.assertEqual((output.getvalue(), errors.getvalue()), ('', ''))


@unittest.skipUnless(sys.platform == 'linux', 'actual confinement requires Linux')
class LinuxConfinementTests(unittest.TestCase):
    def run_child(self, code, *args, pass_fds=()):
        environment = image_worker_environment()
        # Packaged tests can live outside /app/verification; import the installed policy.
        module_path = str(Path(policy.__file__).resolve().parent)
        environment['PYTHONPATH'] = module_path + os.pathsep + environment.get('PYTHONPATH', '')
        return subprocess.run([sys.executable, '-c', code, *map(str, args)],
            input=b'', capture_output=True, timeout=10, env=environment, pass_fds=pass_fds)

    def test_real_files_network_process_access_and_unknown_syscalls_are_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / 'key'
            secret.write_text('synthetic private key')
            alias = Path(directory) / 'alias'
            alias.symlink_to(secret)
            code = r'''
import ctypes, errno, json, os, socket, sys
from bounded_process import disable_worker_core_dumps
from worker_confinement import confine_image_worker
libc = ctypes.CDLL(None, use_errno=True)
parent = os.getppid()
disable_worker_core_dumps()
assert confine_image_worker() is True
def denied(operation):
    try: operation()
    except OSError as error: assert error.errno in (errno.EPERM, errno.EACCES), error.errno
    else: raise AssertionError('operation unexpectedly permitted')
for path in (sys.argv[1], sys.argv[2], f'/proc/{parent}/environ', f'/proc/{parent}/mem'):
    denied(lambda: os.open(path, os.O_RDONLY))
denied(lambda: os.open(sys.argv[1], os.O_WRONLY | os.O_TRUNC))
denied(lambda: os.open(sys.argv[1]+'new', os.O_CREAT | os.O_WRONLY, 0o600))
denied(lambda: os.chmod(sys.argv[1], 0o777))
for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
    denied(lambda: socket.socket(family))
denied(socket.socketpair)
denied(lambda: os.kill(parent, 0))
denied(os.fork)
for number in (101, 310, 311, 425, 426, 427, 435, 438, 9999, 0x40000029):
    ctypes.set_errno(0)
    assert libc.syscall(number, 0, 0, 0, 0, 0, 0) == -1
    assert ctypes.get_errno() == errno.EPERM
assert libc.prctl(3,0,0,0,0) == 0
assert libc.prctl(39,0,0,0,0) == 1
assert libc.prctl(21,0,0,0,0) == 2
assert libc.prctl(4,1,0,0,0) == -1
with open(sys.argv[3], 'rb') as allowed: assert allowed.read(10)
print(json.dumps({'confined':True,'negativeOperations':'passed'}))
'''
            result = self.run_child(code, secret, alias, policy.__file__)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(json.loads(result.stdout), {'confined': True, 'negativeOperations': 'passed'})
            self.assertEqual(secret.read_text(), 'synthetic private key')
            self.assertFalse(Path(str(secret)+'new').exists())

    def test_inherited_file_descriptor_cannot_bypass_policy(self):
        with tempfile.TemporaryFile() as file:
            result = self.run_child('''
from worker_confinement import ConfinementUnavailable, confine_image_worker
try: confine_image_worker()
except ConfinementUnavailable: print('rejected')
else: raise AssertionError('inherited descriptor accepted')
''', pass_fds=(file.fileno(),))
        self.assertEqual((result.returncode, result.stdout), (0, b'rejected\n'), result.stderr.decode())

    def test_existing_background_thread_cannot_escape_policy(self):
        result = self.run_child('''
import threading
from worker_confinement import ConfinementUnavailable, confine_image_worker
stop = threading.Event()
thread = threading.Thread(target=stop.wait)
thread.start()
try:
    try: confine_image_worker()
    except ConfinementUnavailable: print('rejected')
    else: raise AssertionError('existing thread accepted')
finally:
    stop.set()
    thread.join()
''')
        self.assertEqual((result.returncode, result.stdout), (0, b'rejected\n'), result.stderr.decode())


if __name__ == '__main__':
    unittest.main()
