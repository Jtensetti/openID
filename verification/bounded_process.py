"""Bounded POSIX worker pipes; this is not a filesystem/network sandbox."""
import math
import os
import selectors
import signal
import subprocess
import sys
import time


class WorkerOutputLimit(OSError):
    pass


def disable_worker_core_dumps():
    """Call in the image child before loading codecs/models or reading input."""
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.platform == 'linux':
        # RLIMIT_CORE alone does not block Linux's piped crash collectors.
        import ctypes
        prctl = ctypes.CDLL(None, use_errno=True).prctl
        prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
        prctl.restype = ctypes.c_int
        # Linux UAPI: PR_SET_DUMPABLE=4, PR_GET_DUMPABLE=3.
        if prctl(4, 0, 0, 0, 0) != 0 or prctl(3, 0, 0, 0, 0) != 0:
            raise OSError('image worker dump protection unavailable')


def image_worker_environment():
    # Preserve the reviewed native-candidate import path, not service secrets
    # or dynamic-loader overrides from the parent environment.
    environment = {'PATH': os.defpath, 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'OMP_NUM_THREADS': '1', 'OPENBLAS_NUM_THREADS': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    if 'PYTHONPATH' in os.environ:
        environment['PYTHONPATH'] = os.environ['PYTHONPATH']
    return environment


def run_bounded(args, *, input, timeout, max_input, max_output, env=None):
    if (not isinstance(input, bytes) or type(max_input) is not int or max_input < 0
            or len(input) > max_input or type(max_output) is not int or max_output < 1
            or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError('invalid worker bounds')
    deadline = time.monotonic() + timeout
    output, offset = bytearray(), 0
    process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, bufsize=0, close_fds=True, start_new_session=True, env=env)
    try:
        with selectors.DefaultSelector() as selected:
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            selected.register(process.stdout, selectors.EVENT_READ)
            if input:
                selected.register(process.stdin, selectors.EVENT_WRITE)
            else:
                process.stdin.close()
            while selected.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(args, timeout)
                for key, events in selected.select(remaining):
                    if key.fileobj is process.stdout:
                        try:
                            data = os.read(key.fd, min(65536, max_output + 1 - len(output)))
                        except BlockingIOError:
                            continue
                        if not data:
                            selected.unregister(process.stdout)
                            process.stdout.close()
                        else:
                            output.extend(data)
                            if len(output) > max_output:
                                raise WorkerOutputLimit('worker output limit exceeded')
                    else:
                        try:
                            offset += os.write(key.fd, memoryview(input)[offset:offset+65536])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            selected.unregister(process.stdin)
                            process.stdin.close()
                            continue
                        if offset == len(input):
                            selected.unregister(process.stdin)
                            process.stdin.close()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(args, timeout)
        code = process.wait(timeout=remaining)
        if code == 0 and offset != len(input):
            raise OSError('worker exited before input was sent')
        return subprocess.CompletedProcess(args, code, bytes(output))
    finally:
        # On pipe/timeout failure the child has not been reaped, so its PID
        # still identifies the private process group created by Popen.
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        process.stdin.close()
        process.stdout.close()
