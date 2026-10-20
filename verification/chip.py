import base64
import json
import os
import selectors
import subprocess
import threading
import time


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result


class ChipProcess:
    """One server-side JMRTD session; no keys or process options cross the API."""
    slots = threading.BoundedSemaphore(4)

    def __init__(self, command, document, timeout=75):
        if not self.slots.acquire(blocking=False):
            raise ValueError('chip capacity')
        self.process = None
        self.closed = False
        self.lock = threading.Lock()
        self.buffer = bytearray()
        self.sequence = -1
        self.deadline = time.monotonic() + timeout
        self.timer = threading.Timer(timeout, self.close)
        self.timer.daemon = True
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL)
            self.timer.start()
            self._write({field: document[field] for field in ('sod', 'dg1', 'dg2', 'dg14')})
        except BaseException:
            self.close()
            raise

    def _write(self, data):
        if self.closed:
            raise ValueError('chip closed')
        self.process.stdin.write(json.dumps(data, separators=(',', ':')).encode() + b'\n')
        self.process.stdin.flush()

    def next(self, response=None, sequence=None):
        try:
            if response is not None:
                if type(sequence) is not int or sequence != self.sequence:
                    raise ValueError('chip sequence')
                raw = base64.b64decode(response, validate=True)
                if not 2 <= len(raw) <= 4096:
                    raise ValueError('chip response size')
                self._write({'sequence': sequence, 'response': response})
            elif self.sequence != -1:
                raise ValueError('chip response missing')
            result = self._read()
            if result == {'type': 'verified'}:
                if self.sequence < 0 or self.process.wait(timeout=2) != 0:
                    raise ValueError('chip failed')
                self.close()
                return result
            if (not isinstance(result, dict) or set(result) != {'type', 'sequence', 'command'}
                    or result['type'] != 'command' or type(result['sequence']) is not int
                    or result['sequence'] != self.sequence + 1 or result['sequence'] >= 128):
                raise ValueError('chip protocol')
            raw = base64.b64decode(result['command'], validate=True)
            if not 4 <= len(raw) <= 4096:
                raise ValueError('chip command size')
            self.sequence = result['sequence']
            return result
        except BaseException:
            self.close()
            raise

    def _read(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while b'\n' not in self.buffer:
                remaining = min(15, self.deadline - time.monotonic())
                if self.closed or remaining <= 0 or not selector.select(remaining):
                    raise ValueError('chip timeout')
                chunk = os.read(self.process.stdout.fileno(), 8193 - len(self.buffer))
                if not chunk:
                    raise ValueError('chip process stopped')
                self.buffer.extend(chunk)
                if len(self.buffer) > 8192:
                    raise ValueError('chip message size')
            line, _, rest = self.buffer.partition(b'\n')
            self.buffer = bytearray(rest)
            return json.loads(line, object_pairs_hook=unique_object)

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            self.timer.cancel()
            if self.process is not None:
                if self.process.poll() is None:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=2)
                self.process.stdin.close()
                self.process.stdout.close()
            self.buffer.clear()
            self.slots.release()
