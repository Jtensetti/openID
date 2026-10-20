"""Bounded, serial IPC to Node's crypto library. No custom cryptographic operations."""
import json
from pathlib import Path
import os
import selectors
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parent


class CryptoProcess:
    def __init__(self, kind, timeout=10):
        if kind not in ('signature', 'profile'): raise ValueError('crypto operation')
        self.kind, self.timeout = kind, timeout
        self.process = None
        self.lock = threading.Lock()
        self.calls = 0

    @staticmethod
    def terminate(process):
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=1)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=2)

    def close(self):
        with self.lock: self._close()

    def _close(self):
        if self.process is not None:
            self.terminate(self.process)
            self.process.stdin.close(); self.process.stdout.close()
            self.process = None

    def __call__(self, request):
        raw = json.dumps(request, separators=(',', ':'), allow_nan=False).encode()+b'\n'
        if len(raw)>100000: raise ValueError('crypto input size')
        with self.lock:
            if self.process is not None and (self.process.poll() is not None or self.calls>=1000): self._close()
            if self.process is None:
                self.process = subprocess.Popen(['node',str(ROOT/'crypto-worker.mjs'),self.kind],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
                self.calls = 0
            process = self.process
            timer = threading.Timer(self.timeout, self.terminate, args=(process,))
            timer.daemon = True
            timer.start()
            try:
                process.stdin.write(raw); process.stdin.flush()
                data = bytearray(); deadline = time.monotonic()+self.timeout
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while not data.endswith(b'\n'):
                        remaining = deadline-time.monotonic()
                        if remaining<=0 or not selector.select(remaining): raise TimeoutError('crypto timeout')
                        chunk=os.read(process.stdout.fileno(),100001-len(data))
                        if not chunk: raise ValueError('crypto process stopped')
                        data.extend(chunk)
                        if len(data)>100000: raise ValueError('crypto output size')
                result=json.loads(data)
                if result.get('ok') is not True: raise ValueError('crypto rejected')
                self.calls+=1
                return result['result']
            except BaseException:
                self._close()
                raise
            finally:
                timer.cancel()


class CryptoRuntime:
    def __init__(self):
        self.signature = CryptoProcess('signature')
        self.profile = CryptoProcess('profile')

    def device(self, operation, **data):
        if self.signature({'operation': operation, **data}).get('valid') is not True:
            raise ValueError('device signature rejected')

    def close(self):
        self.signature.close(); self.profile.close()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
