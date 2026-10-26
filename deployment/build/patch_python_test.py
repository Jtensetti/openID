"""Backport one upstream test expectation, never runtime TLS behavior.

Expectation derived from CPython test_ssl.py at the revision in the build lock.
PSF license is retained with the CPython source and final build evidence.
"""
import hashlib
import json
from pathlib import Path


def patch_source(original, lock):
    if hashlib.sha256(original).hexdigest() != lock['originalSHA256']:
        raise ValueError('unexpected original TLS test source')
    start = original.index(b'    def test_pha_required_nocert(')
    end = original.index(b'\n    def ', start+10)
    old = b"                    ssl.SSLError,\n                    '(certificate required|EOF occurred)'"
    new = b"                    OSError,\n                    ('certificate required'\n                     '|EOF occurred'\n                     '|closed by the remote host'\n                     '|Connection reset by peer'\n                     '|Broken pipe')"
    section = original[start:end]
    if section.count(old) != 1:
        raise ValueError('ambiguous TLS test expectation')
    patched = original[:start]+section.replace(old, new)+original[end:]
    if hashlib.sha256(patched).hexdigest() != lock['patchedSHA256']:
        raise ValueError('unexpected patched TLS test source')
    return patched


if __name__ == '__main__':
    lock = json.loads(Path('/tmp/python-runtime.lock.json').read_text())['tlsTestPatch']
    source = Path('/usr/src/openid-python/Lib/test/test_ssl.py')
    source.write_bytes(patch_source(source.read_bytes(), lock))
    Path('/stage/usr/share/doc/openid-python/tls-test-patch.json').write_text(json.dumps(lock, indent=2)+'\n')
