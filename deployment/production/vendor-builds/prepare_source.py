"""Apply only the reviewed dependency manifests to checksum-bound upstream source."""
import hashlib
import json
from pathlib import Path
import sys


def prepare(source, patch):
    lock = json.loads((patch/'sources.lock.json').read_text())
    expected = {'go.mod':'openbao.go.mod', 'go.sum':'openbao.go.sum',
                'internal/vault/login_mfa.go':'openbao.login_mfa.go'}
    if (set(lock['sourceFiles']) != set(expected) or
            any(item.get('replacement') != expected[name] for name,item in lock['sourceFiles'].items())):
        raise ValueError('complete fixed dependency patch required')
    for name, hashes in lock['sourceFiles'].items():
        if name not in {'go.mod', 'go.sum', 'internal/vault/login_mfa.go'}:
            raise ValueError('unexpected source patch')
        target, replacement = source/name, patch/hashes['replacement']
        for path, expected in [(target, hashes['upstreamSHA256']),
                               (replacement, hashes['modifiedSHA256'])]:
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError('upstream or dependency patch changed')
    for name in lock['sourceFiles']:
        (source/name).write_bytes((patch/lock['sourceFiles'][name]['replacement']).read_bytes())
    (source/'internal/vault/tjipp_mfa_test.go').write_bytes((patch/'tjipp_mfa_test.go').read_bytes())


if __name__ == '__main__': prepare(Path(sys.argv[1]), Path(sys.argv[2]))
