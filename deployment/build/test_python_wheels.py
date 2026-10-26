"""Reject missing, changed or network-enabled application wheel installations.

These source checks supplement the real network-isolated Linux builds and
their installed-package/report checks. They do not simulate BuildKit isolation.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import shlex
import unittest
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[2]
DOCKERFILES = {'pilot': 'deployment/Dockerfile', 'registry': 'deployment/cluster/Dockerfile'}
REQUIREMENTS = {
    'pilot': {'requirements.lock': 'verification/requirements.lock',
              'rp-requirements.lock': 'verification/rp-requirements.lock',
              'runtime-requirements.lock': 'verification/runtime-requirements.lock',
              '/app/aws-requirements.lock': 'deployment/aws/requirements.lock'},
    'registry': {'cluster-requirements.lock': 'verification/cluster-requirements.lock',
                 'rp-requirements.lock': 'verification/rp-requirements.lock',
                 'runtime-requirements.lock': 'verification/runtime-requirements.lock'},
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(lock, requirements, dockerfiles):
    require(lock['format'] == 1 and lock['target'] == 'CPython 3.12 Linux amd64', 'unsupported lock')
    require(set(lock['profiles']) == set(DOCKERFILES), 'profile coverage')
    require(set(lock['requirements']) == set(requirements), 'requirement coverage')
    parsed = {}
    for path, data in requirements.items():
        require(hashlib.sha256(data).hexdigest() == lock['requirements'][path], 'changed requirement file')
        parsed[path] = {}
        for line in data.decode().splitlines():
            if not line or line.startswith('#') or line in (
                    '--index-url https://pypi.org/simple',
                    '--extra-index-url https://download.pytorch.org/whl/cpu'):
                continue
            match = re.fullmatch(r'([A-Za-z0-9_.-]+)==(\S+) --hash=sha256:([a-f0-9]{64})', line)
            require(match is not None, 'requirement must be an exact version and hash')
            name, version, sha = match.groups()
            name = re.sub('[-_.]+', '-', name).lower()
            require(name not in parsed[path], 'duplicate requirement')
            parsed[path][name] = (version, sha)
    wheels = {w['name']: w for w in lock['wheels']}
    require(len(wheels) == len(lock['wheels']), 'duplicate wheel')
    all_names = set()
    for profile, paths in REQUIREMENTS.items():
        require(set(lock['profiles'][profile]['requirements']) == set(paths.values()), 'profile requirements')
        expected = {}
        for path in paths.values():
            for name, value in parsed[path].items():
                require(name not in expected or expected[name] == value, 'conflicting versions')
                expected[name] = value
        names = lock['profiles'][profile]['packages']
        require(len(names) == len(set(names)) and set(names) == set(expected), 'profile package coverage')
        all_names.update(expected)
        additions = set()
        for name, value in expected.items():
            require(name in wheels, 'missing wheel')
            wheel = wheels[name]
            require((wheel['version'], wheel['sha256']) == value, 'wheel does not match requirement')
            url = urlsplit(wheel['url'])
            host = 'download-r2.pytorch.org' if name == 'torch' else 'files.pythonhosted.org'
            require(url.scheme == 'https' and url.netloc == host and not url.query and not url.fragment, 'unapproved origin')
            require(re.fullmatch(r'[A-Za-z0-9_.+-]+\.whl', wheel['filename']) is not None, 'unsafe wheel filename')
            require(unquote(url.path.rsplit('/', 1)[-1]) == wheel['filename'], 'URL filename mismatch')
            additions.add('ADD --checksum=sha256:'+wheel['sha256']+' '+wheel['url']+' /wheels/'+wheel['filename'])
        lines = [line.strip() for line in dockerfiles[profile].replace('\\\n', ' ').splitlines()
                 if line.strip() and not line.lstrip().startswith('#')]
        require(lines[0] == 'FROM scratch AS python-wheels', 'download stage missing')
        end = next(i for i, line in enumerate(lines[1:], 1) if line.startswith('FROM '))
        require(len(lines[1:end]) == len(additions) and set(lines[1:end]) == additions, 'download stage differs from lock')
        installs = [shlex.split(line) for line in lines if line.startswith('RUN ') and ' install ' in line and ' pip ' in line]
        require(len(installs) == 1, 'unexpected application pip invocation')
        args = installs[0]
        prefix = ['RUN', '--network=none', '--mount=type=bind,from=python-wheels,source=/wheels,target=/wheels',
                  'python', '-m', 'pip', '--isolated', '--disable-pip-version-check', 'install',
                  '--no-index', '--find-links=/wheels', '--no-cache-dir', '--require-hashes', '--only-binary=:all:',
                  '--report=/usr/share/doc/openid-python/wheel-installation.json']
        require(args[:len(prefix)] == prefix, 'installation lost network isolation or hash enforcement')
        rest = args[len(prefix):]
        require(rest[::2] == ['-r']*len(paths) and len(rest) == 2*len(paths)
                and set(rest[1::2]) == set(paths), 'installation requirement coverage')
    require(set(wheels) == all_names, 'extra wheel')


class WheelBuildTests(unittest.TestCase):
    def setUp(self):
        self.lock = json.loads((ROOT/'deployment/build/python-wheels.lock.json').read_text())
        self.requirements = {p: (ROOT/p).read_bytes() for p in self.lock['requirements']}
        self.dockerfiles = {p: (ROOT/path).read_text() for p, path in DOCKERFILES.items()}

    def check(self):
        validate(self.lock, self.requirements, self.dockerfiles)

    def test_current_builds(self):
        self.check()

    def test_changed_requirements(self):
        self.requirements['verification/requirements.lock'] += b'\n'
        with self.assertRaisesRegex(ValueError, 'changed requirement'):
            self.check()

    def test_direct_url_requirement_even_with_new_file_hash(self):
        path = 'verification/requirements.lock'
        self.requirements[path] += b'torch @ https://attacker.invalid/package.whl\n'
        self.lock['requirements'][path] = hashlib.sha256(self.requirements[path]).hexdigest()
        with self.assertRaisesRegex(ValueError, 'exact version and hash'):
            self.check()

    def test_changed_wheel_hash(self):
        self.lock['wheels'][0]['sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'match requirement'):
            self.check()

    def test_missing_wheel(self):
        self.lock['wheels'].pop(0)
        with self.assertRaisesRegex(ValueError, 'missing wheel'):
            self.check()

    def test_duplicate_wheel(self):
        self.lock['wheels'].append(copy.deepcopy(self.lock['wheels'][0]))
        with self.assertRaisesRegex(ValueError, 'duplicate wheel'):
            self.check()

    def test_unapproved_origin(self):
        self.lock['wheels'][0]['url'] = self.lock['wheels'][0]['url'].replace('files.pythonhosted.org', 'attacker.invalid')
        with self.assertRaisesRegex(ValueError, 'unapproved origin'):
            self.check()

    def test_extra_download(self):
        self.dockerfiles['registry'] = self.dockerfiles['registry'].replace('FROM scratch AS python-wheels',
            'FROM scratch AS python-wheels\nADD https://attacker.invalid/package.whl /wheels/extra.whl')
        with self.assertRaisesRegex(ValueError, 'download stage'):
            self.check()

    def test_removed_isolation_hashes_index_or_readonly_mount(self):
        original = self.dockerfiles['pilot']
        for before, after in [('--network=none --mount=', '--network=default --mount='),
                              ('--require-hashes ', ''), ('--no-index ', ''),
                              ('source=/wheels,target=/wheels', 'source=/wheels,target=/wheels,rw')]:
            with self.subTest(before=before):
                self.dockerfiles['pilot'] = original.replace(before, after)
                with self.assertRaisesRegex(ValueError, 'isolation or hash'):
                    self.check()

    def test_missing_install_requirement(self):
        self.dockerfiles['pilot'] = self.dockerfiles['pilot'].replace(' -r /app/aws-requirements.lock', '')
        with self.assertRaisesRegex(ValueError, 'installation requirement'):
            self.check()


if __name__ == '__main__':
    unittest.main()
