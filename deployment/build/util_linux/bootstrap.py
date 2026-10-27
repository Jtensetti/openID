"""Install a snapshot-locked toolchain only in the disposable candidate builder."""
import hashlib
import json
import lzma
import os
from pathlib import Path
import platform
import subprocess
import urllib.request


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fields(raw):
    result = {}
    key = None
    for line in raw.splitlines():
        if line[:1].isspace() and key:
            result[key] += '\n' + line[1:]
        elif ':' in line:
            key, value = line.split(':', 1)
            result[key] = value.lstrip()
    return result


def package_index(raw):
    result = {}
    for block in raw.decode().split('\n\n'):
        item = fields(block)
        if 'Package' in item:
            key = (item['Package'], item['Version'], item['Architecture'])
            if key in result:
                raise ValueError('duplicate package identity')
            result[key] = item
    if not result:
        raise ValueError('empty package index')
    return result


def fetch(url, expected, limit):
    if not url.startswith('https://snapshot.debian.org/archive/debian/20261027T000000Z/'):
        raise ValueError('unexpected snapshot')
    with urllib.request.urlopen(url, timeout=90) as response:
        raw = response.read(limit + 1)
    if len(raw) > limit or sha(raw) != expected:
        raise ValueError('snapshot checksum mismatch')
    return raw


def check_deb(path, index):
    identity = subprocess.check_output(
        ['dpkg-deb', '-f', str(path), 'Package', 'Version', 'Architecture'], text=True)
    item = fields(identity)
    key = (item['Package'], item['Version'], item['Architecture'])
    origin = index.get(key)
    if not origin or sha(path.read_bytes()) != origin['SHA256']:
        raise ValueError('downloaded dependency is outside the locked index')
    return {'name': key[0], 'version': key[1], 'architecture': key[2],
            'sha256': origin['SHA256'], 'filename': origin['Filename']}


def main():
    if (platform.system(), platform.machine(), os.geteuid()) != ('Linux', 'x86_64', 0):
        raise ValueError('requires the isolated Linux amd64 builder')
    if os.environ.get('OPENID_PACKAGE_CANDIDATE_BUILD') != '1':
        raise ValueError('candidate builder marker absent')
    lock = json.loads(Path('/builder/candidate.lock.json').read_text())
    snapshot = lock['snapshot']
    evidence = Path('/toolchain-evidence')
    evidence.mkdir()
    release = fetch(snapshot['url'] + 'dists/trixie/InRelease',
                    snapshot['inReleaseSHA256'], 1024 * 1024)
    compressed = fetch(snapshot['url'] + 'dists/trixie/main/binary-amd64/Packages.xz',
                       snapshot['packagesCompressedSHA256'], 16 * 1024 * 1024)
    raw = lzma.decompress(compressed)
    if sha(raw) != snapshot['packagesSHA256']:
        raise ValueError('expanded package index differs')
    index = package_index(raw)
    (evidence / 'InRelease').write_bytes(release)
    with (evidence / 'archive-signature.log').open('w') as log:
        subprocess.run(['gpgv', '--status-fd=1', '--keyring',
                        '/usr/share/keyrings/debian-archive-keyring.gpg',
                        str(evidence / 'InRelease')], stdout=log, stderr=subprocess.STDOUT, check=True)
    # This directory belongs to the disposable image, not to the CI host.
    Path('/etc/apt/sources.list').write_text('')
    for path in Path('/etc/apt/sources.list.d').iterdir():
        if path.suffix in ('.list', '.sources'):
            path.unlink()
    Path('/etc/apt/sources.list.d/candidate.sources').write_text(
        'Types: deb\nURIs: ' + snapshot['url'] + '\nSuites: trixie\nComponents: main\n'
        'Architectures: amd64\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n')
    apt = ['apt-get', '-o', 'Acquire::Languages=none', '-o', 'Acquire::GzipIndexes=false']
    subprocess.run(apt + ['update'], check=True)
    releases = list(Path('/var/lib/apt/lists').glob('*_InRelease'))
    indexes = list(Path('/var/lib/apt/lists').glob('*_binary-amd64_Packages'))
    if len(releases) != 1 or sha(releases[0].read_bytes()) != snapshot['inReleaseSHA256']:
        raise ValueError('APT used a different signed release')
    if len(indexes) != 1 or sha(indexes[0].read_bytes()) != snapshot['packagesSHA256']:
        raise ValueError('APT used a different package index')
    wanted = [p['name'] + '=' + p['version'] for p in lock['buildPackages']]
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
    command = apt + ['--yes', '--no-install-recommends', '--no-remove', 'install']
    subprocess.run(command + ['--download-only', *wanted], env=env, check=True)
    downloaded = [check_deb(path, index) for path in sorted(Path('/var/cache/apt/archives').glob('*.deb'))]
    # All transitive downloads have now been bound to the reviewed snapshot.
    # Toolchain packages may contain service units; no service is started while building.
    policy = Path('/usr/sbin/policy-rc.d')
    policy.write_text('#!/bin/sh\nexit 101\n')
    policy.chmod(0o755)
    subprocess.run(command + ['--no-download', *wanted], env=env, check=True)
    if subprocess.check_output(['dpkg', '--audit']):
        raise ValueError('inconsistent toolchain package state')
    for item in lock['buildPackages']:
        actual = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', item['name']], text=True)
        if actual != item['version']:
            raise ValueError('installed build dependency differs')
    installed = subprocess.check_output(
        ['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'])
    if any(line.split(b'\t')[-1] != b'installed' for line in installed.splitlines()):
        raise ValueError('partly installed toolchain package')
    (evidence / 'installed-packages.tsv').write_bytes(installed)
    (evidence / 'downloaded-packages.json').write_text(json.dumps(downloaded, indent=2) + '\n')
    (evidence / 'candidate.lock.json').write_text(json.dumps(lock, indent=2) + '\n')
    (evidence / 'manifest.json').write_text(json.dumps(
        {p.name: sha(p.read_bytes()) for p in sorted(evidence.iterdir())}, indent=2) + '\n')


if __name__ == '__main__':
    main()
