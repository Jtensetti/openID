"""Install hash-locked Debian security fixes during an isolated image build only."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import urllib.request


def download(item):
    if not item['url'].startswith(('https://security.debian.org/debian-security/pool/updates/main/',
                                   'https://deb.debian.org/debian/pool/main/')):
        raise ValueError('unexpected Debian distribution source')
    with urllib.request.urlopen(item['url'], timeout=60) as response:
        data = response.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != item['sha256']:
        raise ValueError('Debian package checksum mismatch')
    return data


def verify_versions(packages):
    for item in packages:
        actual = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}\t${db:Status-Status}', item['name']], text=True)
        if actual != item['version'] + '\tinstalled':
            raise ValueError('Debian runtime package version or installation state differs from lock')


def main():
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or os.geteuid() != 0:
        raise ValueError('requires root in the isolated Linux amd64 image build')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID', '').strip('"') != 'debian' or release.get('VERSION_CODENAME', '').strip('"') != 'trixie':
        raise ValueError('requires Debian trixie')
    lock = json.loads(Path(__file__).with_name('debian-runtime.lock.json').read_text())
    verify_versions(lock['verifyInstalled'])
    packages = lock['packages']
    with tempfile.TemporaryDirectory(prefix='openid-security-updates-') as directory:
        paths = []
        for index, item in enumerate(packages):
            current = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', item['name']], text=True)
            subprocess.run(['dpkg', '--compare-versions', current, 'le', item['version']], check=True)
            path = Path(directory) / f'{index}.deb'
            path.write_bytes(download(item))
            fields = subprocess.check_output(['dpkg-deb', '-f', str(path), 'Package', 'Version'], text=True).splitlines()
            if fields != ['Package: ' + item['name'], 'Version: ' + item['version']]:
                raise ValueError('unexpected Debian package identity')
            paths.append(str(path))
        # Download and verify every package before any install. No unpinned dependency fetch.
        subprocess.run(['dpkg', '--install', *paths], check=True,
                       env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'))
        verify_versions(packages + lock['verifyInstalled'])


if __name__ == '__main__': main()
