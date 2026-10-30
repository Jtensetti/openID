"""Bootstrap the hash-locked build tool without trusting the builder's pip."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig


def main():
    if sys.platform != 'linux' or os.geteuid() != 0 or sys.version_info[:3] != (3, 12, 16):
        raise RuntimeError('requires the isolated Python 3.12.16 image build')
    if sysconfig.get_path('stdlib') != '/usr/local/lib/python3.12':
        raise ValueError('unexpected Python installation')
    root = Path('/usr/share/doc/openid-python')
    lock = json.loads((root/'build-lock.json').read_text())['pip']
    wheel = Path('/tmp')/lock['wheelName']
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != lock['sha256']:
        raise ValueError('pip wheel checksum mismatch')
    # Run pip directly from the verified wheel, even when no pip is installed.
    environment = dict(os.environ, PYTHONPATH=str(wheel))
    subprocess.run([sys.executable, '-m', 'pip', '--isolated', '--disable-pip-version-check',
                    'install', '--ignore-installed', '--no-index', '--no-deps', '--no-cache-dir',
                    '--only-binary=:all:', str(wheel)], env=environment, check=True)
    from importlib.metadata import distribution
    installed = distribution('pip')
    if installed.version != lock['version']:
        raise ValueError('unexpected installed pip version')
    # A fresh interpreter must find the installed package without PYTHONPATH.
    version = subprocess.check_output([sys.executable, '-I', '-m', 'pip', '--version'], text=True)
    if not version.startswith('pip '+lock['version']+' '):
        raise ValueError('build pip is not available in the image')
    sbom = Path(installed.locate_file('pip/_vendor/bom.cdx.json')).read_bytes()
    if hashlib.sha256(sbom).hexdigest() != lock['sbomSHA256']:
        raise ValueError('installed pip SBOM mismatch')
    (root/'pip-upstream-sbom.cdx.json').write_bytes(sbom)
    licenses = {}
    for item in installed.files:
        if not any(word in item.name.upper() for word in ('LICENSE', 'COPYING', 'AUTHORS', 'NOTICE', 'COPYRIGHT')):
            continue
        if item.is_absolute() or '..' in item.parts:
            raise ValueError('unexpected pip license path')
        source = Path(installed.locate_file(item))
        target = root/'pip-licenses'/str(item)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        licenses[str(item)] = hashlib.sha256(target.read_bytes()).hexdigest()
    if not licenses:
        raise ValueError('pip licenses missing')
    report = {'version': lock['version'], 'wheelSHA256': lock['sha256'],
              'licenseSHA256': licenses, 'scope': 'Build tool; removed after package installation.',
              'limits': ['Vendored components require separate build-time advisory assessment.']}
    (root/'pip-build-tool.json').write_text(json.dumps(report, indent=2)+'\n')
    print('PASS: hash-locked pip installed without using builder site-packages')


if __name__ == '__main__':
    main()
