"""Remove unused package installers from the final runtime filesystem."""
import importlib.metadata
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
    stdlib = Path(sysconfig.get_path('stdlib'))
    if stdlib != Path('/usr/local/lib/python3.12'):
        raise ValueError('unexpected Python installation')
    root = Path('/usr/share/doc/openid-python')
    version = json.loads((root/'build-lock.json').read_text())['pip']['version']
    if importlib.metadata.version('pip') != version:
        raise ValueError('unexpected pip version before removal')
    packages = stdlib/'site-packages'
    targets = [packages/'pip', packages/('pip-'+version+'.dist-info'), stdlib/'ensurepip']
    for target in targets:
        if target.is_symlink() or not target.is_dir():
            raise ValueError('unexpected package path: '+str(target))
    # Record removed installer files; retain original component metadata/SBOM.
    removed = []
    removed_files = {}
    def record_files(directory):
        for item in directory.rglob('*'):
            if item.is_symlink():
                raise ValueError('unexpected installer symlink')
            if item.is_file():
                removed_files[str(item)] = hashlib.sha256(item.read_bytes()).hexdigest()
    for target in targets:
        record_files(target)
        shutil.rmtree(target)
        removed.append(str(target))
    for name in ('pip', 'pip3', 'pip3.12'):
        target = Path('/usr/local/bin')/name
        if not target.is_file():
            raise ValueError('unexpected pip launcher: '+str(target))
        if target.is_symlink() and target.resolve().parent != Path('/usr/local/bin'):
            raise ValueError('unexpected launcher symlink target')
        removed_files[str(target)] = hashlib.sha256(target.read_bytes()).hexdigest()
        target.unlink()
        removed.append(str(target))
    subprocess.run([sys.executable, '-I', '-c',
                    "import importlib.util; assert importlib.util.find_spec('pip') is None; "
                    "assert importlib.util.find_spec('ensurepip') is None"], check=True)
    if list(packages.glob('pip*')) or list(Path('/usr/local/bin').glob('pip*')):
        raise ValueError('remaining pip package or launcher')
    report = {'removed': removed, 'removedFileSHA256': removed_files,
              'pipImportable': False, 'ensurepipImportable': False,
              'scope': 'Final runtime filesystem; historical build layers and build-tool risks are separate.'}
    (root/'pip-removal.json').write_text(json.dumps(report, indent=2)+'\n')
    with (root/'BUILD-NOTICE.txt').open('a') as notice:
        notice.write('pip and ensurepip removed from the final runtime filesystem; build-tool licenses and SBOM retained.\n')
    print('PASS: runtime has neither pip nor ensurepip; build licenses retained')


if __name__ == '__main__':
    main()
