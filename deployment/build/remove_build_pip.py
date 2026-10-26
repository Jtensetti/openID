"""Remove unused package installers from the final runtime filesystem."""
import importlib.metadata
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
    removed = []
    for target in targets:
        shutil.rmtree(target)
        removed.append(str(target))
    for name in ('pip', 'pip3', 'pip3.12'):
        target = Path('/usr/local/bin')/name
        if not target.is_file() or target.is_symlink():
            raise ValueError('unexpected pip launcher: '+str(target))
        target.unlink()
        removed.append(str(target))
    subprocess.run([sys.executable, '-I', '-c',
                    "import importlib.util; assert importlib.util.find_spec('pip') is None; "
                    "assert importlib.util.find_spec('ensurepip') is None"], check=True)
    if list(packages.glob('pip*')) or list(Path('/usr/local/bin').glob('pip*')):
        raise ValueError('remaining pip package or launcher')
    report = {'removed': removed, 'pipImportable': False, 'ensurepipImportable': False,
              'scope': 'Final runtime filesystem; historical build layers and build-tool risks are separate.'}
    (root/'pip-removal.json').write_text(json.dumps(report, indent=2)+'\n')
    with (root/'BUILD-NOTICE.txt').open('a') as notice:
        notice.write('pip and ensurepip removed from the final runtime filesystem; build-tool licenses and SBOM retained.\n')
    print('PASS: runtime has neither pip nor ensurepip; build licenses retained')


if __name__ == '__main__':
    main()
