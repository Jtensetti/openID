"""Remove unused runtime code in the isolated image; preserve dpkg records/licenses."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

ROOT = Path('/usr/share/doc/openid-runtime')
POLICY = Path(__file__).with_name('runtime-policy.json')


def payload_paths(package, root=Path('/')):
    lists = list((root/'var/lib/dpkg/info').glob(package+'.list'))
    lists += list((root/'var/lib/dpkg/info').glob(package+':*.list'))
    if len(lists) != 1:
        raise ValueError('missing/ambiguous package file list: '+package)
    paths = set()
    for line in lists[0].read_text().splitlines():
        p = Path(line)
        if not p.is_absolute() or '..' in p.parts:
            raise ValueError('unsafe package file list')
        # All executable/library/config payload is removed, including shared
        # libraries without executable bits. Keep attribution and dpkg metadata.
        if str(p).startswith(('/usr/share/doc/', '/usr/share/man/', '/usr/share/lintian/')):
            continue
        actual = root / str(p).lstrip('/')
        if actual.is_symlink() or actual.is_file():
            paths.add(actual)
    return paths


def remove(paths):
    records = []
    for p in sorted(paths):
        if p.is_symlink():
            records.append({'path':str(p), 'symlink':os.readlink(p)})
        elif p.is_file():
            records.append({'path':str(p), 'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
        else:
            raise ValueError('unexpected removal target: '+str(p))
        p.unlink()
    return records


def apply(policy):
    packages = policy['removedPackages']
    paths = set()
    per_package = {}
    for package in packages:
        selected = payload_paths(package)
        per_package[package] = sorted(map(str,selected))
        paths.update(selected)
    stdlib = Path('/usr/local/lib/python3.12')
    for name in ('imaplib.py','poplib.py'):
        paths.add(stdlib/name)
    for name in ('readline.*.so','_curses*.so'):
        paths.update((stdlib/'lib-dynload').glob(name))
    for name in ('imaplib.*.pyc','poplib.*.pyc'):
        paths.update((stdlib/'__pycache__').glob(name))
    torch = stdlib/'site-packages/torch'
    if torch.is_dir():
        paths.update(p for p in (torch/'test').rglob('*') if p.is_file() or p.is_symlink())
        paths.update(p for p in (torch/'bin').iterdir() if p.name.startswith('test_') or p.name.endswith('Test'))
    for name in ('EUC-JISX0213.so','SHIFT_JISX0213.so'):
        matches = list(Path('/usr/lib/x86_64-linux-gnu/gconv').glob(name))
        if len(matches)!=1: raise ValueError('expected gconv module absent: '+name)
        paths.update(matches)
    paths.add(Path('/usr/bin/ldd'))
    records = remove(paths)
    ROOT.mkdir(parents=True,exist_ok=True)
    (ROOT/'removal.json').write_text(json.dumps({'format':1,'packages':per_package,'removed':records,
        'scope':'Final filesystem only. Original package records and licenses retained; removed code is not available at runtime.'},indent=2)+'\n')
    shutil.copyfile(POLICY,ROOT/'runtime-policy.json')
    # Resolver configuration cannot select the vulnerable DNS search-list path.
    # Python, Node and Java inherit the same empty LOCALDOMAIN value.
    site = stdlib/'site-packages/sitecustomize.py'
    if site.exists(): raise ValueError('unexpected site customization')
    site.write_text('import os\nos.environ["LOCALDOMAIN"] = ""\nos.environ["OPENCV_VIDEOIO_PRIORITY_FFMPEG"] = "0"\n')
    shutil.rmtree('/runtime-build')
    print('PASS: unused runtime payload removed; original dpkg metadata and attribution retained')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['apply']);parser.parse_args()
    if (sys.platform!='linux' or os.geteuid()!=0 or sys.version_info[:3]!=(3,12,16)
            or not Path('/app/verification/serve.py').is_file() or str(POLICY)!='/runtime-build/runtime-policy.json'):
        raise RuntimeError('requires isolated openID image build')
    apply(json.loads(POLICY.read_text()))
