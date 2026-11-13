"""Retain each resolved Go module's license and notice files, including nested ones."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def collect(destination):
    # Inspect the actual production import graph. `go list -m all` also lists
    # lazy, uncompiled test/tool modules whose source was never downloaded.
    raw = subprocess.check_output(['go', 'list', '-mod=readonly', '-tags=openbao', '-deps', '-json', '.'], text=True)
    decoder = json.JSONDecoder(); modules = []; pos = 0; resolved = {}
    supplements = Path(__file__).with_name('supplemental-licenses')
    supplemental = json.loads((supplements/'lock.json').read_text())
    destination.mkdir(parents=True)
    while pos < len(raw):
        if raw[pos].isspace(): pos += 1; continue
        package, length = decoder.raw_decode(raw[pos:]); pos += length
        module = package.get('Module')
        if module is not None: resolved[module['Path']] = module
    if not resolved: raise ValueError('empty production module inventory')
    for module in sorted(resolved.values(), key=lambda m:m['Path']):
        origin = module.get('Replace', module)
        root = Path(origin['Dir']) if origin.get('Dir') else None
        if root is None: raise ValueError('module source unavailable: '+module['Path'])
        files = []
        for path in sorted(root.rglob('*')):
            if not path.is_file() or path.is_symlink(): continue
            if not path.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'AUTHORS')): continue
            relative = path.relative_to(root)
            target = destination/'modules'/module['Path']/module.get('Version', 'local')/relative
            target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(path, target)
            files.append({'path': str(relative), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        key = module['Path']+'@'+module.get('Version','local')
        if not files and module.get('Replace'):
            local = {'./api','./api/auth/kubernetes','./internal/helper/stubbolt','./sdk'}
            if module['Replace']['Path'] not in local:
                raise ValueError('unreviewed local module license inheritance')
            license_path = Path.cwd()/'LICENSE'
            target = destination/'modules'/module['Path']/'local'/'LICENSE'
            target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(license_path,target)
            files.append({'path':'LICENSE','inheritedFrom':'OpenBao source root (MPL-2.0)',
                          'sha256':hashlib.sha256(license_path.read_bytes()).hexdigest()})
        if not files and key in supplemental:
            record = supplemental[key]; license_path = supplements/record['file']
            if (license_path.is_symlink() or license_path.parent != supplements or
                    hashlib.sha256(license_path.read_bytes()).hexdigest() != record['sha256']):
                raise ValueError('supplemental license changed')
            target = destination/'modules'/module['Path']/module['Version']/'LICENSE'
            target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(license_path,target)
            files.append({'path':'LICENSE', **record})
        if not files:
            raise ValueError('module license unavailable: '+module['Path'])
        modules.append({k:v for k,v in module.items() if k in {'Path','Version','Sum','GoModSum','Replace'}} | {'licenseFiles':files})
    (destination/'modules.json').write_text(json.dumps(modules, sort_keys=True, indent=2)+'\n')


if __name__ == '__main__': collect(Path(sys.argv[1]))
