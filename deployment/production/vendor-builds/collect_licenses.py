"""Retain each resolved Go module's license and notice files, including nested ones."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def collect(destination):
    raw = subprocess.check_output(['go', 'list', '-mod=readonly', '-m', '-json', 'all'], text=True)
    decoder = json.JSONDecoder(); modules = []; pos = 0
    destination.mkdir(parents=True)
    while pos < len(raw):
        if raw[pos].isspace(): pos += 1; continue
        module, length = decoder.raw_decode(raw[pos:]); pos += length
        origin = module.get('Replace', module)
        root = Path(origin['Dir']) if origin.get('Dir') else None
        if root is None: raise ValueError('module source unavailable for license inventory')
        files = []
        for path in sorted(root.rglob('*')):
            if not path.is_file() or path.is_symlink(): continue
            if not path.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'AUTHORS')): continue
            relative = path.relative_to(root)
            target = destination/'modules'/module['Path']/module.get('Version', 'local')/relative
            target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(path, target)
            files.append({'path': str(relative), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        if not files and not module.get('Replace'):
            raise ValueError('module license unavailable: '+module['Path'])
        modules.append({k:v for k,v in module.items() if k in {'Path','Version','Sum','GoModSum','Replace'}} | {'licenseFiles':files})
    (destination/'modules.json').write_text(json.dumps(modules, sort_keys=True, indent=2)+'\n')


if __name__ == '__main__': collect(Path(sys.argv[1]))
