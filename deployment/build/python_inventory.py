"""Inventory the actual runtime using the standard library, without pip."""
import importlib.metadata
import importlib.util
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote


assert sys.version_info[:3] == (3, 12, 16)
for name in ('pip', 'ensurepip'):
    assert importlib.util.find_spec(name) is None, name+' is still importable'
assert not list(Path('/usr/local/bin').glob('pip*')), 'pip launcher remains'
installed = sorted(({'name': d.metadata['Name'], 'version': d.version,
                     'requiresDist': d.requires or []}
                    for d in importlib.metadata.distributions()), key=lambda item: item['name'].lower())
assert installed and all(item['name'].lower() != 'pip' for item in installed)
evidence = Path('/usr/share/doc/openid-python')
lock_bytes = (evidence/'python-wheels.lock.json').read_bytes()
lock = json.loads(lock_bytes)
profile = (evidence/'wheel-profile.txt').read_text().strip()
names = set(lock['profiles'][profile]['packages'])
expected = {w['name']: w['version'] for w in lock['wheels'] if w['name'] in names}
actual = {re.sub('[-_.]+', '-', p['name']).lower(): p['version'] for p in installed}
assert len(actual) == len(installed) and actual == expected, 'installed packages differ from wheel lock'
report_bytes = (evidence/'wheel-installation.json').read_bytes()
report = json.loads(report_bytes)
downloaded = {re.sub('[-_.]+', '-', p['metadata']['name']).lower(): p for p in report['install']}
assert len(downloaded) == len(report['install']) and set(downloaded) == names
for wheel in lock['wheels']:
    if wheel['name'] not in names:
        continue
    item = downloaded[wheel['name']]
    assert item['metadata']['version'] == wheel['version']
    assert unquote(item['download_info']['url']) == 'file:///wheels/'+wheel['filename']
    assert item['download_info']['archive_info']['hashes']['sha256'] == wheel['sha256']
assert not list(Path('/wheels').glob('*.whl')), 'build wheels remain in runtime'
print(json.dumps({'format': 'openid-python-inventory-v1', 'python': sys.version,
                  'installed': installed, 'pipImportable': False, 'ensurepipImportable': False,
                  'wheelProfile': profile, 'wheelLockSHA256': hashlib.sha256(lock_bytes).hexdigest(),
                  'wheelInstallReportSHA256': hashlib.sha256(report_bytes).hexdigest(),
                  'wheelOriginsVerified': True}, indent=2))
