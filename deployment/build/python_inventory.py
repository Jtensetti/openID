"""Inventory the actual runtime using the standard library, without pip."""
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import sys


assert sys.version_info[:3] == (3, 12, 16)
for name in ('pip', 'ensurepip'):
    assert importlib.util.find_spec(name) is None, name+' is still importable'
assert not list(Path('/usr/local/bin').glob('pip*')), 'pip launcher remains'
installed = sorted(({'name': d.metadata['Name'], 'version': d.version,
                     'requiresDist': d.requires or []}
                    for d in importlib.metadata.distributions()), key=lambda item: item['name'].lower())
assert installed and all(item['name'].lower() != 'pip' for item in installed)
print(json.dumps({'format': 'openid-python-inventory-v1', 'python': sys.version,
                  'installed': installed, 'pipImportable': False, 'ensurepipImportable': False}, indent=2))
