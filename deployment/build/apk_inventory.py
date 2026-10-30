"""Inventory the installed APK database without a runtime package manager."""
import json
from pathlib import Path, PurePosixPath
import re


def parse(raw):
    packages, files, names = [], set(), set()
    for block in raw.strip().split('\n\n'):
        fields, directory = {}, None
        for line in block.splitlines():
            if len(line) < 2 or line[1] != ':':
                raise ValueError('malformed APK database')
            key, value = line[0], line[2:]
            if key in ('P', 'V', 'A', 'o'):
                if key in fields:
                    raise ValueError('duplicate APK identity field')
                fields[key] = value
            elif key == 'F':
                directory = PurePosixPath(value)
                if directory.is_absolute() or '..' in directory.parts:
                    raise ValueError('unsafe APK directory')
            elif key == 'R':
                if directory is None or not value or '/' in value or value in ('.', '..'):
                    raise ValueError('unsafe APK file')
                files.add('/'+str(directory/value))
        name, version, arch = (fields.get(k, '') for k in ('P', 'V', 'A'))
        if (not re.fullmatch(r'[a-z0-9][a-z0-9+_.-]*', name) or not version
                or any(c.isspace() for c in version) or arch not in ('x86_64', 'noarch')
                or name in names):
            raise ValueError('invalid or duplicate APK package identity')
        names.add(name)
        packages.append({'name': name, 'version': version, 'architecture': arch,
                         'origin': fields.get('o', name)})
    if not packages or not files:
        raise ValueError('empty APK inventory or file coverage')
    return {'packages': sorted(packages, key=lambda p: p['name']), 'files': sorted(files)}


def read():
    return parse(Path('/usr/lib/apk/db/installed').read_text())


if __name__ == '__main__':
    print(json.dumps(read(), sort_keys=True))
