"""Read-only component evidence for OS advisory review; never suppress findings."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys


COMPONENTS = {'mount', 'umount', 'nsenter', 'infocmp', 'systemd-homed',
              'systemd-homework', 'homectl', 'systemd-homed.service', 'getfacl', 'setfacl', 'bzip2recover'}
EPHEMERAL_ROOTS = ('dev', 'proc', 'sys')
LIMITS = [
    'Evidence from one isolated CI probe process, not the deployed service or host.',
    'Known filenames and package manifests do not prove absence of renamed, embedded or dynamically supplied code.',
    'Package file lists describe APK records before documented installer removal; they are not content verification.',
    'Presence is not exploitability; absence in this inventory is not an advisory decision or risk acceptance.',
    'No exploit inputs or privileged utility operations are executed; no scanner finding is removed.',
    'SQLite metadata describes a new in-memory connection in this interpreter; other processes, copied libraries and later-loaded extensions require separate review.',
]


def relevant(path):
    return (path.name in COMPONENTS or path.name.startswith('libacl.so')
            or path.name.startswith('libsqlite3.so')
            or (path.name.startswith('_sqlite3.') and path.suffix == '.so')
            or (path.name == 'Tar.pm' and path.parent.name == 'Archive'))


def sqlite_runtime_evidence():
    """Query the installed engine without opening a user database or loading extensions."""
    report = {'complete': False, 'connection': ':memory:', 'pythonExecutable': sys.executable,
              'errors': [], 'extensionLoadingRequested': False}
    try:
        import sqlite3
        import _sqlite3
        report['wrapperPath'] = str(Path(_sqlite3.__file__).resolve(strict=True))
        with sqlite3.connect(':memory:') as db:
            version, source_id = db.execute('SELECT sqlite_version(), sqlite_source_id()').fetchone()
            if version != sqlite3.sqlite_version or not isinstance(source_id, str) or not source_id:
                raise ValueError('inconsistent SQLite version metadata')
            report.update(version=version, sourceID=source_id)
            for key, query, columns in (
                    ('compileOptions', 'PRAGMA compile_options', ('compile_options',)),
                    ('modules', 'PRAGMA module_list', ('name',)),
                    ('functions', 'PRAGMA function_list', ('name','builtin','type','enc','narg','flags'))):
                cursor = db.execute(query)
                # SQLite silently accepts unknown pragmas: no description/rows
                # must not be interpreted as proof that a feature is absent.
                rows = cursor.fetchmany(2049)
                if (cursor.description is None or tuple(c[0] for c in cursor.description) != columns
                        or (key != 'modules' and not rows) or len(rows) > 2048
                        or any(len(row) != len(columns) for row in rows)):
                    raise ValueError('missing or unbounded SQLite feature metadata')
                report[key] = sorted([dict(zip(columns, row)) for row in rows],
                                     key=lambda row: json.dumps(row, sort_keys=True))
        report['queriesComplete'] = True
        paths = set()
        for line in Path('/proc/self/maps').read_text().splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) == 6 and Path(fields[5]).name.startswith('libsqlite3.so'):
                if fields[5].endswith(' (deleted)'):
                    raise ValueError('mapped SQLite library no longer has a file')
                paths.add(fields[5])
        report['mappedSQLiteLibraries'] = sorted(paths)
        report['complete'] = True
    except Exception as error:
        report['errors'].append(type(error).__name__)
    return report


def within(path, roots):
    return any(path == base or base in path.parents for base in roots)


def file_evidence(path, root, roots, excluded=()):
    info = path.lstat()
    result = {'mode': oct(stat.S_IMODE(info.st_mode)), 'uid': info.st_uid,
              'gid': info.st_gid, 'symlink': path.is_symlink()}
    if path.is_symlink():
        result['target'] = os.readlink(path)
    resolved = path.resolve(strict=True)
    if not within(resolved, roots) or within(resolved, excluded):
        raise ValueError('component target outside inspected roots')
    target = resolved.stat()
    if not stat.S_ISREG(target.st_mode):
        raise ValueError('component is not a regular file')
    result.update({'resolvedPath': '/'+str(resolved.relative_to(root)),
                   'resolvedMode': oct(stat.S_IMODE(target.st_mode)),
                   'resolvedUid': target.st_uid, 'resolvedGid': target.st_gid})
    h = hashlib.sha256()
    with resolved.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    result['sha256'] = h.hexdigest()
    return result


def filesystem_evidence(root, *, whole_image=False):
    """Inspect physical directories without following aliases or hiding omissions."""
    root = root.resolve(strict=True)
    errors, roots, hits = [], [], {}
    excluded = [root/name for name in EPHEMERAL_ROOTS] if whole_image else []
    names = ('',) if whole_image else ('usr', 'lib', 'lib64', 'bin', 'sbin', 'opt', 'app')
    def logical(path):
        return '/' if path == root else '/'+str(path.relative_to(root))
    for name in names:
        path = root/name
        try:
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
            if not resolved.is_dir():
                raise ValueError('code root is not a directory')
            if not within(resolved, roots):
                roots.append(resolved)
        except (OSError, RuntimeError, ValueError) as error:
            errors.append({'path': '/'+name, 'error': type(error).__name__})
    visited = 0
    def failed(error):
        errors.append({'path': str(error.filename), 'error': type(error).__name__})
    for base in roots:
        for directory, dirs, files in os.walk(base, followlinks=False, onerror=failed):
            if whole_image and Path(directory) == root:
                dirs[:] = [name for name in dirs if name not in EPHEMERAL_ROOTS]
                files = [name for name in files if name not in EPHEMERAL_ROOTS]
            for name in dirs:
                path = Path(directory)/name
                if path.is_symlink():
                    try:
                        target = path.resolve(strict=True)
                        if not within(target, roots) or within(target, excluded):
                            errors.append({'path': '/'+str(path.relative_to(root)),
                                           'error': 'directory symlink outside inspected roots'})
                    except (OSError, RuntimeError) as error:
                        errors.append({'path': '/'+str(path.relative_to(root)), 'error': type(error).__name__})
            for name in files:
                visited += 1
                path = Path(directory)/name
                if relevant(path):
                    try:
                        hits['/'+str(path.relative_to(root))] = file_evidence(path, root, roots, excluded)
                    except (OSError, RuntimeError, ValueError) as error:
                        errors.append({'path': '/'+str(path.relative_to(root)), 'error': type(error).__name__,
                                       'reason': str(error) if isinstance(error, ValueError) else None})
    return {'roots': [logical(b) for b in roots],
            'scope': 'physical image paths' if whole_image else 'conventional code roots',
            'excludedRoots': [logical(b) for b in excluded],
            'filesVisited': visited, 'knownComponents': hits, 'errors': errors,
            'completeWithinStatedScope': bool(roots) and not errors}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--whole-image', action='store_true',
                        help='Inspect physical image directories as root; excludes /dev, /proc and /sys.')
    args = parser.parse_args()
    assert re.fullmatch(r'sha256:[a-f0-9]{64}', args.image_id)
    assert re.fullmatch(r'[a-f0-9]{40}', args.revision)
    assert platform.system() == 'Linux'
    if args.whole_image and os.geteuid() != 0:
        raise ValueError('whole-image inspection requires the isolated root inspector')
    report = {'format': 1, 'checkedAt': datetime.now(timezone.utc).isoformat(),
              'imageID': args.image_id, 'testedRevision': args.revision,
              'collectorSHA256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'advisoryDecisions': 'NOT_EVALUATED', 'limits': LIMITS}
    inventory = json.loads(subprocess.check_output([sys.executable,
        '/usr/share/doc/openid-runtime/apk_inventory.py'], text=True, timeout=30))
    report['packages'] = inventory['packages']
    report['packageFilePaths'] = inventory['files']
    report['packageFileNotes'] = ['APK inventory retained, including removed installer paths recorded in pip-removal.json.']
    report['filesystem'] = filesystem_evidence(Path('/'), whole_image=args.whole_image)
    report['sqliteRuntime'] = sqlite_runtime_evidence()
    selected = {'NoNewPrivs', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'Seccomp'}
    report['probeProcess'] = {'uid': os.getuid(), 'euid': os.geteuid(), 'gid': os.getgid(),
        'status': {line.split(':', 1)[0]: line.split(':', 1)[1].strip()
                   for line in Path('/proc/self/status').read_text().splitlines()
                   if line.split(':', 1)[0] in selected}}
    fstab = Path('/etc/fstab')
    if fstab.exists():
        raw = fstab.read_bytes()
        entries = [line for line in raw.decode().splitlines() if line.strip() and not line.lstrip().startswith('#')]
        report['fstab'] = {'sha256': hashlib.sha256(raw).hexdigest(), 'activeEntryCount': len(entries),
                           'xMountEntryCount': sum('X-mount.' in line for line in entries)}
    else:
        report['fstab'] = {'present': False}
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.whole_image and (not report['filesystem']['completeWithinStatedScope']
                            or not report['sqliteRuntime']['complete']):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
