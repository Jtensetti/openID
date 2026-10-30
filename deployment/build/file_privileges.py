"""Remove unnecessary set-ID file modes in an isolated runtime image build."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


EXCLUDED = ('dev', 'proc', 'sys')
REPORT = Path('/usr/share/doc/openid-python/file-privileges.json')
LIMIT = ('Final image regular files, excluding /dev, /proc and /sys; no symlink traversal. '
         'Directory setgid, file capabilities, mounted data, host privileges and historical layers are separate. '
         'This hardening does not close package advisories or replace no-new-privileges/cap-drop.')


def scan(root):
    """Fail on traversal errors; inspect physical files, not symlink aliases."""
    root = root.resolve(strict=True)
    found, visited = [], 0
    def failed(error):
        raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed):
        if Path(directory) == root:
            dirs[:] = [name for name in dirs if name not in EXCLUDED]
        for name in files:
            path = Path(directory)/name
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                visited += 1
                if info.st_mode & 0o6000:
                    found.append(path)
    return visited, sorted(found)


def file_record(path, root, *, remove=False):
    # O_NONBLOCK prevents an unexpected FIFO from blocking before fstat.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('expected a regular image file')
        mode = stat.S_IMODE(before.st_mode)
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
        after_mode = mode & ~0o6000 if remove else mode
        if remove:
            os.fchmod(stream.fileno(), after_mode)
            if stat.S_IMODE(os.fstat(stream.fileno()).st_mode) != after_mode:
                raise ValueError('file mode change did not persist')
        return {'path': '/'+str(path.relative_to(root)), 'mode': oct(after_mode),
                'previousMode': oct(mode), 'uid': before.st_uid, 'gid': before.st_gid,
                'sha256': digest.hexdigest()}


def apply(root):
    root = root.resolve(strict=True)
    visited, paths = scan(root)
    # Hardlink aliases share a mode; record the first change to each inode.
    changed = [file_record(p, root, remove=True) for p in paths if p.lstat().st_mode & 0o6000]
    _, remaining = scan(root)
    if remaining:
        raise ValueError('setuid/setgid file remains after hardening')
    return {'format': 1, 'helperSHA256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'filesVisited': visited, 'changed': changed, 'remaining': [], 'scope': LIMIT}


def verify(root, report):
    root = root.resolve(strict=True)
    if report['format'] != 1 or report['remaining'] != []:
        raise ValueError('invalid build report')
    if report['helperSHA256'] != hashlib.sha256(Path(__file__).read_bytes()).hexdigest():
        raise ValueError('build and check helper differ')
    visited, remaining = scan(root)
    if remaining:
        raise ValueError('setuid/setgid file exists in final image')
    seen = set()
    for expected in report['changed']:
        relative = Path(expected['path'].removeprefix('/'))
        if relative.is_absolute() or '..' in relative.parts or str(relative) in seen:
            raise ValueError('unsafe or duplicate build report path')
        seen.add(str(relative))
        path = root/relative
        if path.resolve(strict=True) != path:
            raise ValueError('build report path became a symlink')
        actual = file_record(path, root)
        if any(actual[k] != expected[k] for k in ('path', 'mode', 'uid', 'gid', 'sha256')):
            raise ValueError('hardened file differs from build report')
        previous = int(expected['previousMode'], 8)
        if not previous & 0o6000 or int(expected['mode'], 8) != previous & ~0o6000:
            raise ValueError('build report does not describe a set-ID file')
    return {'filesVisited': visited, 'remaining': [], 'buildFilesVerified': len(seen)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('apply', 'check'))
    parser.add_argument('--image-id')
    parser.add_argument('--revision')
    args = parser.parse_args()
    # This tool must never be run against the developer's machine.
    if (sys.platform != 'linux' or os.geteuid() != 0 or
            not Path('/usr/share/doc/openid-python/build-lock.json').is_file() or
            not Path('/app/verification/serve.py').is_file()):
        raise RuntimeError('requires the isolated openID runtime image as root')
    if args.action == 'apply':
        report = apply(Path('/'))
        REPORT.write_text(json.dumps(report, indent=2)+'\n')
        REPORT.chmod(0o644)
        print('PASS: removed setuid/setgid modes from', len(report['changed']), 'image files')
    else:
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', args.image_id or '') or not re.fullmatch(r'[a-f0-9]{40}', args.revision or ''):
            raise ValueError('exact image ID and tested revision required')
        report = json.loads(REPORT.read_bytes())
        result = verify(Path('/'), report)
        result.update({'imageID': args.image_id, 'testedRevision': args.revision,
                       'buildReport': report, 'scope': LIMIT})
        selected = {'CapEff', 'CapBnd', 'NoNewPrivs', 'Seccomp'}
        result['inspectionProcess'] = {'uid': os.getuid(), 'euid': os.geteuid(),
            'status': {line.split(':', 1)[0]: line.split(':', 1)[1].strip()
                       for line in Path('/proc/self/status').read_text().splitlines()
                       if line.split(':', 1)[0] in selected}}
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
