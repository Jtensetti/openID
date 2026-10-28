"""Probe the new ACL library and existing tar using generated files only."""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

from bootstrap import sha


def probe(package_directory, packages, directory, evidence, build_env):
    if os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError('compatibility checks require the ordinary builder user')
    directory.mkdir()
    env = dict(build_env, DEB_BUILD_MAINT_OPTIONS='hardening=+all')
    log = evidence / 'compatibility.log'

    def command(args, cwd=None, expected=0, rejection=None):
        result = subprocess.run([str(a) for a in args], cwd=cwd, env=env, capture_output=True,
                                text=True, timeout=30)
        with log.open('a') as output:
            output.write(json.dumps({'argv': [str(a) for a in args], 'exit': result.returncode})
                         + '\n' + result.stdout + result.stderr)
        if result.returncode != expected or (rejection is not None and rejection not in result.stderr):
            raise ValueError('unexpected compatibility command outcome: ' + str(args[0]))
        return result.stdout

    # Extract the exact exportable debs as an ordinary user. This neither
    # installs packages nor runs maintainer scripts. Probe the stripped ELF
    # shipped in libacl1, rather than a different unstripped build-tree copy.
    root = directory / 'packages'
    root.mkdir()
    for package in packages:
        path = package_directory / package['filename']
        if path.is_symlink() or sha(path.read_bytes()) != package['sha256']:
            raise ValueError('built package changed before compatibility probe')
        command(['dpkg-deb', '--extract', path, root])
    libraries = root / 'usr/lib/x86_64-linux-gnu'
    library = (libraries / 'libacl.so.1').resolve(strict=True)
    if library.parent != libraries.resolve() or not library.is_file():
        raise ValueError('candidate library resolves outside extracted package directory')
    env['LD_LIBRARY_PATH'] = str(libraries)
    tar_version = command(['dpkg-query', '-W', '-f=${Version}', 'tar']).strip()
    if tar_version != '1.35+dfsg-3.1':
        raise ValueError('tar version differs from the application-image compatibility target')
    linkage = command(['ldd', '/usr/bin/tar'])
    matches = re.findall(r'^\s*libacl\.so\.1 => (\S+) \(', linkage, re.M)
    if len(matches) != 1 or Path(matches[0]).resolve(strict=True) != library:
        raise ValueError('tar did not resolve the newly built ACL library')
    original, restored = directory / 'original', directory / 'restored'
    original.mkdir()
    restored.mkdir()
    payload = original / 'payload'
    payload.write_bytes(b'generated openID ACL compatibility fixture\n')
    (original / 'directory').mkdir()
    (original / 'link').symlink_to('payload')
    command([root / 'usr/bin/setfacl', '-m', 'u:12345:r--', payload])
    command([root / 'usr/bin/setfacl', '-m', 'd:u:12345:r-x', original / 'directory'])

    def acl(path):
        return command([root / 'usr/bin/getfacl', '-cpn', path])

    before = {name: acl(original / name) for name in ('payload', 'directory')}
    cpp_flags = shlex.split(command(['dpkg-buildflags', '--get', 'CPPFLAGS']))
    compiler_flags = shlex.split(command(['dpkg-buildflags', '--get', 'CFLAGS']))
    linker_flags = shlex.split(command(['dpkg-buildflags', '--get', 'LDFLAGS']))
    executable = directory / 'acl-api-probe'
    command(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', *cpp_flags, *compiler_flags,
             '-I' + str(root / 'usr/include'), Path(__file__).with_name('api_probe.c'),
             '-L' + str(libraries), '-Wl,-rpath,' + str(libraries),
             *linker_flags, '-lacl', '-o', executable])
    api = json.loads(command([executable, original]))
    if len(api) != 6 or any(value is not True for value in api.values()):
        raise ValueError('incomplete ACL API regression')
    if {name: acl(original / name) for name in before} != before:
        raise ValueError('no-follow probe changed the target ACL')
    physical = directory / 'physical.acl'
    physical.write_text(command([root / 'usr/bin/getfacl', '-pn', payload]))
    command([root / 'usr/bin/setfacl', '-P', '--restore=' + str(physical)])
    through_link = directory / 'through-link.acl'
    through_link.write_text('# file: link\nuser::rw-\nuser:12346:r--\ngroup::r--\nmask::r--\nother::---\n')
    command([root / 'usr/bin/setfacl', '-P', '--restore=' + str(through_link)], cwd=original,
            expected=1, rejection='link: Too many levels of symbolic links')
    if {name: acl(original / name) for name in before} != before:
        raise ValueError('physical restore through symlink changed the target ACL')
    archive = directory / 'generated.tar'
    command(['/usr/bin/tar', '--acls', '--numeric-owner', '-C', original,
             '-cf', archive, 'payload', 'directory', 'link'])
    command(['/usr/bin/tar', '--acls', '--no-same-owner', '-C', restored, '-xf', archive])
    after = {name: acl(restored / name) for name in before}
    if before != after or (restored / 'payload').read_bytes() != payload.read_bytes():
        raise ValueError('tar failed to preserve generated content or ACLs with the new library')
    if not (restored / 'link').is_symlink() or os.readlink(restored / 'link') != 'payload':
        raise ValueError('tar changed the generated symlink')
    result = {'passed': True, 'uid': os.getuid(), 'euid': os.geteuid(),
              'librarySHA256': sha(library.read_bytes()), 'libraryPath': str(library),
              'probedPackages': {p['filename']: p['sha256'] for p in packages},
              'tarVersion': tar_version, 'tarSHA256': sha(Path('/usr/bin/tar').read_bytes()),
              'tarResolvesCandidateLibrary': True, 'apiChecks': api,
              'physicalRestoreRejectsSymlinkWithoutTargetChange': True,
              'accessAndDefaultACLsPreserved': True, 'contentAndSymlinkPreserved': True,
              'limits': ['Generated ordinary-user cases only; not a concurrent race, root, NFS or full ABI test.',
                         'Existing tar binary compatibility does not establish that tar can be rebuilt with the new headers.',
                         'Application-image installation, package transitions and full application/protocol tests remain required.']}
    (evidence / 'compatibility.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
