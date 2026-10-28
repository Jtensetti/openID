"""Authenticate and build ncurses against the isolated native Trixie toolchain."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request

sys.path.append(str(Path(__file__).resolve().parent.parent / 'util_linux'))
from bootstrap import fields, sha
from build import check_input, extract_regular, run, verify_signature

ORIGIN = 'https://deb.debian.org/debian/pool/main/n/ncurses/'
PACKAGING_LINKS = {f'debian/lib{width}{name}.symbols': f'lib{name}.symbols'
                   for width in ('32', '64') for name in ('ncurses6', 'ncursesw6', 'tinfo6')}


def load_lock():
    return json.loads(Path(__file__).with_name('candidate.lock.json').read_text())


def fetch_inputs(directory, lock):
    directory.mkdir(parents=True, exist_ok=False)
    names = set()
    for item in lock['inputs']:
        name = item['filename']
        if (PurePosixPath(name).name != name or name in names or item['url'] != ORIGIN + name
                or type(item['bytes']) is not int or not 0 < item['bytes'] < 16 * 1024 * 1024):
            raise ValueError('unexpected ncurses source input')
        names.add(name)
        with urllib.request.urlopen(item['url'], timeout=60) as response:
            raw = response.read(item['bytes'] + 1)
        path = directory / name
        path.write_bytes(raw)
        check_input(path, item)
        print(json.dumps({'input': name, 'bytes': len(raw), 'sha256': sha(raw)}), flush=True)


def check_dsc(text, lock):
    metadata = fields(text)
    if (metadata.get('Source') != 'ncurses' or metadata.get('Version') != lock['packagingVersion']
            or metadata.get('Format') != '3.0 (quilt)'):
        raise ValueError('unexpected ncurses source identity')
    actual = {}
    for line in metadata.get('Checksums-Sha256', '').splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 3:
            raise ValueError('malformed signed checksum')
        digest, size, name = parts
        if (name in actual or PurePosixPath(name).name != name
                or not re.fullmatch(r'[a-f0-9]{64}', digest) or not size.isdecimal()):
            raise ValueError('ambiguous signed checksum')
        actual[name] = (int(size), digest)
    expected = {p['filename']: (p['bytes'], p['sha256']) for p in lock['inputs']
                if not p['filename'].endswith('.dsc')}
    if actual != expected:
        raise ValueError('signed source group differs from reviewed inputs')


def check_key(listing, expected):
    rows = [line.split(':') for line in listing.splitlines()]
    if any(row[0] in ('sec', 'ssb') for row in rows):
        raise ValueError('private source verification key')
    found = []
    for i, row in enumerate(rows):
        if row[0] == 'pub':
            if (i + 1 == len(rows) or rows[i + 1][0] != 'fpr' or len(rows[i + 1]) < 10
                    or not re.fullmatch(r'[A-F0-9]{40}', rows[i + 1][9])):
                raise ValueError('missing full primary fingerprint')
            found.append(rows[i + 1][9])
    if found != [expected]:
        raise ValueError('unexpected upstream key set')


def extract_packaging(archive, destination):
    """Permit only the six signed Debian symbol aliases within this package."""
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive) as source:
        members = source.getmembers()
        names, links = set(), set()
        if not members or len(members) > 1000 or sum(m.size for m in members) > 8 * 1024 * 1024:
            raise ValueError('unexpected ncurses packaging archive extent')
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or '..' in path.parts or not path.parts
                    or path.parts[0] != 'debian' or str(path) in names or member.size < 0):
                raise ValueError('unsafe ncurses packaging member')
            names.add(str(path))
            if member.issym():
                if PACKAGING_LINKS.get(str(path)) != member.linkname:
                    raise ValueError('unexpected ncurses packaging link')
                links.add(str(path))
            elif not (member.isfile() or member.isdir()):
                raise ValueError('unexpected ncurses packaging file type')
        if links != set(PACKAGING_LINKS):
            raise ValueError('missing ncurses packaging symbol alias')
        for member in members:
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as stream:
                    target.write_bytes(stream.read())
                target.chmod(member.mode & 0o777)
    packaging = destination / 'debian'
    for name, linkname in PACKAGING_LINKS.items():
        link = destination / name
        target = (link.parent / linkname).resolve(strict=True)
        if target.parent != packaging.resolve(strict=True) or not target.is_file():
            raise ValueError('ncurses packaging link target differs')
        link.symlink_to(linkname)
    return packaging


def prepare(inputs, work, evidence, lock, keyring):
    for item in lock['inputs']:
        check_input(inputs / item['filename'], item)
    if sha(keyring.read_bytes()) != lock['debianKeyringSHA256']:
        raise ValueError('Debian maintainer keyring differs from authenticated snapshot')
    home = work / 'gnupg'
    home.mkdir(mode=0o700)
    prefix = 'ncurses_' + lock['packagingVersion']
    dsc = inputs / (prefix + '.dsc')
    debian = verify_signature(dsc, None, keyring, home, evidence / 'debian-signature.log', lock['debianSigner'])
    check_dsc(dsc.read_text(), lock)
    packaging = extract_packaging(inputs / (prefix + '.debian.tar.xz'), work / 'packaging')
    key = packaging / 'upstream/signing-key.asc'
    if sha(key.read_bytes()) != lock['upstreamKeySHA256']:
        raise ValueError('authenticated upstream key differs')
    run(['gpg', '--batch', '--no-options', '--homedir', str(home), '--with-colons',
         '--with-fingerprint', '--show-keys', str(key)], evidence / 'upstream-key.log')
    check_key((evidence / 'upstream-key.log').read_text(), lock['upstreamSigner'])
    ring = home / 'upstream.gpg'
    run(['gpg', '--batch', '--no-options', '--homedir', str(home), '--dearmor',
         '--output', str(ring), str(key)], evidence / 'upstream-key-import.log')
    archive = inputs / ('ncurses_' + lock['sourceVersion'] + '.orig.tar.gz')
    upstream = verify_signature(Path(str(archive) + '.asc'), archive, ring, home,
                                evidence / 'upstream-signature.log', lock['upstreamSigner'])
    source = extract_regular(archive, work / 'source', lock['sourceDirectory'])
    shutil.copytree(packaging, source / 'debian', symlinks=True)
    for name, expected in {**lock['packagingFiles'], **lock['licenseFiles']}.items():
        if sha((source / name).read_bytes()) != expected:
            raise ValueError('reviewed source or packaging differs: ' + name)
    for name in lock['licenseFiles']:
        target = evidence / 'licenses' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    changelog = source / 'debian/changelog'
    changelog.write_text('ncurses (' + lock['candidateVersion'] + ') UNRELEASED; urgency=medium\n\n'
                        '  * openID native amd64 evaluation with the Debian nobiarch profile.\n'
                        '  * Preserve upstream code, Debian patches and native/example builds.\n'
                        '  * Not an official Debian update or production-approved build.\n\n'
                        ' -- openID candidate automation <noreply@example.invalid>  '
                        'Wed, 28 Oct 2026 00:00:00 +0000\n\n' + changelog.read_text())
    return source, {'debianSigner': debian, 'upstreamSigner': upstream}


def check_packages(packages, lock):
    required = lock['requiredPackages']
    debug = {n + '-dbgsym': 'amd64' for n in ('libtinfo6', 'libncurses6', 'libncursesw6',
                                             'ncurses-bin', 'ncurses-examples')}
    allowed = dict(required, **debug)
    names, filenames = set(), set()
    for p in packages:
        name, version = p['Package'], p['Version']
        if (name not in allowed or name in names or p['filename'] in filenames
                or version != lock['candidateVersion'] or p['Architecture'] != allowed[name]
                or p.get('Source', name) not in ('ncurses', 'ncurses (' + version + ')')
                or p['filename'] != name + '_' + version + '_' + allowed[name] + '.deb'
                or type(p['bytes']) is not int or p['bytes'] <= 0
                or not re.fullmatch(r'[a-f0-9]{64}', p['sha256'])):
            raise ValueError('unexpected or duplicate ncurses package identity')
        names.add(name)
        filenames.add(p['filename'])
    if not set(required) <= names:
        raise ValueError('native/independent ncurses package group is incomplete')
    return [p for p in packages if p['Package'] in lock['runtimePackages']]


def build(inputs, output, lock):
    if (platform.system() != 'Linux' or platform.machine() != 'x86_64' or os.geteuid() == 0
            or os.environ.get('OPENID_NCURSES_CANDIDATE_BUILD') != '1'):
        raise ValueError('requires the unprivileged isolated Linux amd64 ncurses builder')
    if lock['buildProfiles'] != ['nobiarch']:
        raise ValueError('native/example builds must remain enabled')
    inputs, output = inputs.resolve(strict=True), output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    work, evidence = output / 'work', output / 'evidence'
    work.mkdir()
    evidence.mkdir()
    source = None
    report = {'format': 1, 'complete': False, 'passed': False, 'runtimeInstalled': False,
              'candidateVersion': lock['candidateVersion'], 'limits': lock['limits']}
    try:
        shutil.copytree('/toolchain-evidence', evidence / 'toolchain')
        shutil.copytree('/builder', evidence / 'build-inputs', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        (evidence / 'candidate.lock.json').write_text(json.dumps(lock, indent=2) + '\n')
        for name in ('libgpm2', 'libgpm-dev', 'autoconf-dickey'):
            target = evidence / 'licenses/build-dependencies' / name
            target.mkdir(parents=True)
            shutil.copyfile(Path('/usr/share/doc') / name / 'copyright', target / 'copyright')
        run([sys.executable, '/builder/test_signature_policy.py'], evidence / 'signature-policy.log')
        source, report['source'] = prepare(inputs, work, evidence, lock,
                                          Path('/usr/share/keyrings') / lock['debianKeyringFile'])
        env = {'PATH': os.environ['PATH'], 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
               'SOURCE_DATE_EPOCH': str(lock['sourceDateEpoch']), 'DEB_BUILD_OPTIONS': 'parallel=2',
               'DEB_BUILD_PROFILES': 'nobiarch'}
        run(['dpkg-source', '--before-build', '.'], evidence / 'patches.log', cwd=source, env=env)

        def normalize(info):
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mtime = lock['sourceDateEpoch']
            return info

        with tarfile.open(evidence / 'prepared-source.tar.xz', 'w:xz') as archive:
            archive.add(source, arcname='ncurses-candidate', filter=normalize)
        run(['dpkg-checkbuilddeps', '-P', 'nobiarch'], evidence / 'build-dependencies.log', cwd=source, env=env)
        run(['dpkg-buildpackage', '--build=binary', '--no-sign', '--jobs=2', '-P', 'nobiarch'],
            evidence / 'package-build.log', cwd=source, env=env)
        packages = []
        for path in sorted(source.parent.glob('*.deb')):
            p = fields(subprocess.check_output(['dpkg-deb', '-f', str(path), 'Package', 'Version',
                'Architecture', 'Source', 'Depends', 'Pre-Depends'], text=True))
            p.update(filename=path.name, bytes=path.stat().st_size, sha256=sha(path.read_bytes()))
            packages.append(p)
        exported = check_packages(packages, lock)
        report['packages'] = packages
        report['exportedPackages'] = sorted(p['Package'] for p in exported)
        for p in exported:
            target = evidence / 'candidate-packages' / p['filename']
            target.parent.mkdir(exist_ok=True)
            shutil.copyfile(source.parent / p['filename'], target)
        for pattern in ('*.buildinfo', '*.changes'):
            for path in source.parent.glob(pattern):
                shutil.copyfile(path, evidence / path.name)
        from inventory import sbom
        (evidence / 'sbom.cdx.json').write_text(json.dumps(sbom(lock, packages,
            (evidence / 'toolchain/installed-packages.tsv').read_text()), indent=2) + '\n')
        from compatibility import probe
        report['compatibility'] = probe(source.parent, packages, work / 'compatibility', evidence, env, lock)
        report['upstreamRuntimeSuite'] = 'No complete automated runtime suite is claimed; Debian builds examples but does not execute the CVE regressions.'
        report['complete'] = report['passed'] = True
    except Exception as error:
        report['errorType'] = type(error).__name__
        if isinstance(error, ValueError):
            report['error'] = str(error)
        raise
    finally:
        if source is not None:
            for path in source.glob('obj*/config.log'):
                target = evidence / 'configuration' / path.relative_to(source)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
        report['files'] = {str(p.relative_to(evidence)): sha(p.read_bytes())
                           for p in sorted(evidence.rglob('*')) if p.is_file()}
        (evidence / 'assessment.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'complete': report['complete'], 'passed': report['passed'], 'runtimeInstalled': False}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    fetch = commands.add_parser('fetch')
    fetch.add_argument('--directory', type=Path, required=True)
    compile_command = commands.add_parser('build')
    compile_command.add_argument('--inputs', type=Path, required=True)
    compile_command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'fetch':
        fetch_inputs(args.directory, load_lock())
    else:
        build(args.inputs, args.output, load_lock())
