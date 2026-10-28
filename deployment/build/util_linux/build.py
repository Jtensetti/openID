"""Authenticate, prepare and build the complete util-linux package candidate."""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import urllib.parse

from bootstrap import fields, sha


RUNTIME_PACKAGES = {'bsdutils', 'libblkid1', 'liblastlog2-2', 'libmount1',
                    'libsmartcols1', 'libuuid1', 'login', 'mount', 'util-linux'}
UPSTREAM_KEY_URL = ('https://keyserver.ubuntu.com/pks/lookup?op=get&search='
                    '0xB0C64D14301CC6EFAEDF60E4E4B71D5EEC39C284')
UPSTREAM_KEY_FILE = Path(__file__).with_name('upstream-signing-key-refreshed.asc')


def validate_packages(packages, version):
    """Check the whole build before exporting any installable package."""
    names, filenames, runtime = set(), set(), []
    for item in packages:
        name = item['Package']
        base = name.removesuffix('-dbgsym')
        # Debian's reviewed debputy.manifest preserves these historical epochs.
        prefix = {'bsdutils': '1:', 'login': '1:4.16.0-2+really'}.get(base, '')
        expected_version = prefix + version
        source = item.get('Source', name)
        architecture = item['Architecture']
        filename = name + '_' + expected_version.split(':')[-1] + '_' + architecture + '.deb'
        if (not re.fullmatch(r'[a-z0-9][a-z0-9+.-]+', name)
                or name in names or item['filename'] in filenames
                or item['Version'] != expected_version
                or source not in ('util-linux', 'util-linux (' + version + ')')
                or architecture not in ('amd64', 'all')
                or item['filename'] != filename
                or type(item['bytes']) is not int or item['bytes'] <= 0
                or not re.fullmatch(r'[a-f0-9]{64}', item['sha256'])):
            raise ValueError('unexpected or duplicate built package identity')
        names.add(name)
        filenames.add(item['filename'])
        if name in RUNTIME_PACKAGES:
            if architecture != 'amd64':
                raise ValueError('runtime package architecture differs')
            runtime.append(item)
    if {item['Package'] for item in runtime} != RUNTIME_PACKAGES:
        raise ValueError('incomplete runtime package set')
    return runtime


def load_lock():
    return json.loads(Path(__file__).with_name('candidate.lock.json').read_text())


def check_input(path, item):
    if path.is_symlink() or not path.is_file():
        raise ValueError('missing or linked candidate input')
    size, digest = path.stat().st_size, sha(path.read_bytes())
    if size != item['bytes'] or digest != item['sha256']:
        raise ValueError('candidate input checksum mismatch: ' + item['filename']
                         + '; expected bytes=' + str(item['bytes']) + ' sha256=' + item['sha256']
                         + '; actual bytes=' + str(size) + ' sha256=' + digest)


def fetch_inputs(directory, lock):
    directory.mkdir(parents=True, exist_ok=False)
    for item in lock['inputs']:
        url = item['url']
        if url != UPSTREAM_KEY_URL and not url.startswith(('https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/',
                               'https://deb.debian.org/debian/pool/main/u/util-linux/',
                               'https://github.com/util-linux/util-linux/compare/')):
            raise ValueError('unexpected candidate input origin')
        name = item['filename']
        if PurePosixPath(name).name != name:
            raise ValueError('input name must be a basename')
        if url == UPSTREAM_KEY_URL:
            # Reviewed public bytes, not a new trust anchor. prepare() still
            # binds the primary key to signed Debian packaging and verifies
            # the actual upstream signature. Never fall back to a live key.
            if name != UPSTREAM_KEY_FILE.name:
                raise ValueError('unexpected versioned public key name')
            check_input(UPSTREAM_KEY_FILE, item)
            raw = UPSTREAM_KEY_FILE.read_bytes()
        else:
            with urllib.request.urlopen(url, timeout=90) as response:
                raw = response.read(item['bytes'] + 1)
        path = directory / name
        path.write_bytes(raw)
        check_input(path, item)
        print(json.dumps({'input': name, 'bytes': len(raw), 'sha256': sha(raw),
                          'retrieval': 'repository' if url == UPSTREAM_KEY_URL else 'https'}),
              flush=True)


def extract_regular(archive, destination, prefix):
    """These reviewed archives contain no links; reject new path/file types."""
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive) as source:
        members = source.getmembers()
        names = set()
        if not members or len(members) > 10000 or sum(m.size for m in members) > 128 * 1024 * 1024:
            raise ValueError('unexpected archive extent')
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or '..' in path.parts or not path.parts
                    or path.parts[0] != prefix or str(path) in names or member.size < 0
                    or not (member.isfile() or member.isdir())):
                raise ValueError('unsafe archive member')
            names.add(str(path))
        for member in members:
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as stream:
                    target.write_bytes(stream.read())
                target.chmod(member.mode & 0o777)
    return destination / prefix


def valid_signature(status, expected_signer=None):
    """Parse only GnuPG's ASCII machine fields; user IDs may have other bytes."""
    if isinstance(status, str):
        status = status.encode('utf-8')
    lines = []
    for line in status.splitlines():
        if not line.startswith(b'[GNUPG:]'):
            continue
        fields = line.split()
        if (len(fields) < 2 or fields[0] != b'[GNUPG:]'
                or not re.fullmatch(rb'[A-Z0-9_]+', fields[1])):
            raise ValueError('malformed GnuPG status')
        if fields[1] == b'VALIDSIG':
            if len(fields) < 3 or not re.fullmatch(rb'(?:[A-F0-9]{40}|[A-F0-9]{64})', fields[2]):
                raise ValueError('malformed GnuPG signature fingerprint')
            lines.append((fields[1], fields[2]))
        else:
            lines.append((fields[1],))
    forbidden = {b'BADSIG', b'ERRSIG', b'EXPSIG', b'EXPKEYSIG', b'REVKEYSIG', b'KEYEXPIRED',
                 b'SIGEXPIRED', b'KEYREVOKED', b'NO_PUBKEY', b'FAILURE'}
    if any(line[0] in forbidden for line in lines):
        raise ValueError('rejected source signature')
    valid = [line for line in lines if line[0] == b'VALIDSIG']
    if len(valid) != 1:
        raise ValueError('missing unambiguous source signature')
    signer = valid[0][1].decode('ascii')
    if expected_signer is not None and signer != expected_signer:
        raise ValueError('source signature uses an unexpected signing key')
    return signer


def primary_fingerprint(listing):
    """Read GnuPG's machine format, never infer trust from a name or key ID."""
    rows = [line.split(':') for line in listing.splitlines()]
    primary = [i for i, row in enumerate(rows) if row[0] == 'pub']
    if len(primary) != 1 or any(row[0] in ('sec', 'ssb') for row in rows):
        raise ValueError('expected one public primary key')
    following = rows[primary[0] + 1:primary[0] + 2]
    if (not following or len(following[0]) < 10 or following[0][0] != 'fpr'
            or not re.fullmatch(r'(?:[A-F0-9]{40}|[A-F0-9]{64})', following[0][9])):
        raise ValueError('missing full primary fingerprint')
    return following[0][9]


def validate_key_refresh(original, refreshed, expected):
    # The original key is bound by Debian's authenticated packaging. The
    # keyserver distributes updated self-signatures; it supplies no new trust.
    if primary_fingerprint(original) != expected or primary_fingerprint(refreshed) != expected:
        raise ValueError('key refresh changes the trusted primary key')


def run(command, log, cwd=None, env=None):
    with log.open('w') as stream:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=stream,
                                stderr=subprocess.STDOUT, timeout=1200)
    if result.returncode:
        print(log.read_text(errors='replace')[-20000:], flush=True)
        result.check_returncode()


def verify_signature(signature, content, keyring, home, log, expected_signer=None):
    command = ['gpgv', '--homedir', str(home), '--status-fd=1', '--keyring', str(keyring), str(signature)]
    if content is not None:
        command.append(str(content))
    # Only stdout carries --status-fd=1. A key's arbitrary user ID can also
    # appear on stderr; never parse that human-facing channel as status.
    status_log = log.with_name(log.stem + '-status.log')
    with status_log.open('wb') as machine, log.open('wb') as diagnostic:
        result = subprocess.run(command, stdout=machine, stderr=diagnostic, timeout=1200)
    status = status_log.read_bytes()
    with log.open('ab') as diagnostic:
        diagnostic.write(status)
    if result.returncode:
        print(log.read_text(errors='replace')[-20000:], flush=True)
        result.check_returncode()
    return valid_signature(status, expected_signer)


def source_bundle(source, path, epoch):
    def normalize(info):
        info.uid = info.gid = 0
        info.uname = info.gname = ''
        info.mtime = epoch
        return info
    with tarfile.open(path, 'w:xz') as archive:
        archive.add(source, arcname='util-linux-candidate', filter=normalize)


def sbom(lock, packages, toolchain):
    components = []
    for item in lock['inputs']:
        components.append({'type': 'file', 'bom-ref': 'input:' + item['filename'],
                           'name': item['filename'], 'hashes': [{'alg': 'SHA-256', 'content': item['sha256']}],
                           'externalReferences': [{'type': 'distribution', 'url': item['url']}]})
    for item in packages:
        components.append({'type': 'library', 'bom-ref': 'built:' + item['Package'],
                           'name': item['Package'], 'version': item['Version'],
                           'hashes': [{'alg': 'SHA-256', 'content': item['sha256']}],
                           'licenses': [{'license': {'name': 'See preserved Debian copyright and per-file notices'}}],
                           'properties': [{'name': 'openid:origin', 'value': 'Local evaluation build, not an official Debian binary'},
                                          {'name': 'openid:artifact-exported', 'value': str(item['Package'] in RUNTIME_PACKAGES).lower()}]})
    for line in toolchain.splitlines():
        name, version, architecture, state = line.split('\t')
        if state != 'installed':
            raise ValueError('incomplete toolchain inventory')
        components.append({'type': 'library', 'bom-ref': 'toolchain:' + name + ':' + architecture,
                           'name': name, 'version': version,
                           'purl': 'pkg:deb/debian/' + name + '@' + urllib.parse.quote(version, safe='')
                                   + '?arch=' + architecture,
                           'properties': [{'name': 'openid:scope', 'value': 'Builder package; not installed in the application image by this change'}]})
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'component': {'type': 'application', 'bom-ref': 'candidate:util-linux',
                                      'name': 'openid-util-linux-package-evaluation', 'version': lock['candidateVersion']},
                         'properties': [{'name': 'openid:scope', 'value':
                             'Source inputs, produced Debian packages and builder dpkg inventory only. '
                             'Not an application SBOM, complete embedded-library inventory or advisory decision.'}]},
            'components': components}


def prepare(inputs, work, evidence, lock):
    for item in lock['inputs']:
        check_input(inputs / item['filename'], item)
    home = work / 'gnupg'
    home.mkdir(mode=0o700)
    packaging_name = 'util-linux_' + lock['packagingVersion'] + '.debian.tar.xz'
    dsc = inputs / ('util-linux_' + lock['packagingVersion'] + '.dsc')
    debian_signer = verify_signature(dsc, None, Path('/usr/share/keyrings/debian-keyring.gpg'),
                                     home, evidence / 'debian-signature.log')
    checksums = fields(dsc.read_text())['Checksums-Sha256'].splitlines()
    expected = [line.split() for line in checksums if line.strip()]
    if [sha((inputs / packaging_name).read_bytes()), str((inputs / packaging_name).stat().st_size),
            packaging_name] not in expected:
        raise ValueError('Debian signature does not bind packaging bytes')
    packaging = extract_regular(inputs / packaging_name, work / 'packaging', 'debian')
    key = packaging / 'upstream/signing-key.asc'
    if sha(key.read_bytes()) != lock['upstreamKeySHA256']:
        raise ValueError('upstream signing key differs')
    refreshed = inputs / 'upstream-signing-key-refreshed.asc'
    shutil.copyfile(refreshed, evidence / refreshed.name)
    for label, path in [('packaging', key), ('refreshed', refreshed)]:
        run(['gpg', '--batch', '--no-options', '--homedir', str(home),
             '--with-colons', '--with-fingerprint', '--show-keys', str(path)],
            evidence / ('upstream-key-' + label + '.log'))
    validate_key_refresh((evidence / 'upstream-key-packaging.log').read_text(),
                         (evidence / 'upstream-key-refreshed.log').read_text(),
                         lock['upstreamPrimaryFingerprint'])
    keyring = home / 'upstream.gpg'
    run(['gpg', '--batch', '--no-options', '--homedir', str(home), '--dearmor',
         '--output', str(keyring), str(refreshed)], evidence / 'upstream-key-import.log')
    source_name = 'util-linux-' + lock['sourceVersion']
    uncompressed = work / 'upstream.tar'
    uncompressed.write_bytes(lzma.decompress((inputs / (source_name + '.tar.xz')).read_bytes()))
    upstream_signer = verify_signature(inputs / (source_name + '.tar.sign'), uncompressed,
                                      keyring, home, evidence / 'upstream-signature.log',
                                      expected_signer=lock['upstreamPrimaryFingerprint'])
    source = extract_regular(uncompressed, work / 'source', source_name)
    shutil.copytree(packaging, source / 'debian')
    for relative, expected_hash in lock['licenseFiles'].items():
        original = source / relative
        if sha(original.read_bytes()) != expected_hash:
            raise ValueError('license text differs: ' + relative)
        target = evidence / 'licenses' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
    series = (source / 'debian/patches/series').read_text().splitlines()
    if series != [p['patch'] for p in lock['debianPatches']]:
        raise ValueError('Debian patch series differs')
    for item in lock['debianPatches']:
        patch = source / 'debian/patches' / item['patch']
        if sha(patch.read_bytes()) != item['sha256']:
            raise ValueError('Debian patch differs')
        if item['patch'] in lock['alreadyUpstreamPatches']:
            subprocess.run(['git', 'apply', '--reverse', '--check', str(patch)], cwd=source, check=True)
    removed = set(lock['alreadyUpstreamPatches'] + [lock['removeKnownFailurePatch']])
    series = [name for name in series if name not in removed]
    followup = source / 'debian/patches/openid/stable-followup.patch'
    followup.parent.mkdir()
    followup.write_text('Description: Pinned upstream stable/v2.41 follow-up for evaluation\n'
                       'Origin: upstream, ' + lock['stableCommit'] + '\n'
                       'Forwarded: not-needed\n\n' + (inputs / 'stable-post-2.41.6.diff').read_text())
    series.append('openid/stable-followup.patch')
    (source / 'debian/patches/series').write_text('\n'.join(series) + '\n')
    changelog = source / 'debian/changelog'
    changelog.write_text('util-linux (' + lock['candidateVersion'] + ') UNRELEASED; urgency=medium\n\n'
                         '  * Local openID evaluation: upstream 2.41.6 and pinned stable follow-up.\n'
                         '  * Preserve Debian packaging; omit already-upstream patches.\n'
                         '  * Restore hardlink test failures; enable all Debian hardening options.\n'
                         '  * Not an official Debian update or production-approved build.\n\n'
                         ' -- openID candidate automation <noreply@example.invalid>  '
                         'Tue, 27 Oct 2026 00:00:00 +0000\n\n' + changelog.read_text())
    rules = source / 'debian/rules'
    old = 'export DEB_BUILD_MAINT_OPTIONS = hardening=+bindnow'
    if rules.read_text().count(old) != 1:
        raise ValueError('unexpected Debian hardening definition')
    rules.write_text(rules.read_text().replace(old,
        '# openID candidate packaging change, 2026-10-27: all Debian hardening.\n'
        'export DEB_BUILD_MAINT_OPTIONS = hardening=+all'))
    run(['dpkg-source', '--before-build', '.'], evidence / 'patches.log', cwd=source)
    for relative, expected_hash in lock['stableFiles'].items():
        if sha((source / relative).read_bytes()) != expected_hash:
            raise ValueError('prepared file differs from pinned upstream: ' + relative)
    if 'TS_KNOWN_FAIL="yes"' in (source / 'tests/ts/hardlink/options').read_text():
        raise ValueError('hardlink test failure still masked')
    source_bundle(source, evidence / 'prepared-source.tar.xz', lock['sourceDateEpoch'])
    return source, {'debianSigner': debian_signer, 'upstreamSigner': upstream_signer,
                    'appliedPatchSeries': series, 'removedAlreadyUpstream': lock['alreadyUpstreamPatches'],
                    'removedKnownFailureMask': lock['removeKnownFailurePatch'],
                    'stableFilesVerified': len(lock['stableFiles']), 'licensesVerified': len(lock['licenseFiles'])}


def build(inputs, output, lock):
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or os.geteuid() == 0:
        raise ValueError('requires the unprivileged isolated Linux amd64 builder')
    output.mkdir(parents=True, exist_ok=True)
    work = output / 'work'
    evidence = output / 'evidence'
    work.mkdir()
    evidence.mkdir()
    report = {'format': 1, 'complete': False, 'passed': False, 'candidateVersion': lock['candidateVersion'],
              'runtimeInstalled': False, 'limits': lock['limits']}
    try:
        shutil.copytree('/toolchain-evidence', evidence / 'toolchain')
        (evidence / 'candidate.lock.json').write_text(json.dumps(lock, indent=2) + '\n')
        # Exercise actual key/signature status handling with this locked Linux
        # verifier before trusting source inputs. These fixtures contain no
        # private keys and do not enter either source-verification keyring.
        run([sys.executable, str(Path(__file__).with_name('test_signature_policy.py'))],
            evidence / 'signature-policy.log')
        report['signaturePolicyRegressionPassed'] = True
        source, report['source'] = prepare(inputs, work, evidence, lock)
        env = {'PATH': os.environ['PATH'], 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
               'SOURCE_DATE_EPOCH': str(lock['sourceDateEpoch']), 'DEB_BUILD_OPTIONS': 'parallel=2'}
        run(['dpkg-checkbuilddeps'], evidence / 'build-dependencies.log', cwd=source, env=env)
        run(['dpkg-buildpackage', '--build=binary', '--no-sign', '--jobs=2'],
            evidence / 'package-build.log', cwd=source, env=env)
        log = (evidence / 'package-build.log').read_text(errors='replace')
        suites = re.findall(r'All (\d+) tests PASSED', log)
        if not suites or max(map(int, suites)) < 100 or 'Ignore util-linux test suite' in log:
            raise ValueError('upstream regression execution not established')
        report['regression'] = {'suiteEntries': list(map(int, suites)),
                                'skipLines': [line for line in log.splitlines() if re.search(r'\bSKIP(?:PED)?\b', line, re.I)],
                                'limit': 'Upstream PASS totals can include skips; raw logs remain authoritative.'}
        packages = []
        for path in sorted(source.parent.glob('*.deb')):
            item = fields(subprocess.check_output(['dpkg-deb', '-f', str(path),
                'Package', 'Version', 'Architecture', 'Source', 'Depends', 'Pre-Depends'], text=True))
            item.update({'filename': path.name, 'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())})
            packages.append(item)
        runtime = validate_packages(packages, lock['candidateVersion'])
        for item in runtime:
            target = evidence / 'runtime-packages' / item['filename']
            target.parent.mkdir(exist_ok=True)
            shutil.copyfile(source.parent / item['filename'], target)
        for pattern in ('*.buildinfo', '*.changes'):
            for path in source.parent.glob(pattern):
                shutil.copyfile(path, evidence / path.name)
        report['packages'] = packages
        report['exportedRuntimePackages'] = sorted(item['Package'] for item in runtime)
        (evidence / 'sbom.cdx.json').write_text(json.dumps(sbom(lock, packages,
            (evidence / 'toolchain/installed-packages.tsv').read_text()), indent=2) + '\n')
        report['complete'] = report['passed'] = True
    except Exception as error:
        report['errorType'] = type(error).__name__
        if isinstance(error, ValueError):
            report['error'] = str(error)
        raise
    finally:
        report['files'] = {str(p.relative_to(evidence)): sha(p.read_bytes())
                           for p in sorted(evidence.rglob('*')) if p.is_file()}
        (evidence / 'assessment.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'complete': report['complete'], 'passed': report['passed'],
                          'runtimeInstalled': False}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
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
