"""Authenticate and build an ACL candidate without installing it in an app image."""
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
import urllib.parse
import urllib.request

# The same reviewed archive/signature helpers are copied beside this module in
# the isolated builder. On the developer host they live in the sibling tree.
sys.path.append(str(Path(__file__).resolve().parent.parent / 'util_linux'))
from bootstrap import fields, sha
from build import check_input, extract_regular, run, verify_signature


ORIGIN = 'https://deb.debian.org/debian/pool/main/a/acl/'
PACKAGES = {'acl', 'libacl1', 'libacl1-dev'}


def load_lock():
    return json.loads(Path(__file__).with_name('candidate.lock.json').read_text())


def fetch_inputs(directory, lock):
    directory.mkdir(parents=True, exist_ok=False)
    names = set()
    for item in lock['inputs']:
        name = item['filename']
        if (PurePosixPath(name).name != name or name in names
                or item['url'] != ORIGIN + name
                or type(item['bytes']) is not int or not 0 < item['bytes'] < 16 * 1024 * 1024):
            raise ValueError('unexpected source input')
        names.add(name)
        with urllib.request.urlopen(item['url'], timeout=60) as response:
            raw = response.read(item['bytes'] + 1)
        path = directory / name
        path.write_bytes(raw)
        check_input(path, item)
        print(json.dumps({'input': name, 'bytes': len(raw), 'sha256': sha(raw)}), flush=True)


def check_dsc(text, lock):
    metadata = fields(text)
    if (metadata.get('Source') != 'acl' or metadata.get('Version') != lock['packagingVersion']
            or metadata.get('Format') != '3.0 (quilt)'):
        raise ValueError('unexpected Debian source identity')
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
        raise ValueError('signed source checksums differ from reviewed inputs')
    return metadata


def check_public_keys(listing, expected):
    rows = [line.split(':') for line in listing.splitlines()]
    if any(row[0] in ('sec', 'ssb') for row in rows):
        raise ValueError('private source verification key')
    found = []
    for i, row in enumerate(rows):
        if row[0] != 'pub':
            continue
        if (i + 1 >= len(rows) or len(rows[i + 1]) < 10 or rows[i + 1][0] != 'fpr'
                or not re.fullmatch(r'[A-F0-9]{40}', rows[i + 1][9])):
            raise ValueError('missing full public primary fingerprint')
        found.append(rows[i + 1][9])
    if len(found) != len(set(found)) or sorted(found) != sorted(expected) or not found:
        raise ValueError('source key set differs')
    return found


def prepare(inputs, work, evidence, lock, debian_keyring):
    for item in lock['inputs']:
        check_input(inputs / item['filename'], item)
    if sha(debian_keyring.read_bytes()) != lock['debianKeyringSHA256']:
        raise ValueError('Debian keyring differs from authenticated snapshot')
    home = work / 'gnupg'
    home.mkdir(mode=0o700)
    prefix = 'acl_' + lock['packagingVersion']
    dsc = inputs / (prefix + '.dsc')
    debian_signer = verify_signature(dsc, None, debian_keyring, home,
                                    evidence / 'debian-signature.log', lock['debianSigner'])
    check_dsc(dsc.read_text(), lock)
    packaging = extract_regular(inputs / (prefix + '.debian.tar.xz'), work / 'packaging', 'debian')
    key = packaging / 'upstream/signing-key.asc'
    if sha(key.read_bytes()) != lock['upstreamKeySHA256']:
        raise ValueError('authenticated upstream key bytes differ')
    run(['gpg', '--batch', '--no-options', '--homedir', str(home), '--with-colons',
         '--with-fingerprint', '--show-keys', str(key)], evidence / 'upstream-key.log')
    check_public_keys((evidence / 'upstream-key.log').read_text(), lock['upstreamPrimaryFingerprints'])
    if lock['upstreamSigner'] not in lock['upstreamPrimaryFingerprints']:
        raise ValueError('expected signer is not an authenticated primary key')
    ring = home / 'upstream.gpg'
    run(['gpg', '--batch', '--no-options', '--homedir', str(home), '--dearmor',
         '--output', str(ring), str(key)], evidence / 'upstream-key-import.log')
    archive = inputs / ('acl_' + lock['sourceVersion'] + '.orig.tar.xz')
    upstream_signer = verify_signature(Path(str(archive) + '.asc'), archive, ring, home,
                                      evidence / 'upstream-signature.log', lock['upstreamSigner'])
    source = extract_regular(archive, work / 'source', 'acl-' + lock['sourceVersion'])
    shutil.copytree(packaging, source / 'debian')
    for name, expected in {**lock['packagingFiles'], **lock['licenseFiles']}.items():
        if sha((source / name).read_bytes()) != expected:
            raise ValueError('reviewed source/packaging file differs: ' + name)
    for name in lock['licenseFiles']:
        target = evidence / 'licenses' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    # No source, patch-series, hardening or test setting is changed.
    changelog = source / 'debian/changelog'
    changelog.write_text('acl (' + lock['candidateVersion'] + ') UNRELEASED; urgency=medium\n\n'
                        '  * openID isolated evaluation against the pinned Trixie toolchain.\n'
                        '  * Preserve upstream code and Debian patches, hardening and tests.\n'
                        '  * Not an official Debian update or production-approved build.\n\n'
                        ' -- openID candidate automation <noreply@example.invalid>  '
                        'Wed, 28 Oct 2026 00:00:00 +0000\n\n' + changelog.read_text())
    return source, {'debianSigner': debian_signer, 'upstreamSigner': upstream_signer,
                    'packagingFilesVerified': len(lock['packagingFiles']),
                    'licenseFilesVerified': len(lock['licenseFiles'])}


def check_results(source, lock):
    expected = set(lock['requiredPassingTests'] + lock['environmentLimitedTests'])
    actual = {str(p.relative_to(source).with_suffix('.run')): p for p in (source / 'test').rglob('*.trs')}
    if set(actual) != expected:
        raise ValueError('missing or unexpected upstream test results')
    outcomes = {}
    for name, path in actual.items():
        if path.is_symlink() or not path.is_file():
            raise ValueError('linked or non-regular upstream test result')
        matches = re.findall(r'^:test-result: (PASS|FAIL|SKIP|XFAIL|XPASS|ERROR)\s*$',
                             path.read_text(), re.M)
        if len(matches) != 1:
            raise ValueError('ambiguous upstream test result')
        outcomes[name] = matches[0]
        if (matches[0] in ('FAIL', 'XPASS', 'ERROR')
                or (name in lock['requiredPassingTests'] and matches[0] != 'PASS')):
            raise ValueError('required upstream regression did not pass: ' + name)
    return outcomes


def check_packages(packages, version):
    names, filenames = set(), set()
    for p in packages:
        name = p['Package']
        if (name not in PACKAGES | {'acl-dbgsym', 'libacl1-dbgsym'} or name in names
                or p['filename'] in filenames or p['Version'] != version
                or p.get('Source', name) not in ('acl', 'acl (' + version + ')')
                or p['Architecture'] != 'amd64'
                or p['filename'] != name + '_' + version + '_amd64.deb'
                or type(p['bytes']) is not int or p['bytes'] <= 0
                or not re.fullmatch(r'[a-f0-9]{64}', p['sha256'])):
            raise ValueError('unexpected built ACL package identity')
        names.add(name)
        filenames.add(p['filename'])
    if not PACKAGES <= names:
        raise ValueError('incomplete ACL binary package group')
    return [p for p in packages if p['Package'] in PACKAGES]


def source_bundle(source, path, epoch):
    def normalize(info):
        info.uid = info.gid = 0
        info.uname = info.gname = ''
        info.mtime = epoch
        return info
    with tarfile.open(path, 'w:xz') as archive:
        archive.add(source, arcname='acl-candidate', filter=normalize)


def sbom(lock, packages, toolchain):
    components = [{'type': 'file', 'bom-ref': 'input:' + p['filename'], 'name': p['filename'],
                   'hashes': [{'alg': 'SHA-256', 'content': p['sha256']}],
                   'externalReferences': [{'type': 'distribution', 'url': p['url']}]}
                  for p in lock['inputs']]
    for p in packages:
        components.append({'type': 'library', 'bom-ref': 'built:' + p['Package'],
                           'name': p['Package'], 'version': p['Version'],
                           'hashes': [{'alg': 'SHA-256', 'content': p['sha256']}],
                           'licenses': [{'license': {'name': 'See preserved per-file notices and Debian copyright'}}],
                           'properties': [{'name': 'openid:origin', 'value': 'Local evaluation build; not an official Debian binary'},
                                          {'name': 'openid:artifact-exported', 'value': str(p['Package'] in PACKAGES).lower()}]})
    for line in toolchain.splitlines():
        name, version, arch, state = line.split('\t')
        if state != 'installed':
            raise ValueError('incomplete builder package state')
        components.append({'type': 'library', 'bom-ref': 'toolchain:' + name + ':' + arch,
                           'name': name, 'version': version,
                           'purl': 'pkg:deb/debian/' + name + '@' + urllib.parse.quote(version, safe='') + '?arch=' + arch,
                           'properties': [{'name': 'openid:scope', 'value': 'Disposable builder only'}]})
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'component': {'type': 'application', 'name': 'openid-acl-package-evaluation',
                                      'version': lock['candidateVersion']},
                         'properties': [{'name': 'openid:scope', 'value': 'Source inputs, produced debs and builder dpkg packages; not an application or complete embedded-code SBOM.'}]},
            'components': components}


def build(inputs, output, lock):
    if (platform.system() != 'Linux' or platform.machine() != 'x86_64' or os.geteuid() == 0
            or os.environ.get('OPENID_ACL_CANDIDATE_BUILD') != '1'):
        raise ValueError('requires the unprivileged isolated Linux amd64 ACL builder')
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
        shutil.copytree('/builder', evidence / 'build-inputs',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for name in ('libattr1', 'libattr1-dev'):
            target = evidence / 'licenses' / 'build-dependencies' / name
            target.mkdir(parents=True)
            shutil.copyfile(Path('/usr/share/doc') / name / 'copyright', target / 'copyright')
        (evidence / 'candidate.lock.json').write_text(json.dumps(lock, indent=2) + '\n')
        run([sys.executable, '/builder/test_signature_policy.py'], evidence / 'signature-policy.log')
        report['signaturePolicyRegressionPassed'] = True
        source, report['source'] = prepare(inputs, work, evidence, lock,
                                         Path('/usr/share/keyrings/debian-keyring.pgp'))
        # The upstream runwrapper loads a generated test library from mktemp's
        # directory. Keep /tmp non-executable; place that directory on the
        # disposable, writable build volume instead.
        test_tmp = work / 'test-tmp'
        test_tmp.mkdir(mode=0o700)
        env = {'PATH': os.environ['PATH'], 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
               'SOURCE_DATE_EPOCH': str(lock['sourceDateEpoch']), 'DEB_BUILD_OPTIONS': 'parallel=1',
               'TMPDIR': str(test_tmp)}
        run(['dpkg-source', '--before-build', '.'], evidence / 'patches.log', cwd=source, env=env)
        source_bundle(source, evidence / 'prepared-source.tar.xz', lock['sourceDateEpoch'])
        run(['dpkg-checkbuilddeps'], evidence / 'build-dependencies.log', cwd=source, env=env)
        run(['dpkg-buildpackage', '--build=binary', '--no-sign', '--jobs=1'],
            evidence / 'package-build.log', cwd=source, env=env)
        report['upstreamTests'] = check_results(source, lock)
        packages = []
        for path in sorted(source.parent.glob('*.deb')):
            p = fields(subprocess.check_output(['dpkg-deb', '-f', str(path), 'Package', 'Version',
                'Architecture', 'Source', 'Depends', 'Pre-Depends'], text=True))
            p.update(filename=path.name, bytes=path.stat().st_size, sha256=sha(path.read_bytes()))
            packages.append(p)
        exported = check_packages(packages, lock['candidateVersion'])
        from compatibility import probe
        report['compatibility'] = probe(source.parent, exported, work / 'compatibility', evidence, env)
        for p in exported:
            target = evidence / 'candidate-packages' / p['filename']
            target.parent.mkdir(exist_ok=True)
            shutil.copyfile(source.parent / p['filename'], target)
        for pattern in ('*.buildinfo', '*.changes'):
            for path in source.parent.glob(pattern):
                shutil.copyfile(path, evidence / path.name)
        report['packages'] = packages
        report['exportedPackages'] = sorted(p['Package'] for p in exported)
        (evidence / 'sbom.cdx.json').write_text(json.dumps(sbom(lock, packages,
            (evidence / 'toolchain/installed-packages.tsv').read_text()), indent=2) + '\n')
        report['complete'] = report['passed'] = True
    except Exception as error:
        report['errorType'] = type(error).__name__
        if isinstance(error, ValueError):
            report['error'] = str(error)
        raise
    finally:
        if source is not None:
            for path in (source / 'test').rglob('*'):
                if path.is_file() and not path.is_symlink() and path.suffix in ('.log', '.trs'):
                    target = evidence / 'upstream-tests' / path.relative_to(source / 'test')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, target)
        report['files'] = {str(p.relative_to(evidence)): sha(p.read_bytes())
                           for p in sorted(evidence.rglob('*')) if p.is_file()}
        (evidence / 'assessment.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'complete': report['complete'], 'passed': report['passed'],
                          'runtimeInstalled': False}), flush=True)


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
