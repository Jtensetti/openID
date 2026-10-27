"""Offline trial installation inside a disposable image, never on a host."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess

from bootstrap import fields, sha
from build import RUNTIME_PACKAGES, load_lock, validate_packages


def check_image(reference, candidate):
    for image in (reference, candidate):
        if (image.get('Os') != 'linux' or image.get('Architecture') != 'amd64'
                or not re.fullmatch(r'sha256:[a-f0-9]{64}', image.get('Id', ''))
                or image.get('RootFS', {}).get('Type') != 'layers'):
            raise ValueError('unexpected trial image identity')
    layers = reference['RootFS']['Layers']
    new_layers = candidate['RootFS']['Layers']
    if (reference['Id'] == candidate['Id'] or not layers or len(new_layers) <= len(layers)
            or new_layers[:len(layers)] != layers):
        raise ValueError('trial image is not derived from the exact reference')
    keys = ('User', 'Env', 'Entrypoint', 'Cmd', 'WorkingDir', 'Healthcheck',
            'ExposedPorts', 'Volumes', 'StopSignal')
    if reference['Config'].get('User') != '10001:10001':
        raise ValueError('reference runtime user differs')
    if any(reference['Config'].get(key) != candidate['Config'].get(key) for key in keys):
        raise ValueError('trial changed runtime configuration')
    labels = dict(reference['Config'].get('Labels') or {})
    labels.update({'io.openid.candidate-only': 'true', 'io.openid.evaluation': 'util-linux'})
    if candidate['Config'].get('Labels') != labels:
        raise ValueError('trial image labels differ')
    return {'referenceImage': reference['Id'], 'candidateImage': candidate['Id'],
            'preservedReferenceLayers': len(layers), 'configurationFields': list(keys)}


def installed_packages(raw):
    result = {}
    for line in raw.splitlines():
        name, version, architecture, state = line.split('\t')
        if name in result or state != 'installed' or architecture not in ('amd64', 'all'):
            raise ValueError('duplicate or incomplete installed package')
        result[name] = {'Version': version, 'Architecture': architecture}
    if not result:
        raise ValueError('empty installed package inventory')
    return result


def check_plan(output, expected):
    """APT simulation is advisory; the installed state is also checked afterwards."""
    selected = {}
    for line in output.splitlines():
        if line.startswith(('Remv ', 'Purg ')):
            raise ValueError('trial would remove a package')
        if not line.startswith('Inst '):
            continue
        match = re.fullmatch(r'Inst ([a-z0-9][a-z0-9+.-]*)(?::amd64)?(?: \[[^\]]+\])? \((\S+)(?: .*)?\)', line)
        if not match or match[1] in selected:
            raise ValueError('unrecognized or duplicate APT installation')
        selected[match[1]] = match[2]
    if selected != expected:
        raise ValueError('APT plan differs from the complete candidate group')
    return selected


def check_transition(before, after, expected):
    if set(before) != set(after) or not set(expected) <= set(before):
        raise ValueError('trial changed the installed package set')
    changed = {name for name in before if before[name] != after[name]}
    if changed != set(expected):
        raise ValueError('trial changed an unexpected package or missed an upgrade')
    for name, version in expected.items():
        if after[name] != {'Version': version, 'Architecture': 'amd64'}:
            raise ValueError('installed candidate identity differs')
    return sorted(changed)


def protected_files(roots):
    """Hash physical files and link text without following directory symlinks."""
    records = {}
    def failed(error):
        raise error
    for root in roots:
        if root.is_symlink() or not root.is_dir():
            raise ValueError('protected root is missing or linked')
        paths = [root]
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed):
            paths.extend(Path(directory) / name for name in dirs + files)
        for path in sorted(paths):
            info = path.lstat()
            record = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
            if stat.S_ISLNK(info.st_mode):
                record.update(type='symlink', target=os.readlink(path))
            elif stat.S_ISDIR(info.st_mode):
                record['type'] = 'directory'
            elif stat.S_ISREG(info.st_mode):
                digest = hashlib.sha256()
                with path.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(chunk)
                record.update(type='file', bytes=info.st_size, sha256=digest.hexdigest())
            else:
                raise ValueError('unexpected protected file type')
            records[str(path)] = record
    return records


def run(command, log):
    with log.open('w') as stream:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stream,
                                stderr=subprocess.STDOUT, timeout=180,
                                env=dict(os.environ, LC_ALL='C.UTF-8', DEBIAN_FRONTEND='noninteractive'))
    if result.returncode:
        print(log.read_text(errors='replace')[-16000:], flush=True)
        result.check_returncode()
    return log.read_text()


def inventory():
    return installed_packages(subprocess.check_output(['dpkg-query', '-W',
        '-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'], text=True))


def main():
    if ((platform.system(), platform.machine(), os.geteuid()) != ('Linux', 'x86_64', 0)
            or os.environ.get('OPENID_UTIL_LINUX_TRIAL') != '1'
            or not Path('/usr/share/doc/openid-python/build-lock.json').is_file()
            or not Path('/app/verification/serve.py').is_file()):
        raise ValueError('requires the isolated openID trial image build')
    inputs = Path('/package-candidate')
    output = Path('/usr/share/doc/openid-util-linux-candidate')
    output.mkdir()
    report = {'format': 1, 'complete': False, 'passed': False, 'evaluationOnly': True,
              'limits': ['Only the nine candidate dpkg packages may change version; no additions/removals.',
                         'Protected-tree comparison covers names, types, content, modes and ownership, not xattrs.',
                         'This is not an ABI, vulnerability, application regression or production acceptance result.']}
    try:
        lock = load_lock()
        assessment = json.loads((inputs / 'assessment.json').read_text())
        expected_digest = os.environ.get('OPENID_CANDIDATE_ASSESSMENT_SHA256', '')
        if (not re.fullmatch(r'[a-f0-9]{64}', expected_digest)
                or sha((inputs / 'assessment.json').read_bytes()) != expected_digest
                or assessment.get('complete') is not True or assessment.get('passed') is not True
                or assessment.get('runtimeInstalled') is not False
                or assessment.get('candidateVersion') != lock['candidateVersion']
                or json.loads((inputs / 'candidate.lock.json').read_text()) != lock):
            raise ValueError('candidate build evidence is absent, failed or different')
        runtime = validate_packages(assessment['packages'], lock['candidateVersion'])
        if assessment.get('exportedRuntimePackages') != sorted(RUNTIME_PACKAGES):
            raise ValueError('candidate export differs')
        expected = {item['Package']: item['Version'] for item in runtime}
        directory = inputs / 'runtime-packages'
        if directory.is_symlink() or {p.name for p in directory.iterdir()} != {p['filename'] for p in runtime}:
            raise ValueError('candidate package files differ')
        package_paths = []
        for item in runtime:
            path = directory / item['filename']
            relative = str(path.relative_to(inputs))
            if (path.is_symlink() or not path.is_file() or path.stat().st_size != item['bytes']
                    or sha(path.read_bytes()) != item['sha256']
                    or assessment['files'].get(relative) != item['sha256']):
                raise ValueError('candidate package bytes differ')
            actual = fields(subprocess.check_output(['dpkg-deb', '-f', str(path),
                'Package', 'Version', 'Architecture', 'Source', 'Depends', 'Pre-Depends'], text=True))
            if actual != {k: v for k, v in item.items() if k not in ('filename', 'bytes', 'sha256')}:
                raise ValueError('candidate package header differs')
            package_paths.append(str(path))
        before = inventory()
        for name, version in expected.items():
            if name not in before or before[name]['Architecture'] != 'amd64':
                raise ValueError('runtime package missing or wrong architecture')
            subprocess.run(['dpkg', '--compare-versions', version, 'gt', before[name]['Version']], check=True)
        roots = [Path('/app'), Path('/usr/local'), Path('/opt/java/openjdk')]
        protected = protected_files(roots)
        policy = Path('/usr/sbin/policy-rc.d')
        previous_policy = policy.read_bytes() if policy.is_file() and not policy.is_symlink() else None
        if policy.is_symlink() or (policy.exists() and previous_policy is None):
            raise ValueError('unexpected service policy type')
        previous_mode = stat.S_IMODE(policy.stat().st_mode) if previous_policy is not None else None
        policy.write_text('#!/bin/sh\nexit 101\n')
        policy.chmod(0o755)
        command = ['apt-get', '--no-download', '--no-remove', '--no-install-recommends',
                   '--yes', 'install', *package_paths]
        report['plan'] = check_plan(run([*command, '--simulate'], output / 'apt-plan.log'), expected)
        run(command, output / 'apt-install.log')
        if subprocess.check_output(['dpkg', '--audit']):
            raise ValueError('incomplete package state after installation')
        after = inventory()
        report['changedPackages'] = check_transition(before, after, expected)
        if previous_policy is None:
            policy.unlink()
        else:
            policy.write_bytes(previous_policy)
            policy.chmod(previous_mode)
        if protected_files(roots) != protected:
            raise ValueError('trial changed protected application/runtime files')
        # This exact helper is copied from the reviewed source into the trial build.
        import file_privileges
        old_report = file_privileges.REPORT.read_bytes()
        (output / 'reference-file-privileges.json').write_bytes(old_report)
        privileges = file_privileges.apply(Path('/'))
        file_privileges.REPORT.write_text(json.dumps(privileges, indent=2) + '\n')
        file_privileges.REPORT.chmod(0o644)
        file_privileges.verify(Path('/'), privileges)
        report.update(beforePackages=before, afterPackages=after,
                      candidatePackages=runtime,
                      protectedRoots=[str(p) for p in roots], protectedEntries=len(protected),
                      protectedManifestSHA256=sha(json.dumps(protected, sort_keys=True).encode()),
                      buildAssessmentSHA256=expected_digest, privileges=privileges,
                      complete=True, passed=True)
    except Exception as error:
        report['errorType'] = type(error).__name__
        if isinstance(error, ValueError):
            report['error'] = str(error)
        raise
    finally:
        (output / 'installation.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({key: report[key] for key in ('complete', 'passed', 'evaluationOnly')}))


if __name__ == '__main__':
    main()
