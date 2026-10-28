"""Install the four authenticated runtime packages in a disposable image only."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess


ORDER = ('ncurses-base', 'libtinfo6', 'libncursesw6', 'ncurses-bin')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fields(raw):
    result = {}
    key = None
    for line in raw.splitlines():
        if line[:1].isspace() and key:
            result[key] += '\n' + line[1:]
        elif ':' in line:
            key, value = line.split(':', 1)
            result[key] = value.lstrip()
    return result


def inventory():
    raw = subprocess.check_output(['dpkg-query', '-W',
        '-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'], text=True)
    result = {}
    for line in raw.splitlines():
        name, version, arch, status = line.split('\t')
        if name in result or status != 'installed' or arch not in ('amd64', 'all'):
            raise ValueError('duplicate or incomplete installed package')
        result[name] = {'Version': version, 'Architecture': arch}
    if not result:
        raise ValueError('empty package inventory')
    return result


def protected_files(roots):
    records = {}
    def failed(error):
        raise error
    for root in roots:
        if root.is_symlink() or not root.is_dir():
            raise ValueError('protected root is missing or linked')
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed):
            for path in [Path(directory), *(Path(directory) / name for name in dirs + files)]:
                info = path.lstat()
                item = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
                if stat.S_ISLNK(info.st_mode):
                    item.update(type='symlink', target=os.readlink(path))
                elif stat.S_ISDIR(info.st_mode):
                    item['type'] = 'directory'
                elif stat.S_ISREG(info.st_mode):
                    h = hashlib.sha256()
                    with path.open('rb') as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                            h.update(chunk)
                    item.update(type='file', bytes=info.st_size, sha256=h.hexdigest())
                else:
                    raise ValueError('unexpected protected file type')
                records[str(path)] = item
    return records


def check_image(reference, candidate):
    for image in (reference, candidate):
        if (image.get('Os') != 'linux' or image.get('Architecture') != 'amd64'
                or not re.fullmatch(r'sha256:[a-f0-9]{64}', image.get('Id', ''))
                or image.get('RootFS', {}).get('Type') != 'layers'):
            raise ValueError('unexpected image identity')
    old, new = reference['RootFS']['Layers'], candidate['RootFS']['Layers']
    if (reference['Id'] == candidate['Id'] or not old or len(new) <= len(old)
            or new[:len(old)] != old):
        raise ValueError('trial is not derived from the exact reference')
    keys = ('User', 'Env', 'Entrypoint', 'Cmd', 'WorkingDir', 'Healthcheck',
            'ExposedPorts', 'Volumes', 'StopSignal')
    if (reference['Config'].get('User') != '10001:10001'
            or any(reference['Config'].get(key) != candidate['Config'].get(key) for key in keys)):
        raise ValueError('trial runtime configuration differs')
    labels = dict(reference['Config'].get('Labels') or {})
    labels.update({'io.openid.candidate-only': 'true', 'io.openid.evaluation': 'ncurses'})
    if candidate['Config'].get('Labels') != labels:
        raise ValueError('trial image labels differ')
    return {'referenceImage': reference['Id'], 'candidateImage': candidate['Id'],
            'preservedReferenceLayers': len(old), 'configurationFields': list(keys)}


def run(command, log):
    with log.open('w') as stream:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stream,
                                stderr=subprocess.STDOUT, timeout=180,
                                env=dict(os.environ, LC_ALL='C.UTF-8', DEBIAN_FRONTEND='noninteractive'))
    if result.returncode:
        print(log.read_text(errors='replace')[-16000:], flush=True)
        result.check_returncode()


def main():
    if ((platform.system(), platform.machine(), os.geteuid()) != ('Linux', 'x86_64', 0)
            or os.environ.get('OPENID_NCURSES_TRIAL') != '1'
            or not Path('/usr/share/doc/openid-python/build-lock.json').is_file()
            or not Path('/app/verification/serve.py').is_file()):
        raise ValueError('requires the isolated openID trial image build')
    inputs = Path('/package-candidate')
    output = Path('/usr/share/doc/openid-ncurses-candidate')
    output.mkdir()
    report = {'format': 1, 'complete': False, 'passed': False, 'evaluationOnly': True,
              'limits': ['Only the four already installed ncurses runtime packages may change version.',
                         'Protected application/JDK tree check excludes xattrs.',
                         'This is not privileged CVE reproduction, full ABI validation or release acceptance.']}
    try:
        lock = json.loads(Path('/package-trial/candidate.lock.json').read_text())
        assessment_raw = (inputs / 'assessment.json').read_bytes()
        assessment = json.loads(assessment_raw)
        expected_sha = os.environ.get('OPENID_CANDIDATE_ASSESSMENT_SHA256', '')
        if (not re.fullmatch(r'[a-f0-9]{64}', expected_sha) or sha(assessment_raw) != expected_sha
                or assessment.get('complete') is not True or assessment.get('passed') is not True
                or assessment.get('runtimeInstalled') is not False
                or assessment.get('candidateVersion') != lock['candidateVersion']
                or json.loads((inputs / 'candidate.lock.json').read_text()) != lock
                or assessment.get('exportedPackages') != sorted(ORDER)):
            raise ValueError('candidate build evidence differs or is incomplete')
        runtime = {p['Package']: p for p in assessment['packages'] if p['Package'] in ORDER}
        if set(runtime) != set(ORDER) or len(runtime) != len(ORDER):
            raise ValueError('candidate runtime group differs')
        directory = inputs / 'candidate-packages'
        if (directory.is_symlink() or not directory.is_dir()
                or {p.name for p in directory.iterdir()} != {p['filename'] for p in runtime.values()}):
            raise ValueError('candidate package files differ')
        paths = []
        for name in ORDER:
            item = runtime[name]
            path = directory / item['filename']
            if (path.is_symlink() or not path.is_file() or path.stat().st_size != item['bytes']
                    or sha(path.read_bytes()) != item['sha256']
                    or assessment['files'].get('candidate-packages/' + item['filename']) != item['sha256']
                    or item['Version'] != lock['candidateVersion']
                    or item['Architecture'] != lock['requiredPackages'][name]):
                raise ValueError('candidate package bytes or identity differ')
            header = fields(subprocess.check_output(['dpkg-deb', '-f', str(path),
                'Package', 'Version', 'Architecture', 'Source', 'Depends', 'Pre-Depends'], text=True))
            if header != {k: v for k, v in item.items() if k not in ('filename', 'bytes', 'sha256')}:
                raise ValueError('candidate package header differs')
            paths.append(str(path))
        before = inventory()
        for name in ORDER:
            if name not in before or before[name]['Architecture'] != lock['requiredPackages'][name]:
                raise ValueError('expected reference package is absent')
            subprocess.run(['dpkg', '--compare-versions', lock['candidateVersion'], 'gt',
                            before[name]['Version']], check=True)
        roots = [Path('/app'), Path('/usr/local'), Path('/opt/java/openjdk')]
        protected = protected_files(roots)
        for name, path in zip(ORDER, paths):
            run(['dpkg', '--install', path], output / ('dpkg-' + name + '.log'))
        if subprocess.check_output(['dpkg', '--audit']):
            raise ValueError('incomplete package state after installation')
        after = inventory()
        if (set(before) != set(after)
                or {name for name in before if before[name] != after[name]} != set(ORDER)
                or any(after[name] != {'Version': lock['candidateVersion'],
                                        'Architecture': lock['requiredPackages'][name]} for name in ORDER)):
            raise ValueError('installed package transition differs')
        if protected_files(roots) != protected:
            raise ValueError('trial changed protected application/runtime files')
        report.update(beforePackages=before, afterPackages=after,
                      changedPackages=list(ORDER), candidatePackages=[runtime[n] for n in ORDER],
                      protectedRoots=[str(x) for x in roots], protectedEntries=len(protected),
                      protectedManifestSHA256=sha(json.dumps(protected, sort_keys=True).encode()),
                      buildAssessmentSHA256=expected_sha, complete=True, passed=True)
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
