"""Prepare a bounded Docker context from successful candidate evidence only."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re

from bootstrap import sha
from build import RUNTIME_PACKAGES, load_lock, validate_packages


MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024


def regular_file(root, relative):
    name = PurePosixPath(relative)
    if (not relative or name.is_absolute() or str(name) != relative
            or any(part in ('.', '..') for part in name.parts)):
        raise ValueError('unsafe evidence path')
    path = root
    for part in name.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('linked evidence path')
    if not path.is_file():
        raise ValueError('missing regular evidence file')
    return path


def read_bounded(path):
    with path.open('rb') as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError('evidence file exceeds size limit')
    return raw


def validate_evidence(directory, tested_revision, lock):
    if (directory.is_symlink() or not directory.is_dir()
            or not re.fullmatch(r'[a-f0-9]{40}', tested_revision)):
        raise ValueError('invalid candidate directory or revision')
    if read_bounded(regular_file(directory, 'tested-revision.txt')).decode().strip() != tested_revision:
        raise ValueError('candidate evidence belongs to a different revision')
    evidence = directory / 'evidence'
    if evidence.is_symlink() or not evidence.is_dir():
        raise ValueError('missing or linked evidence directory')
    raw = read_bounded(regular_file(evidence, 'assessment.json'))
    assessment = json.loads(raw)
    if (assessment.get('complete') is not True or assessment.get('passed') is not True
            or assessment.get('runtimeInstalled') is not False
            or assessment.get('candidateVersion') != lock['candidateVersion']):
        raise ValueError('candidate build is failed, incomplete or different')
    locked = read_bounded(regular_file(evidence, 'candidate.lock.json'))
    if json.loads(locked) != lock:
        raise ValueError('candidate used a different source/toolchain lock')
    files = assessment.get('files')
    if not isinstance(files, dict) or not 1 <= len(files) <= 2000:
        raise ValueError('missing or excessive evidence manifest')
    total = 0
    for name, expected in files.items():
        if name == 'assessment.json' or not re.fullmatch(r'[a-f0-9]{64}', expected):
            raise ValueError('invalid evidence digest')
        payload = read_bounded(regular_file(evidence, name))
        total += len(payload)
        if total > MAX_TOTAL_BYTES or sha(payload) != expected:
            raise ValueError('candidate evidence bytes differ or exceed limit')
    if files.get('candidate.lock.json') != sha(locked):
        raise ValueError('source/toolchain lock is absent from evidence manifest')
    runtime = validate_packages(assessment['packages'], lock['candidateVersion'])
    if assessment.get('exportedRuntimePackages') != sorted(RUNTIME_PACKAGES):
        raise ValueError('candidate export differs')
    packages = evidence / 'runtime-packages'
    if (packages.is_symlink() or not packages.is_dir()
            or {p.name for p in packages.iterdir()} != {item['filename'] for item in runtime}):
        raise ValueError('runtime package directory differs')
    selected = {'assessment.json': sha(raw), 'candidate.lock.json': sha(locked)}
    for item in runtime:
        name = 'runtime-packages/' + item['filename']
        path = regular_file(evidence, name)
        if files.get(name) != item['sha256'] or path.stat().st_size != item['bytes']:
            raise ValueError('runtime package is not bound to its build evidence')
        selected[name] = item['sha256']
    return evidence, selected, len(files)


def prepare(directory, destination, tested_revision):
    evidence, selected, verified_files = validate_evidence(directory, tested_revision, load_lock())
    # No container is built, package installed or existing destination overwritten.
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {'format': 1, 'preparedOnly': True, 'runtimeInstalled': False,
              'testedRevision': tested_revision, 'buildAssessmentSHA256': selected['assessment.json'],
              'candidateEvidenceFilesVerified': verified_files, 'files': {},
              'limits': ['Context preparation is not a signature re-verification, installation or ABI test.',
                         'The reference image must be bound and inspected separately before and after Docker build.']}
    for name, expected in selected.items():
        # Recheck the bytes being copied, not just an earlier stat/hash result.
        raw = read_bounded(regular_file(evidence, name))
        if sha(raw) != expected:
            raise ValueError('candidate changed during context preparation')
        target = destination / 'inputs' / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o600)
        report['files'][str(target.relative_to(destination))] = expected
    source = Path(__file__).resolve().parent
    helpers = {name: source / name for name in
               ('trial_install.py', 'bootstrap.py', 'build.py', 'candidate.lock.json')}
    helpers['file_privileges.py'] = source.parent / 'file_privileges.py'
    for name, path in helpers.items():
        raw = read_bounded(regular_file(path.parent, path.name))
        target = destination / 'helpers' / name
        target.parent.mkdir(mode=0o700, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o600)
        report['files']['helpers/' + name] = sha(raw)
    dockerfile = read_bounded(regular_file(source, 'Trial.Dockerfile'))
    (destination / 'Dockerfile').write_bytes(dockerfile)
    (destination / 'Dockerfile').chmod(0o600)
    report['files']['Dockerfile'] = sha(dockerfile)
    # A final manifest is emitted only after every selected file has been copied.
    (destination / 'context-manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    (destination / 'context-manifest.json').chmod(0o600)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-directory', type=Path, required=True)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--tested-revision', required=True)
    args = parser.parse_args()
    report = prepare(args.candidate_directory, args.context, args.tested_revision)
    print(json.dumps({key: report[key] for key in
                      ('preparedOnly', 'runtimeInstalled', 'testedRevision', 'buildAssessmentSHA256')}))
