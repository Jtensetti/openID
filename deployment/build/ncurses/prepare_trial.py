"""Bind a successful ncurses build to a small, offline trial-image context."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

from candidate import check_packages, load_lock


MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(root, relative):
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


def bounded(path):
    with path.open('rb') as stream:
        raw = stream.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise ValueError('evidence file exceeds size limit')
    return raw


def validate(directory, revision, lock):
    if (directory.is_symlink() or not directory.is_dir()
            or not re.fullmatch(r'[a-f0-9]{40}', revision)
            or bounded(regular(directory, 'tested-revision.txt')).decode().strip() != revision):
        raise ValueError('candidate build belongs to another revision')
    evidence = directory / 'evidence'
    if evidence.is_symlink() or not evidence.is_dir():
        raise ValueError('missing or linked evidence directory')
    assessment_raw = bounded(regular(evidence, 'assessment.json'))
    assessment = json.loads(assessment_raw)
    if (assessment.get('complete') is not True or assessment.get('passed') is not True
            or assessment.get('runtimeInstalled') is not False
            or assessment.get('candidateVersion') != lock['candidateVersion']
            or json.loads(bounded(regular(evidence, 'candidate.lock.json'))) != lock):
        raise ValueError('candidate build is failed, incomplete or different')
    files = assessment.get('files')
    if not isinstance(files, dict) or not 1 <= len(files) <= 2000:
        raise ValueError('missing or excessive evidence manifest')
    total = 0
    for name, expected in files.items():
        if name == 'assessment.json' or not re.fullmatch(r'[a-f0-9]{64}', expected):
            raise ValueError('invalid evidence digest')
        raw = bounded(regular(evidence, name))
        total += len(raw)
        if total > MAX_TOTAL or digest(raw) != expected:
            raise ValueError('candidate evidence bytes differ or exceed limit')
    runtime = check_packages(assessment['packages'], lock)
    expected_names = set(lock['runtimePackages'])
    if (len(runtime) != len(expected_names)
            or {p['Package'] for p in runtime} != expected_names
            or assessment.get('exportedPackages') != sorted(expected_names)):
        raise ValueError('candidate runtime group differs')
    packages = evidence / 'candidate-packages'
    if (packages.is_symlink() or not packages.is_dir()
            or {p.name for p in packages.iterdir()} != {p['filename'] for p in runtime}):
        raise ValueError('candidate package directory differs')
    selected = {'assessment.json': digest(assessment_raw),
                'candidate.lock.json': files['candidate.lock.json']}
    for item in runtime:
        name = 'candidate-packages/' + item['filename']
        package = regular(evidence, name)
        if files.get(name) != item['sha256'] or package.stat().st_size != item['bytes']:
            raise ValueError('candidate package is not bound to build evidence')
        selected[name] = item['sha256']
    return evidence, selected, len(files)


def prepare(directory, destination, revision):
    lock = load_lock()
    evidence, selected, verified = validate(directory, revision, lock)
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {'format': 1, 'preparedOnly': True, 'runtimeInstalled': False,
              'testedRevision': revision, 'buildAssessmentSHA256': selected['assessment.json'],
              'candidateEvidenceFilesVerified': verified, 'files': {},
              'limits': ['Context preparation is not installation or an application-image test.']}
    for name, expected in selected.items():
        raw = bounded(regular(evidence, name))
        if digest(raw) != expected:
            raise ValueError('candidate changed during context preparation')
        target = destination / 'inputs' / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o600)
        report['files']['inputs/' + name] = expected
    source = Path(__file__).resolve().parent
    for name in ('trial_install.py', 'candidate.lock.json'):
        raw = bounded(regular(source, name))
        target = destination / 'helpers' / name
        target.parent.mkdir(mode=0o700, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o600)
        report['files']['helpers/' + name] = digest(raw)
    dockerfile = bounded(regular(source, 'Trial.Dockerfile'))
    (destination / 'Dockerfile').write_bytes(dockerfile)
    report['files']['Dockerfile'] = digest(dockerfile)
    (destination / 'context-manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-directory', type=Path, required=True)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--tested-revision', required=True)
    args = parser.parse_args()
    result = prepare(args.candidate_directory, args.context, args.tested_revision)
    print(json.dumps({key: result[key] for key in
                      ('preparedOnly', 'runtimeInstalled', 'testedRevision', 'buildAssessmentSHA256')}))
