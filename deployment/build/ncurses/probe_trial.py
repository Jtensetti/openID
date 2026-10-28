"""Inspect the installed ncurses candidate in the restricted trial image."""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import re
import subprocess


def query_packages():
    raw = subprocess.check_output(['dpkg-query', '-W',
        '-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'], text=True)
    result = {}
    for line in raw.splitlines():
        name, version, arch, status = line.split('\t')
        if name in result or status != 'installed':
            raise ValueError('incomplete package inventory')
        result[name] = {'version': version, 'architecture': arch}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--assessment-sha256', required=True)
    args = parser.parse_args()
    if (not re.fullmatch(r'sha256:[a-f0-9]{64}', args.image_id)
            or not re.fullmatch(r'[a-f0-9]{40}', args.revision)
            or not re.fullmatch(r'[a-f0-9]{64}', args.assessment_sha256)):
        raise ValueError('invalid trial binding')
    installation = json.loads(Path('/usr/share/doc/openid-ncurses-candidate/installation.json').read_text())
    if (installation.get('complete') is not True or installation.get('passed') is not True
            or installation.get('buildAssessmentSHA256') != args.assessment_sha256):
        raise ValueError('trial installation evidence differs')
    packages = query_packages()
    expected = {p['Package']: (p['Version'], p['Architecture']) for p in installation['candidatePackages']}
    if set(expected) != {'libncursesw6', 'libtinfo6', 'ncurses-base', 'ncurses-bin'}:
        raise ValueError('candidate package group differs')
    for name, (version, arch) in expected.items():
        if packages.get(name) != {'version': version, 'architecture': arch}:
            raise ValueError('candidate package differs from installed state')
    for command in (('tic', '-V'), ('infocmp', '-V')):
        result = subprocess.check_output(command, text=True).strip()
        if '6.6' not in result:
            raise ValueError('ncurses command version differs')
    ctypes.CDLL('libncursesw.so.6')
    ctypes.CDLL('libtinfo.so.6')
    import curses
    if curses.ncurses_version.major != 6:
        raise ValueError('unexpected Python curses binding')
    report = {'format': 1, 'passed': True, 'imageID': args.image_id,
              'sourceRevision': args.revision, 'buildAssessmentSHA256': args.assessment_sha256,
              'installedPackages': expected, 'ncursesVersion': subprocess.check_output(
                  ['tic', '-V'], text=True).strip(),
              'installationSHA256': hashlib.sha256(Path(
                  '/usr/share/doc/openid-ncurses-candidate/installation.json').read_bytes()).hexdigest(),
              'limits': ['No privileged CVE reproducer, sanitizer, fuzzing or full ABI sweep.']}
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
