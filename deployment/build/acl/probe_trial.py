"""Inspect the installed ACL library and tar in the restricted trial image."""
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
    installation = json.loads(Path('/usr/share/doc/openid-acl-candidate/installation.json').read_text())
    if (installation.get('complete') is not True or installation.get('passed') is not True
            or installation.get('buildAssessmentSHA256') != args.assessment_sha256):
        raise ValueError('trial installation evidence differs')
    packages = query_packages()
    expected = {p['Package']: (p['Version'], p['Architecture']) for p in installation['candidatePackages']}
    if set(expected) != {'libacl1'}:
        raise ValueError('candidate package group differs')
    for name, (version, arch) in expected.items():
        if packages.get(name) != {'version': version, 'architecture': arch}:
            raise ValueError('candidate package differs from installed state')
    library = ctypes.CDLL('libacl.so.1')
    if library.acl_get_file is None:
        raise ValueError('ACL API is not available')
    linkage = subprocess.check_output(['ldd', '/usr/bin/tar'], text=True)
    if 'libacl.so.1' not in linkage or 'not found' in linkage:
        raise ValueError('tar does not resolve the installed ACL library')
    archive = subprocess.check_output(['tar', '--acls', '-cf', '-',
                                       '--directory', '/app/verification', 'serve.py'])
    members = subprocess.check_output(['tar', '-tf', '-'], input=archive, text=False)
    if members.strip() != b'serve.py':
        raise ValueError('tar archive round-trip differs')
    report = {'format': 1, 'passed': True, 'imageID': args.image_id,
              'sourceRevision': args.revision, 'buildAssessmentSHA256': args.assessment_sha256,
              'installedPackages': expected, 'tarVersion': subprocess.check_output(
                  ['tar', '--version'], text=True).splitlines()[0],
              'tarLinksACL': True, 'archiveRoundTrip': True,
              'installationSHA256': hashlib.sha256(Path(
                  '/usr/share/doc/openid-acl-candidate/installation.json').read_bytes()).hexdigest(),
              'limits': ['No privileged race, NFS, root or full ABI sweep.']}
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
