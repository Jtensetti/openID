"""Check the installed candidate as the ordinary application user."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import re
import subprocess

from bootstrap import sha
from build import load_lock, validate_packages
from trial_install import inventory, check_transition


def probe(image_id, revision, assessment_sha256):
    if ((platform.system(), platform.machine(), os.geteuid()) != ('Linux', 'x86_64', 10001)
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id)
            or not re.fullmatch(r'[a-f0-9]{40}', revision)
            or not re.fullmatch(r'[a-f0-9]{64}', assessment_sha256)):
        raise ValueError('requires the exact trial image as its ordinary runtime user')
    report = {'format': 1, 'complete': False, 'passed': False, 'imageID': image_id,
              'testedRevision': revision, 'uid': os.getuid(), 'euid': os.geteuid(),
              'commands': {}, 'libraries': {},
              'limits': ['Library loading and version commands are not a complete ABI or security regression suite.',
                         'No privileged mount, namespace or kernel feature is exercised here.']}
    try:
        lock = load_lock()
        installation = json.loads(Path('/usr/share/doc/openid-util-linux-candidate/installation.json').read_text())
        if (installation.get('complete') is not True or installation.get('passed') is not True
                or installation.get('buildAssessmentSHA256') != assessment_sha256):
            raise ValueError('installation evidence is incomplete or different')
        packages = validate_packages(installation['candidatePackages'], lock['candidateVersion'])
        installed = inventory()
        if installed != installation['afterPackages']:
            raise ValueError('installed package state changed after trial installation')
        expected = {item['Package']: item['Version'] for item in packages}
        report['changedPackages'] = check_transition(installation['beforePackages'], installed, expected)
        for name in ('mount', 'umount', 'nsenter', 'findmnt', 'lsblk', 'setpriv', 'logger'):
            output = subprocess.check_output(['/usr/bin/' + name, '--version'],
                text=True, stderr=subprocess.STDOUT, timeout=10)
            if not re.search(r'\butil-linux ' + re.escape(lock['sourceVersion']) + r'(?:\s|$)', output):
                raise ValueError('installed command reports an unexpected version: ' + name)
            report['commands'][name] = output.strip()
        base = Path('/usr/lib/x86_64-linux-gnu')
        handles = []
        for name in ('libblkid.so.1', 'liblastlog2.so.2', 'libmount.so.1', 'libsmartcols.so.1', 'libuuid.so.1'):
            path = base / name
            resolved = path.resolve(strict=True)
            if resolved.parent != base or not resolved.is_file():
                raise ValueError('library resolves outside the expected directory')
            handles.append(ctypes.CDLL(str(path), mode=os.RTLD_NOW | os.RTLD_LOCAL))
            report['libraries'][name] = {'resolvedPath': str(resolved), 'sha256': sha(resolved.read_bytes())}
        report.update(complete=True, passed=True, buildAssessmentSHA256=assessment_sha256)
    except Exception as error:
        report['errorType'] = type(error).__name__
        if isinstance(error, ValueError):
            report['error'] = str(error)
        raise
    finally:
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--assessment-sha256', required=True)
    args = parser.parse_args()
    probe(args.image_id, args.revision, args.assessment_sha256)
