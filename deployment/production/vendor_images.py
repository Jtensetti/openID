"""Rebuild locked derived images in CI; production only imports the tested outputs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from contract import VENDORS
from vendor_builder import BUILDER_IMAGE, export_image

ROOT = Path(__file__).resolve().parent
CONTEXT = ROOT / 'vendor-builds'
EPOCH = '1794484800'


def require(value, message):
    if not value:
        raise ValueError(message)


def check_inputs(role, vendor=None, context=CONTEXT):
    vendor = VENDORS[role] if vendor is None else vendor
    build = vendor.get('build')
    require(isinstance(build, dict) and set(build) == {'recipe', 'epoch', 'inputs', 'builderImage'},
            'complete derived-image build lock required')
    require(build['recipe'] == 'Dockerfile.' + role and build['epoch'] == EPOCH,
            'derived-image recipe or timestamp changed')
    require(build['builderImage'] == BUILDER_IMAGE, 'derived-image builder changed')
    inputs = build['inputs']
    expected = {'Dockerfile.postgres'} if role == 'postgres' else {
        'Dockerfile.openbao', 'openbao.go.mod', 'openbao.go.sum', 'openbao.login_mfa.go',
        'tjipp_mfa_test.go', 'sources.lock.json', 'prepare_source.py', 'collect_licenses.py',
        'supplemental-licenses/lock.json', 'supplemental-licenses/reedsolomon-MIT'}
    require(set(inputs) == expected, 'derived-image input coverage changed')
    for name, checksum in inputs.items():
        path = context / name
        require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(context.resolve())
                and hashlib.sha256(path.read_bytes()).hexdigest() == checksum,
                'derived-image input hash mismatch: ' + name)
    return build


def build(role):
    vendor = VENDORS[role]
    recipe = check_inputs(role)
    subprocess.run(['docker', 'pull', '--platform', 'linux/amd64', vendor['source']], check=True)
    base = json.loads(subprocess.check_output(['docker', 'image', 'inspect', vendor['source']]))[0]
    require(base['Id'] == vendor['baseID'] and base['Os'] == 'linux' and base['Architecture'] == 'amd64',
            'derived-image base identity changed')
    tag = 'tjipp-' + role + ':locked-build'
    export_image(CONTEXT, recipe['recipe'], tag, recipe['epoch'])
    info = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tag]))[0]
    require(info['Id'] == vendor['id'] and info['Os'] == 'linux' and info['Architecture'] == 'amd64',
            'derived-image rebuild differs from the locked candidate')
    return info['Id']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=sorted(VENDORS))
    arguments = parser.parse_args()
    for role in [arguments.role] if arguments.role else VENDORS:
        print(role + ': ' + build(role))
