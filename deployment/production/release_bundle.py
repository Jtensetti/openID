"""Verified three-image delivery. Import never starts services or changes their data."""
import argparse
from datetime import datetime, timedelta, timezone
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import audit_vendors
import delivery_inventory
from contract import VENDORS

application = delivery_inventory.image_bundle
SCHEMA = 'tjipp-three-image-bundle-v1'
ROLES = {'application', *VENDORS}
FILES = {'canonical-runtime.json', 'vendor-images.lock.json'}
FILES |= {'application/'+name for name in ('manifest.json', *application.PAYLOADS)}
for role in VENDORS:
    FILES.add('vendors/'+role+'/image.tar.gz')
    FILES |= {'vendors/'+role+'/evidence/'+name for name in ('assessment.json', *audit_vendors.FILES)}
require = application.require
digest = application.digest


def inspection(image):
    result = json.loads(application.run('docker', 'image', 'inspect', image))
    require(len(result) == 1 and result[0]['Os'] == 'linux' and result[0]['Architecture'] == 'amd64',
            'one linux/amd64 image required')
    return result[0]


def image_record(role, info, revision):
    require(re.fullmatch('sha256:[a-f0-9]{64}', info['Id']) and type(info['Size']) is int and info['Size'] > 0,
            'image identity and size required')
    return {'id': info['Id'], 'platform': 'linux/amd64', 'sizeBytes': info['Size'],
            'tag': ('openid-pilot' if role == 'application' else 'tjipp-'+role)+':commit-'+revision}


def export_image(image, target):
    with target.open('xb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as zipped:
        process = subprocess.Popen(['docker', 'save', image], stdout=subprocess.PIPE)
        try:
            shutil.copyfileobj(process.stdout, zipped)
        finally:
            process.stdout.close()
            code = process.wait()
        require(code == 0, 'image export failed')


def package(args):
    revision = application.run('git', 'rev-parse', 'HEAD')
    tree = application.run('git', 'rev-parse', 'HEAD^{tree}')
    require(not application.run('git', 'status', '--porcelain'), 'clean source checkout required')
    require(re.fullmatch('[a-f0-9]{40}', revision) and re.fullmatch('[a-f0-9]{40}', tree), 'full source identity required')
    now = datetime.now(timezone.utc)
    app = inspection(args.image)
    runtime = json.loads(args.runtime.read_text())
    delivery_inventory.runtime_binding(runtime, revision, app['Id'])
    # Complete every vendor check before any tagging, export, or application packaging.
    infos = {'application': app}
    for role, vendor in VENDORS.items():
        audit_vendors.verify(args.vendor_audit/role, role, revision, now)
        delivery_inventory.image_inventory(role, vendor['id'])
        infos[role] = inspection(vendor['id'])
    args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    try:
        application.package(argparse.Namespace(image=args.image, protocol=args.protocol, inventory=args.inventory,
            os_audit=args.os_audit, output=args.output/'application'))
        records = {role:image_record(role, info, revision) for role,info in infos.items()}
        shutil.copyfile(args.runtime, args.output/'canonical-runtime.json')
        shutil.copyfile(audit_vendors.LOCK, args.output/'vendor-images.lock.json')
        for role in VENDORS:
            target = args.output/'vendors'/role
            (target/'evidence').mkdir(parents=True, mode=0o700)
            for name in ('assessment.json', *audit_vendors.FILES):
                shutil.copyfile(args.vendor_audit/role/name, target/'evidence'/name)
            subprocess.run(['docker', 'tag', records[role]['id'], records[role]['tag']], check=True)
            export_image(records[role]['tag'], target/'image.tar.gz')
        manifest = {'schema': SCHEMA, 'createdAt': now.isoformat(), 'source': {'revision': revision, 'tree': tree},
                    'images': records, 'productionApproved': False,
                    'scope': 'three-image candidate; full assurance, independent review and deployment decision remain separate',
                    'files': {name:{'sha256':digest(args.output/name), 'bytes':(args.output/name).stat().st_size}
                              for name in sorted(FILES)}}
        path = args.output/'manifest.json'
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True)+'\n')
        checksum = digest(path)
        verify(args.output, revision, checksum)
        print('Three-image manifest SHA-256: '+checksum)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
                summary.write('\nThree-image candidate `'+revision+'`\n\nManifest SHA-256: `'+checksum+'`\n')
    except BaseException:
        (args.output/'manifest.json').unlink(missing_ok=True)
        raise


def verify(directory, revision, expected_manifest, *, now=None):
    require(re.fullmatch('[a-f0-9]{40}', revision) and re.fullmatch('[a-f0-9]{64}', expected_manifest),
            'trusted full revision and manifest hash required')
    require(directory.is_absolute() and directory == directory.resolve(strict=True), 'real absolute bundle directory required')
    manifest = directory/'manifest.json'
    require(manifest.is_file() and not manifest.is_symlink() and manifest.stat().st_size <= 256*1024
            and digest(manifest) == expected_manifest, 'manifest identity mismatch')
    data = json.loads(manifest.read_text())
    require(data.get('schema') == SCHEMA and data.get('productionApproved') is False,
            'unsupported bundle or approval claim')
    require(data.get('source', {}).get('revision') == revision
            and re.fullmatch('[a-f0-9]{40}', data['source'].get('tree', '')), 'source binding mismatch')
    created = application.instant(data.get('createdAt'))
    require(-timedelta(minutes=5) <= (now or datetime.now(timezone.utc))-created <= timedelta(hours=24),
            'delivery is older than 24 hours or future-dated')
    require(set(data.get('files', {})) == FILES and set(data.get('images', {})) == ROLES,
            'complete three-image payload required')
    for name in FILES:
        path = directory/name; record = data['files'][name]
        require(path.is_file() and path == path.resolve(strict=True) and
                type(record.get('bytes')) is int and record['bytes'] > 0 and
                path.stat().st_size == record['bytes'] and digest(path) == record.get('sha256'),
                'bundle payload missing, linked or modified: '+name)
    require((directory/'vendor-images.lock.json').read_bytes() == audit_vendors.LOCK.read_bytes(),
            'bundle vendor lock differs from verifier source')
    app = application.verify(directory/'application', revision, data['files']['application/manifest.json']['sha256'])
    require(data['source'] == app['source'] and data['images']['application'] == app['image'], 'application binding mismatch')
    runtime = json.loads((directory/'canonical-runtime.json').read_text())
    delivery_inventory.runtime_binding(runtime, revision, app['image']['id'])
    for role in VENDORS:
        info = data['images'][role]
        expected = image_record(role, {'Id':VENDORS[role]['id'], 'Size':info.get('sizeBytes')}, revision)
        require(info == expected, 'vendor image manifest mismatch')
        audit_vendors.verify(directory/'vendors'/role/'evidence', role, revision, created)
    return data


def import_images(directory, data):
    # Called only after verify has checked every image and every evidence file.
    daemon = json.loads(application.run('docker', 'info', '--format', '{{json .}}'))
    require(daemon.get('OSType') == 'linux' and daemon.get('Architecture') in ('x86_64', 'amd64'),
            'local Linux amd64 Docker required')
    root = Path(daemon['DockerRootDir'])
    require(root.is_dir() and shutil.disk_usage(root).free >=
            2*sum(i['sizeBytes'] for i in data['images'].values())+512*1024**2,
            'insufficient storage for complete three-image import')
    for role in ('application', *VENDORS):
        path = directory/('application' if role == 'application' else 'vendors/'+role)/'image.tar.gz'
        subprocess.run(['docker', 'load', '--input', str(path)], check=True)
        info = inspection(data['images'][role]['tag'])
        require(info['Id'] == data['images'][role]['id'], 'loaded image differs from verified bundle')
    print('Verified three images loaded; no services started and no runtime data changed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    build = sub.add_parser('package')
    for name in ('protocol', 'inventory', 'os-audit', 'vendor-audit', 'runtime', 'output'):
        build.add_argument('--'+name, required=True, type=Path)
    build.add_argument('--image', required=True)
    for command in ('verify', 'import'):
        action = sub.add_parser(command)
        action.add_argument('--directory', required=True, type=Path)
        action.add_argument('--expected-revision', required=True)
        action.add_argument('--expected-manifest-sha256', required=True)
    args = parser.parse_args()
    if args.command == 'package':
        args.output = args.output.resolve()
        package(args)
    else:
        data = verify(args.directory, args.expected_revision, args.expected_manifest_sha256)
        if args.command == 'import': import_images(args.directory, data)
    return 0


if __name__ == '__main__': raise SystemExit(main())
