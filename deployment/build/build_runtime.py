"""Assemble the pinned upstream Wolfi packages; never compile a private OS fork."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile


def unpack(image, destination):
    """Read only the single layer of our apko-generated Linux/amd64 image."""
    with tarfile.open(image) as archive:
        manifest = json.load(archive.extractfile('manifest.json'))
        if len(manifest) != 1 or len(manifest[0]['Layers']) != 1:
            raise ValueError('expected one locked runtime layer')
        config = json.load(archive.extractfile(manifest[0]['Config']))
        if config['os'] != 'linux' or config['architecture'] != 'amd64':
            raise ValueError('unexpected runtime platform')
        layer = manifest[0]['Layers'][0]
        member = archive.getmember(layer)
        if not member.isfile() or '/' in layer or not layer.endswith('.tar.gz'):
            raise ValueError('unexpected runtime layer')
        payload = image.with_suffix('.layer.tar.gz')
        with payload.open('wb') as out:
            shutil.copyfileobj(archive.extractfile(member), out)
        if hashlib.sha256(payload.read_bytes()).hexdigest() != layer[:-7]:
            raise ValueError('runtime layer checksum mismatch')
    # Input comes from apko, with repository signatures and locked package hashes.
    # GNU tar prevents extraction through a pre-existing directory symlink.
    destination.mkdir()
    # Docker supplies these virtual trees; never create device nodes in the builder.
    subprocess.run(['tar', '-xzf', str(payload), '-C', str(destination),
                    '--exclude=dev/*', '--exclude=proc/*', '--exclude=sys/*'], check=True)
    payload.unlink()


def main():
    root = Path('/build-runtime')
    lock = json.loads((root/'wolfi-runtime.lock.json').read_text())
    if {p['architecture'] for p in lock['contents']['packages']} != {'x86_64'}:
        raise ValueError('runtime lock must cover exactly Linux amd64')
    output = root/'runtime.tar'
    subprocess.run(['/tmp/apko', 'build', 'wolfi-runtime.yaml', 'openid-runtime:locked', str(output),
                    '--lockfile', 'wolfi-runtime.lock.json', '--arch', 'x86_64', '--vcs=false',
                    '--sbom-path', str(root), '--sbom-formats', 'spdx,cyclonedx'], cwd=root, check=True)
    unpack(output, Path('/runtime'))
    evidence = Path('/runtime/usr/share/doc/openid-runtime')
    evidence.mkdir(parents=True)
    for name in ('wolfi-runtime.yaml', 'wolfi-runtime.lock.json', 'runtime-tools.lock.json',
                 'apk_inventory.py', 'Apko-LICENSE.txt'):
        shutil.copyfile(root/name, evidence/name)
    for sbom in root.glob('sbom-*.json'):
        shutil.copyfile(sbom, evidence/sbom.name)
    if not list(evidence.glob('sbom-*.json')):
        raise ValueError('runtime SBOM missing')
    output.unlink()


if __name__ == '__main__':
    main()
