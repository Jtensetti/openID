"""Use a pinned BuildKit Docker exporter, including normalized layer timestamps."""
from contextlib import contextmanager
from pathlib import Path
import subprocess
import tempfile
import uuid

BUILDER_IMAGE = 'moby/buildkit:v0.33.1@sha256:98cc6a3fc46220d00f8224ae483f3274fc874e9be8d7dd1e2e2c5481209228b5'


@contextmanager
def builder():
    name = 'tjipp-vendor-' + uuid.uuid4().hex
    subprocess.run(['docker', 'buildx', 'create', '--name', name, '--driver',
                    'docker-container', '--driver-opt', 'image=' + BUILDER_IMAGE], check=True)
    try:
        yield name
    finally:
        subprocess.run(['docker', 'buildx', 'rm', name], check=True)


def export_image(context, recipe, tag, epoch):
    # The Docker Engine's default Moby exporter does not rewrite layer times.
    # An explicit container driver and Docker archive exporter are required.
    with builder() as name, tempfile.TemporaryDirectory(prefix='vendor-image-') as work:
        archive = Path(work) / 'image.tar'
        subprocess.run(['docker', 'buildx', 'build', '--builder', name, '--platform',
                        'linux/amd64', '--build-arg', 'SOURCE_DATE_EPOCH=' + epoch,
                        '--provenance=false', '--output',
                        'type=docker,rewrite-timestamp=true,dest=' + str(archive),
                        '--file', str(context / recipe), '--tag', tag, str(context)], check=True)
        subprocess.run(['docker', 'load', '--input', str(archive)], check=True)
