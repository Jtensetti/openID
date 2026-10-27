"""Build an explicitly selected native-code candidate, offline inside Linux CI."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args, log):
    with log.open('w') as stream:
        result = subprocess.run(args, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        print(log.read_text()[-24000:], flush=True)
        result.check_returncode()


def main():
    assert platform.system() == 'Linux' and platform.machine() == 'x86_64'
    assert sys.version_info[:3] == (3, 12, 16)
    lock = json.loads(Path('/inputs/native.lock.json').read_text())
    output = Path('/native')
    evidence = output/'evidence'
    evidence.mkdir(parents=True)
    sources = {}
    for item in lock['archives']:
        archive = Path('/inputs')/item['filename']
        assert digest(archive) == item['sha256']
        assert archive.stat().st_size == item['bytes']
        directory = Path('/work')/item['name']
        directory.mkdir(parents=True)
        with tarfile.open(archive) as source:
            source.extractall(directory, filter='data')
        children = list(directory.iterdir())
        assert len(children) == 1 and children[0].is_dir()
        sources[item['name']] = children[0]
        for relative, expected in item['licenseFiles'].items():
            original = children[0]/relative
            assert digest(original) == expected, relative
            destination = evidence/'licenses'/item['name']/relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, destination)

    numpy_wheel = Path('/inputs/numpy.whl')
    assert digest(numpy_wheel) == lock['numpy']['sha256']
    numpy_directory = Path('/build-numpy')
    numpy_directory.mkdir()
    with zipfile.ZipFile(numpy_wheel) as wheel:
        for item in wheel.infolist():
            assert not item.filename.startswith('/') and '..' not in Path(item.filename).parts
            assert (item.external_attr >> 16) & 0o170000 != 0o120000
        wheel.extractall(numpy_directory)
    sys.path.insert(0, str(numpy_directory))
    os.environ['PYTHONPATH'] = str(numpy_directory)
    import numpy
    assert numpy.__version__ == lock['numpy']['version']
    cmake = str(sources['cmake']/'bin/cmake')
    ctest = str(sources['cmake']/'bin/ctest')
    common = ['-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_POSITION_INDEPENDENT_CODE=ON',
              '-DCMAKE_INSTALL_PREFIX=/native-deps', '-DCMAKE_INSTALL_LIBDIR=lib',
              '-DCMAKE_POLICY_VERSION_MINIMUM=3.10', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON']
    builds = {}
    for name in ('libjpeg-turbo', 'openjpeg', 'opencv'):
        build = Path('/work')/(name+'-build')
        options = common + lock['cmakeOptions'][name]
        if name == 'opencv':
            options += ['-DPYTHON3_EXECUTABLE='+sys.executable,
                        '-DPYTHON3_INCLUDE_DIR=/usr/local/include/python3.12',
                        '-DPYTHON3_LIBRARY=/usr/local/lib/libpython3.12.so',
                        '-DPYTHON3_NUMPY_INCLUDE_DIRS='+numpy.get_include()]
        command = [cmake, '-S', str(sources[name]), '-B', str(build), *options]
        run(command, evidence/(name+'-configure.log'))
        builds[name] = command
        run([cmake, '--build', str(build), '--parallel', '2'], evidence/(name+'-build.log'))
        if name == 'libjpeg-turbo':
            run([ctest, '--test-dir', str(build), '--output-on-failure', '--no-tests=error',
                 '--parallel', '2'], evidence/(name+'-tests.log'))
        if name == 'openjpeg':
            # Upstream generated-data unit test; no external image corpus/download.
            run([str(build/'bin/test_sparse_array')], evidence/(name+'-sparse-array-test.log'))
        install = [cmake, '--install', str(build)]
        if name == 'opencv':
            install += ['--component', 'python']
        run(install, evidence/(name+'-install.log'))
        if name == 'openjpeg':
            # Unmodified upstream issue-1558 regression creates its own image.
            # Build only this test, without the external conformance corpus/tools.
            test_binary = build/'test_tile_part_interleaved'
            test_command = ['cc', '-O2', '-I/native-deps/include/openjpeg-2.5',
                            str(sources[name]/'tests/test_tile_part_interleaved.c'),
                            '/native-deps/lib/libopenjp2.a', '-lm', '-pthread',
                            '-o', str(test_binary)]
            builds['openjpeg-interleaved-test'] = test_command
            run(test_command, evidence/'openjpeg-interleaved-test-build.log')
            run([str(test_binary)], evidence/'openjpeg-interleaved-test.log')
        shutil.copyfile(build/'CMakeCache.txt', evidence/(name+'-CMakeCache.txt'))
        shutil.copyfile(build/'compile_commands.json', evidence/(name+'-compile-commands.json'))

    binaries = list((output/'python').glob('cv2*.so'))
    assert len(binaries) == 1
    binary = binaries[0]
    subprocess.run(['strip', '--strip-unneeded', str(binary)], check=True)
    dynamic = subprocess.check_output(['readelf', '-dW', str(binary)], text=True)
    needed = re.findall(r'\(NEEDED\).*\[([^]]+)\]', dynamic)
    allowed = {'libz.so.1', 'libstdc++.so.6', 'libm.so.6', 'libgcc_s.so.1',
               'libc.so.6', 'libpthread.so.0', 'libdl.so.2', 'librt.so.1'}
    assert needed and set(needed) <= allowed, needed
    assert 'TEXTREL' not in dynamic and 'BIND_NOW' in dynamic
    headers = subprocess.check_output(['readelf', '-lW', str(binary)], text=True)
    stack = next(line for line in headers.splitlines() if 'GNU_STACK' in line)
    assert 'RWE' not in stack and 'GNU_RELRO' in headers
    (evidence/'elf-dynamic.txt').write_text(dynamic)
    (evidence/'elf-program-headers.txt').write_text(headers)
    (evidence/'commands.json').write_text(json.dumps(builds, indent=2)+'\n')
    (evidence/'native.lock.json').write_text(json.dumps(lock, indent=2)+'\n')
    components = []
    for item in lock['archives']:
        components.append({'type': 'application' if item['name'] == 'cmake' else 'library',
                           'bom-ref': 'input:'+item['name'], 'name': item['name'],
                           'version': item['version'],
                           'hashes': [{'alg': 'SHA-256', 'content': item['sha256']}],
                           'licenses': [{'license': {'name': item['license']}}],
                           'externalReferences': [{'type': 'distribution', 'url': item['url']}],
                           'properties': [{'name': 'openid:upstream-commit', 'value': item['commit']},
                                          {'name': 'openid:hash-scope', 'value': 'downloaded input archive'}]})
    components.append({'type': 'library', 'bom-ref': 'embedded:protobuf', 'name': 'protobuf',
                       'version': '3.19.1', 'licenses': [{'license': {'id': 'BSD-3-Clause'}}],
                       'properties': [{'name': 'openid:source', 'value': 'OpenCV 4.14.0 3rdparty/protobuf'}]})
    sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'component': {'type': 'library', 'bom-ref': 'native:candidate',
                         'name': 'openid-opencv-candidate', 'version': '4.14.0+minimal.1',
                         'hashes': [{'alg': 'SHA-256', 'content': digest(binary)}]},
                         'properties': [{'name': 'openid:scope', 'value':
                         'Native candidate and input archives only. System libraries, CMake embedded components, '
                         'JPEG test tooling and full application require separate inventories; not complete coverage.'}]},
            'components': components,
            'dependencies': [{'ref': 'native:candidate', 'dependsOn':
                              ['input:opencv', 'input:libjpeg-turbo', 'input:openjpeg', 'embedded:protobuf']}]}
    (evidence/'sbom.cdx.json').write_text(json.dumps(sbom, indent=2)+'\n')
    (evidence/'BUILD-NOTICE.txt').write_text(
        'Experimental OpenCV build; not an upstream Python wheel or a release approval.\n'
        'Unmodified upstream source, selected CMake features; JPEG SIMD disabled.\n'
        'This software is based in part on the work of the Independent JPEG Group.\n'
        'The reference wheel remains in this comparison image; no image-wide removal claim.\n')
    manifest = {'format': 1, 'candidateOnly': True, 'dynamicLibraries': needed,
                'sourceComponents': lock['components'],
                'files': {str(p.relative_to(output)): digest(p)
                          for p in sorted(output.rglob('*')) if p.is_file()},
                'limits': ['No full native-code advisory coverage or independent attestation.',
                           'Protobuf 3.19.1 remains embedded; system libraries remain separately assessed.']}
    (evidence/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print('PASS: offline native build, JPEG regressions, OpenJPEG generated tests and ELF policy')


if __name__ == '__main__':
    main()
