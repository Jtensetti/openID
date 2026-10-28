"""Run bounded terminal and linkage probes on extracted candidate packages."""
import json
import os
from pathlib import Path
import re
import subprocess

from bootstrap import sha


def probe(package_directory, packages, directory, evidence, build_env, lock):
    if os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError('ncurses compatibility probe requires the ordinary builder user')
    directory.mkdir()
    log = evidence / 'compatibility.log'
    root = directory / 'packages'
    root.mkdir()
    env = dict(build_env)

    def command(args, *, cwd=None, limit=1024 * 1024, expected=(0,)):
        result = subprocess.run([str(arg) for arg in args], cwd=cwd, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=30)
        with log.open('ab') as stream:
            stream.write((json.dumps({'argv': [str(arg) for arg in args],
                                      'exit': result.returncode}) + '\n').encode())
            stream.write(result.stdout[:limit] + result.stderr[:limit] + b'\n')
        if (result.returncode not in expected or len(result.stdout) > limit
                or len(result.stderr) > limit):
            raise ValueError('unexpected ncurses probe outcome: ' + str(args[0]))
        return result.stdout.decode('utf-8', errors='replace'), result.returncode

    required = set(lock['requiredPackages'])
    selected = {p['Package']: p for p in packages if p['Package'] in required}
    if set(selected) != required:
        raise ValueError('incomplete ncurses package group before extraction')
    for name in sorted(required):
        item = selected[name]
        path = package_directory / item['filename']
        if path.is_symlink() or not path.is_file() or sha(path.read_bytes()) != item['sha256']:
            raise ValueError('ncurses package changed before compatibility probe')
        command(['dpkg-deb', '--extract', path, root])

    libraries = root / 'usr/lib/x86_64-linux-gnu'
    binaries = root / 'usr/bin'
    actual_libraries = {}
    for name in ('libtinfo.so.6', 'libncursesw.so.6'):
        library = (libraries / name).resolve(strict=True)
        if library.parent != libraries.resolve(strict=True) or not library.is_file():
            raise ValueError('ncurses library resolves outside extracted package directory')
        soname, _ = command(['readelf', '-d', library])
        if not re.search(r'\(SONAME\).*\[' + re.escape(name) + r'\]', soname):
            raise ValueError('ncurses library SONAME differs')
        actual_libraries[name] = {'sha256': sha(library.read_bytes()), 'path': str(library)}
    env['LD_LIBRARY_PATH'] = str(libraries)

    linkage = {}
    for name in ('tic', 'infocmp'):
        binary = (binaries / name).resolve(strict=True)
        if binary.parent != binaries.resolve(strict=True) or not binary.is_file():
            raise ValueError('ncurses command resolves outside extracted package directory')
        output, _ = command(['ldd', binary])
        matches = re.findall(r'^\s*libtinfo\.so\.6 => (\S+) \(', output, re.M)
        if (len(matches) != 1 or Path(matches[0]).resolve(strict=True)
                != (libraries / 'libtinfo.so.6').resolve(strict=True)):
            raise ValueError('ncurses command did not resolve candidate libtinfo')
        version = command([binary, '-V'])[0].strip()
        if '6.6' not in version:
            raise ValueError('ncurses command reports a different upstream version')
        linkage[name] = {'sha256': sha(binary.read_bytes()), 'version': version,
                         'candidateTinfo': True}

    database = directory / 'terminfo'
    database.mkdir()
    env['TERMINFO'] = str(database)
    source = directory / 'generated.src'
    source.write_text('openid-probe|openID generated terminal,\n'
                      '\tam, cols#80, lines#24,\n'
                      '\tclear=\\E[H\\E[2J,\n'
                      '\tis2=' + ('A' * 2048) + ',\n')
    command([binaries / 'tic', '-x', '-o', database, source])
    compiled = database / 'o/openid-probe'
    if not compiled.is_file() or compiled.is_symlink():
        raise ValueError('generated terminfo entry was not compiled')
    ordinary, _ = command([binaries / 'infocmp', '-x', 'openid-probe'])
    analyzed, _ = command([binaries / 'infocmp', '-x', '-i', 'openid-probe'])
    termcap, _ = command([binaries / 'infocmp', '-C', 'openid-probe'])
    if ('openid-probe' not in ordinary or 'clear=' not in ordinary
            or 'openid-probe' not in analyzed or 'openid-probe' not in termcap):
        raise ValueError('ncurses terminfo or termcap round-trip differs')
    # Exercise the termcap parsing path separately from infocmp's output path.
    cap_source = directory / 'generated.termcap'
    cap_source.write_text('openid-cap|openID termcap fixture:co#80:li#24:'
                          'cl=\\E[H\\E[2J:is=' + ('B' * 2048) + ':\n')
    command([binaries / 'tic', '-x', '-o', database, cap_source])
    if not (database / 'o/openid-cap').is_file():
        raise ValueError('generated termcap entry was not compiled')
    converted, _ = command([binaries / 'infocmp', '-C', 'openid-cap'])
    if 'openid-cap' not in converted:
        raise ValueError('termcap parse or conversion failed')

    # Reporter input shape for CVE-2025-6141: a 4109-byte termcap entry.
    # Errors for malformed syntax are acceptable; signals and timeouts are not.
    long_cap = directory / 'long-termcap.in'
    long_cap.write_bytes(b'0:im=m' + b'0' * 4095 + b':ko=im,0')
    _, termcap_boundary_exit = command([binaries / 'tic', '-x', '-o', database, long_cap],
                                       expected=(0, 1))

    # Reporter input shape for CVE-2025-69720: an SGR CSI parameter list
    # beyond infocmp's historical 4096-byte stack buffer.
    long_sgr = directory / 'long-sgr.src'
    long_sgr.write_text('openid-long-sgr|generated SGR boundary,\n'
                        '\tam, mir, msgr,\n'
                        '\tsgr=\\E[' + ('1234567;' * 800) + 'm,\n')
    command([binaries / 'tic', '-x', '-o', database, long_sgr])
    if not (database / 'o/openid-long-sgr').is_file():
        raise ValueError('long SGR terminfo entry was not compiled')
    command([binaries / 'infocmp', '-i', 'openid-long-sgr'])

    report = {'passed': True, 'uid': os.getuid(), 'euid': os.geteuid(),
              'probedPackages': {p['filename']: p['sha256'] for p in selected.values()},
              'candidateLibraries': actual_libraries, 'candidateCommands': linkage,
              'generatedTerminfoSHA256': sha(compiled.read_bytes()),
              'terminfoInfocmpAndAnalyzeString': True,
              'terminfoToTermcap': True, 'generatedTermcapParse': True,
              'reporterShapeBoundaries': {'longTermcapInputBytes': len(long_cap.read_bytes()),
                                          'longTermcapExit': termcap_boundary_exit,
                                          'longSgrParameters': 800,
                                          'infocmpLongSgrExit': 0},
              'limits': ['Reporter-shape boundaries and ordinary-user paths only; no fuzzing, sanitizers or full ABI test.',
                         'A noncrashing hardened binary is not proof of memory safety or non-applicability.',
                         'Packages are extracted, not installed in the builder or application image.',
                         'Application/protocol tests, complete terminal corpus and independent admission remain required.']}
    (evidence / 'compatibility.json').write_text(json.dumps(report, indent=2) + '\n')
    return report
