"""Audit the built image's Debian packages. Findings and incomplete evidence block export."""
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / 'deployment/build/trivy.lock.json'
DB_REPOSITORY = 'ghcr.io/aquasecurity/trivy-db:2'
LIMITS = [
    'Only dpkg-managed packages in the exact pilot image are covered by this gate.',
    'Copied/built Python, Node and Temurin runtimes, embedded libraries, models, '
    'host OS, other images and deployed configuration need separate assessment.',
    'An advisory database is not exhaustive and this report is not an independent attestation.',
]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('missing timestamp')
    # Go emits nanoseconds; Python 3.9 accepts at most microseconds.
    value = re.sub(r'(\.\d{6})\d+', r'\1', value)
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('timestamp has no timezone')
    return result


def check_database(metadata, now):
    if metadata.get('Version') != 2:
        raise ValueError('unsupported database schema')
    updated = timestamp(metadata.get('UpdatedAt'))
    downloaded = timestamp(metadata.get('DownloadedAt'))
    if not -timedelta(minutes=5) <= now - updated <= timedelta(hours=24):
        raise ValueError('database too old or future-dated')
    if not -timedelta(minutes=5) <= now - downloaded <= timedelta(hours=1):
        raise ValueError('database download not current')
    if timestamp(metadata.get('NextUpdate')) <= updated:
        raise ValueError('invalid database update interval')


def installed_packages(raw):
    result = set()
    for line in raw.splitlines():
        fields = line.split('\t')
        if len(fields) != 4 or not all(fields):
            raise ValueError('invalid dpkg inventory')
        name, version, arch, status = fields
        # This minimal image must not contain partly installed/removed packages.
        if status != 'installed' or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]+', name):
            raise ValueError('unexpected package state or name')
        if arch not in ('amd64', 'all') or any(c.isspace() for c in version):
            raise ValueError('unexpected package version or architecture')
        item = (name, version, arch)
        if item in result or any(p[0] == name and p[2] == arch for p in result):
            raise ValueError('duplicate package')
        result.add(item)
    if not result:
        raise ValueError('empty package inventory')
    return result


def package_version(package):
    # Trivy's dpkg analyzer separates epoch, upstream version and Debian revision.
    # Reconstruct the complete binary version; never discard Debian security revisions.
    version = package['Version']
    release = package.get('Release', '')
    epoch = package.get('Epoch', 0)
    if not isinstance(version, str) or not version or not isinstance(release, str):
        raise ValueError('invalid scanner package version')
    if type(epoch) is not int or epoch < 0:
        raise ValueError('invalid package epoch')
    if release:
        version += '-' + release
    if epoch:
        version = str(epoch) + ':' + version
    return version


def assess(scan, installed, image_id, version, now):
    if scan.get('SchemaVersion') != 2 or scan.get('ArtifactType') != 'container_image':
        raise ValueError('unsupported scanner report')
    if scan.get('Trivy', {}).get('Version') != version:
        raise ValueError('wrong scanner version')
    if not -timedelta(minutes=5) <= now - timestamp(scan.get('CreatedAt')) <= timedelta(hours=1):
        raise ValueError('stale scanner report')
    metadata = scan['Metadata']
    if metadata.get('ImageID') != image_id:
        raise ValueError('report belongs to another image')
    system = metadata['OS']
    if system.get('Family') != 'debian' or not re.fullmatch(r'13(?:\.\d+)?', system.get('Name', '')):
        raise ValueError('unexpected or unidentified operating system')
    if system.get('EOSL', False) is not False:
        raise ValueError('operating system outside support')
    results = scan['Results']
    if not isinstance(results, list) or len(results) != 1:
        raise ValueError('missing or unexpected scan targets')
    result = results[0]
    if result.get('Class') != 'os-pkgs' or result.get('Type') != 'debian':
        raise ValueError('missing Debian assessment')
    packages = result['Packages']
    if not isinstance(packages, list) or not packages:
        raise ValueError('missing package coverage')
    found = [(p['Name'], package_version(p), p['Arch']) for p in packages]
    if len(found) != len(set(found)) or set(found) != installed:
        raise ValueError('scanner and installed package inventories differ')
    if result.get('ExperimentalModifiedFindings') or result.get('Misconfigurations'):
        raise ValueError('unexpected suppressed/modified findings')
    findings = result.get('Vulnerabilities', [])
    if not isinstance(findings, list):
        raise ValueError('invalid vulnerability results')
    counts = Counter()
    for item in findings:
        if not isinstance(item.get('VulnerabilityID'), str) or not item['VulnerabilityID']:
            raise ValueError('missing vulnerability identity')
        if (item.get('PkgName'), item.get('InstalledVersion')) not in {(p[0], p[1]) for p in installed}:
            raise ValueError('finding for unidentified package')
        severity = item.get('Severity')
        if severity not in ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            raise ValueError('invalid severity')
        counts[severity] += 1
    return {'operatingSystem': dict(system), 'packageCount': len(installed), 'findingCount': len(findings),
            'uniqueAdvisoryCount': len({v['VulnerabilityID'] for v in findings}),
            'severityCounts': dict(sorted(counts.items()))}


def fetch_locked(item):
    if not item['url'].startswith('https://github.com/aquasecurity/trivy/releases/download/v'):
        raise ValueError('unexpected scanner distribution source')
    with urllib.request.urlopen(item['url'], timeout=60) as response:
        raw = response.read(item['maxBytes'] + 1)
    if len(raw) > item['maxBytes'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
        raise ValueError('scanner distribution checksum mismatch')
    return raw


def install(lock, work, output):
    raw = fetch_locked(lock['linuxAmd64'])
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        # Do not extract paths, symlinks, or bundled scripts from the archive.
        members = [m for m in archive.getmembers() if m.name == 'trivy']
        if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size <= 256 * 1024 * 1024:
            raise ValueError('unexpected scanner archive')
        binary = work / 'trivy'
        binary.write_bytes(archive.extractfile(members[0]).read())
        binary.chmod(0o700)
    (output / 'scanner-sbom.json').write_bytes(fetch_locked(lock['sbom']))
    return binary


def audit(image_id, output):
    output.mkdir(parents=True, exist_ok=False)
    report = {'format': 1, 'complete': False, 'passed': False,
              'checkedAt': datetime.now(timezone.utc).isoformat(),
              'imageID': image_id, 'limits': LIMITS, 'databaseRepository': DB_REPOSITORY,
              'policy': 'Every reported vulnerability blocks; no severity/status exceptions.'}
    code = 2
    try:
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
            raise ValueError('exact local image ID required')
        if platform.system() != 'Linux' or platform.machine() != 'x86_64':
            raise ValueError('requires isolated Linux amd64 build runner')
        report['sourceRevision'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        lock = json.loads(LOCK.read_text())
        report['scannerLockSha256'] = digest(LOCK)
        report['scannerVersion'] = lock['version']
        save(output / 'scanner-lock.json', lock)
        raw = subprocess.check_output([
            'docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--pids-limit', '32', '--memory', '128m',
            '--cpus', '1', '--entrypoint', 'dpkg-query', image_id, '-W',
            '-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'], text=True, timeout=60)
        (output / 'system-packages.tsv').write_text(raw)
        installed = installed_packages(raw)
        with tempfile.TemporaryDirectory(prefix='openid-os-audit-') as directory:
            work = Path(directory)
            binary = install(lock, work, output)
            env = {k: v for k, v in os.environ.items() if not k.startswith('TRIVY_')}
            prefix = [str(binary), '--config', '', '--cache-dir', str(work / 'cache'), '--timeout', '8m']
            scan_flags = ['image', '--disable-telemetry', '--skip-version-check', '--no-progress',
                          '--module-dir', str(work / 'modules'), '--db-repository', DB_REPOSITORY]
            subprocess.run(prefix + scan_flags + ['--download-db-only'], env=env, cwd=work, check=True, timeout=540)
            database = work / 'cache/db'
            metadata = json.loads((database / 'metadata.json').read_text())
            save(output / 'database-metadata.json', metadata)
            check_database(metadata, datetime.now(timezone.utc))
            report['databaseSha256'] = digest(database / 'trivy.db')
            subprocess.run(prefix + scan_flags + [
                '--skip-db-update', '--skip-java-db-update', '--offline-scan', '--image-src', 'docker',
                '--scanners', 'vuln', '--pkg-types', 'os', '--ignorefile', '', '--ignore-unfixed=false',
                '--ignore-status', '', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
                '--list-all-pkgs', '--show-suppressed', '--format', 'json', '--exit-code', '0',
                '--output', str(output / 'trivy-os.json'), image_id], env=env, cwd=work, check=True, timeout=540)
            subprocess.run(prefix + ['convert', '--format', 'cyclonedx', '--output',
                str(output / 'os-sbom.cdx.json'), str(output / 'trivy-os.json')],
                env=env, cwd=work, check=True, timeout=60)
            report.update(assess(json.loads((output / 'trivy-os.json').read_text()), installed,
                                 image_id, lock['version'], datetime.now(timezone.utc)))
            report['complete'] = True
            report['passed'] = report['findingCount'] == 0
            code = 0 if report['passed'] else 1
    except Exception as error:
        report['errorType'] = type(error).__name__
        # Fixed validation errors carry no credentials or service response bodies.
        if isinstance(error, ValueError):
            report['error'] = str(error)[:200]
    finally:
        report['files'] = {p.name: digest(p) for p in sorted(output.iterdir()) if p.is_file()}
        save(output / 'assessment.json', report)
    print(f"Image OS audit: complete={report['complete']}; passed={report['passed']}; exit={code}")
    return code


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    raise SystemExit(audit(args.image, args.output.resolve()))
