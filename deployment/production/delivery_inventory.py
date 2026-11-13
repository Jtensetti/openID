"""Inventory the exact three runtime images; do not export or approve a release."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

from contract import IDENTITIES, VENDORS

_spec = importlib.util.spec_from_file_location('production_image_bundle', Path(__file__).resolve().parents[1] / 'image_bundle.py')
image_bundle = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(image_bundle)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'tjipp-three-image-inventory-v1'
CHECKS = {
    'actual_service_uid_gid_mount_capability_and_dual_stack_imds_isolation',
    'closed_registration_and_separate_api_roles',
    'explicit_registration_notice_paired_session_and_required_production_attestation',
    'actual_controller_activation_atomic_outbox_role_scoped_sqs_retry_and_ack',
    'actual_pg_bridge_java_saml_signed_consent_and_session',
    'actual_pg_bridge_java_oidc_signed_consent_and_session',
    'actual_separate_sign_message_sad_and_test_ca_pades',
    'scoped_periodic_self_renewal_and_atomic_replacement_reject_wrong_role_and_expiry',
    'same_configuration_data_and_keys_after_service_restart',
    'sealed_openbao_and_external_revocation_survive_restart_without_local_active_fallback',
    'synthetic_identity_absent_from_service_logs',
}
PROBE = r'''printf 'os-release\000'
cat /etc/os-release
printf '\000manager\000'
if command -v dpkg-query >/dev/null 2>&1; then
  printf 'dpkg\000packages\000'
  dpkg-query -W -f '${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'
elif test -r /lib/apk/db/installed; then
  printf 'apk\000packages\000'
  cat /lib/apk/db/installed
else
  exit 65
fi
printf '\000versions\000'
'''
VERSIONS = {'application': 'python --version\nnode --version\njava -version 2>&1\n',
            'postgres': 'postgres --version\n', 'openbao': 'bao version\n'}
APPLICATION_PROBE = r'''from pathlib import Path
import subprocess
import sys
sys.stdout.write('os-release\0' + Path('/etc/os-release').read_text() + '\0manager\0dpkg\0packages\0')
sys.stdout.flush()
subprocess.run(['dpkg-query', '-W', '-f', '${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'], check=True)
sys.stdout.write('\0versions\0')
sys.stdout.flush()
for args in [['python', '--version'], ['node', '--version'], ['java', '-version']]:
    subprocess.run(args, check=True, stderr=subprocess.STDOUT)
'''


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def command(args):
    # No environment, credential directory, Docker socket or runtime volume is mounted.
    with tempfile.TemporaryFile() as output:
        try:
            subprocess.run(args, cwd=ROOT, stdout=output, stderr=subprocess.DEVNULL,
                           check=True, timeout=120)
        except (OSError, subprocess.SubprocessError):
            raise ValueError('inventory command failed or timed out') from None
        output.seek(0)
        raw = output.read(16 * 1024 * 1024 + 1)
    require(len(raw) <= 16 * 1024 * 1024, 'inventory output exceeds limit')
    return raw


def runtime_binding(report, revision, image):
    require(isinstance(report, dict), 'canonical runtime report object required')
    require(re.fullmatch(r'[a-f0-9]{40}', revision or '') is not None, 'full source revision required')
    require(re.fullmatch(r'sha256:[a-f0-9]{64}', image or '') is not None, 'exact application image required')
    require(report.get('schema') == 'tjipp-production-composition-v1'
            and report.get('status') == 'PASS' and report.get('phase') == 'complete'
            and report.get('synthetic') is True and report.get('productionApproved') is False
            and report.get('sourceRevision') == revision and report.get('applicationImage') == image,
            'complete canonical runtime evidence for this source and application image required')
    checks = report.get('checks', [])
    require(isinstance(checks, list) and all(isinstance(c, str) for c in checks)
            and len(checks) == len(CHECKS) and set(checks) == CHECKS,
            'canonical runtime checks missing, duplicated or changed')
    require(report.get('vendorImages') == {k: v['id'] for k, v in VENDORS.items()},
            'canonical runtime vendor images differ from the locked contract')
    boundaries = report.get('serviceBoundaries', [])
    require(isinstance(boundaries, list) and all(isinstance(b, dict) for b in boundaries)
            and len(boundaries) == len(IDENTITIES)
            and {b.get('service') for b in boundaries} == set(IDENTITIES),
            'complete actual service boundaries required')
    for boundary in boundaries:
        name = boundary['service']
        uid, gid = map(int, IDENTITIES[name].split(':'))
        imds = 'trusted_rotator' if name == 'credential-rotator' else 'blocked'
        require(boundary.get('actual_container_inspected') is True
                and (boundary.get('uid'), boundary.get('gid')) == (uid, gid)
                and boundary.get('imds_ipv4') == boundary.get('imds_ipv6') == imds,
                'actual service identity or metadata isolation mismatch')
    require(len({image, *[v['id'] for v in VENDORS.values()]}) == 3, 'three distinct images required')


def installed(manager, value):
    packages = []
    if manager == 'dpkg':
        for line in value.splitlines():
            fields = line.split('\t')
            require(len(fields) == 4, 'malformed dpkg inventory')
            if fields[3] != 'installed':
                # dpkg also lists residual configuration records, which are not installed packages.
                require(fields[3] in ('config-files', 'not-installed'), 'partial package installation')
                continue
            packages.append(dict(zip(('name', 'version', 'architecture'), fields[:3])))
    elif manager == 'apk':
        for record in value.strip().split('\n\n'):
            fields = {}
            for line in record.splitlines():
                if line[:2] in ('P:', 'V:', 'A:'):
                    require(line[0] not in fields, 'duplicate APK package field')
                    fields[line[0]] = line[2:]
            require(set(fields) == {'P', 'V', 'A'}, 'partial APK package record')
            packages.append({'name': fields['P'], 'version': fields['V'], 'architecture': fields['A']})
    else:
        raise ValueError('unsupported package inventory format')
    require(packages and all(all(isinstance(v, str) and v.strip() == v and v for v in p.values())
                             for p in packages), 'empty or invalid installed package inventory')
    require(len({(p['name'], p['architecture']) for p in packages}) == len(packages),
            'duplicate installed package identity')
    return sorted(packages, key=lambda p: (p['name'], p['architecture']))


def parse_inventory(raw):
    parts = raw.decode('utf-8').split('\0')
    require(len(parts) == 8 and parts[::2] == ['os-release', 'manager', 'packages', 'versions'],
            'incomplete image inventory sections')
    release = {}
    for line in parts[1].splitlines():
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        require(sep and re.fullmatch(r'[A-Z_]+', key) and key not in release, 'invalid OS release')
        parsed = shlex.split(value)  # Parse text only; never source the image's os-release as shell code.
        require(len(parsed) == 1, 'invalid OS release value')
        release[key] = parsed[0]
    require(release.get('ID') and release.get('VERSION_ID'), 'OS identity and version required')
    versions = parts[7].strip().splitlines()
    require(versions and all(line.strip() for line in versions), 'missing binary versions')
    return {'osRelease': release, 'packageManager': parts[3],
            'packages': installed(parts[3], parts[5]), 'binaryVersions': versions,
            'probeOutputSha256': digest(raw)}


def image_inventory(role, image_id, runner=command):
    source = VENDORS[role]['source'] if role in VENDORS else image_id
    if role in VENDORS:
        require(image_id == VENDORS[role]['id'], 'vendor output differs from the source lock')
    derived = role in VENDORS and 'build' in VENDORS[role]
    if derived:
        from vendor_images import check_inputs
        check_inputs(role)
    infos = json.loads(runner(['docker', 'image', 'inspect', image_id if derived else source]))
    require(isinstance(infos, list) and len(infos) == 1, 'one locally resolved image required')
    info = infos[0]
    require(isinstance(info, dict), 'image inspection object required')
    require(info.get('Id') == image_id, 'resolved source image ID mismatch')
    require(info.get('Os') == 'linux' and info.get('Architecture') == 'amd64'
            and info.get('Variant') in (None, ''), 'linux/amd64 image required')
    if role in VENDORS and not derived:
        repository, sha = source.split('@')
        repository = repository.rsplit(':', 1)[0]
        # Docker Hub may report either a short or fully qualified official repository.
        aliases = {repository, 'docker.io/library/' + repository} if '/' not in repository else {repository}
        require(any(ref == repo + '@' + sha for repo in aliases for ref in info.get('RepoDigests', [])),
                'locked registry repository/digest not present in local daemon resolution')
    invocation = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
                  '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '64',
                  '--memory', '256m', '--memory-swap', '256m', '--cpus', '1',
                  '--tmpfs', '/tmp:size=16m,mode=1777', '--entrypoint']
    # The hardened application has no shell. Use its existing Python runtime.
    invocation += ['python', image_id, '-c', APPLICATION_PROBE] if role == 'application' else [
        '/bin/sh', image_id, '-eu', '-c', PROBE + VERSIONS[role]]
    raw = runner(invocation)
    return {'role': role, 'source': source, 'imageID': image_id, 'platform': 'linux/amd64',
            'sourceBinding': 'locked_derived_image_and_build_inputs' if derived else 'local_docker_daemon_resolution',
            'inventoryComplete': True,
            **parse_inventory(raw)}


def application_assessment(directory, image_id, revision):
    path = directory / 'assessment.json'
    if not path.is_file():
        return {'state': 'missing', 'reason': 'application OS assessment is absent'}
    try:
        value = json.loads(path.read_text())
        require(isinstance(value, dict), 'application assessment object required')
        require(value.get('imageID') == image_id and value.get('sourceRevision') == revision,
                'application assessment image/source mismatch')
        if value.get('complete') is not True:
            return {'state': 'incomplete', 'reason': 'application OS assessment is incomplete',
                    'assessmentSha256': digest(path.read_bytes())}
        if value.get('passed') is not True:
            return {'state': 'failed', 'reason': 'application OS assessment did not pass',
                    'assessmentSha256': digest(path.read_bytes())}
        # Reuse the existing application verifier, including scan, policy, hashes and freshness.
        # Its Debian/Python rules must never be applied to the vendor images.
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            for name in image_bundle.OS_FILES:
                shutil.copyfile(directory / name, target / ('os-' + name))
            image_bundle.os_passed(target, image_id, revision, datetime.now(timezone.utc).isoformat())
        return {'state': 'passed', 'assessmentSha256': digest(path.read_bytes())}
    except (ValueError, OSError, TypeError, KeyError):
        return {'state': 'rejected', 'reason': 'application evidence failed existing verification'}


def vendor_assessment(directory, role, revision):
    from audit_vendors import verify
    path = directory / role / 'assessment.json'
    if not path.is_file():
        return {'state': 'missing', 'reason': 'component-specific vendor assessment is absent'}
    try:
        value = json.loads(path.read_text())
        require(value.get('imageID') == VENDORS[role]['id'] and value.get('sourceRevision') == revision,
                'vendor source mismatch')
        if value.get('complete') is not True:
            return {'state': 'incomplete', 'reason': 'vendor assessment is incomplete'}
        if value.get('passed') is not True:
            return {'state': 'failed', 'reason': 'vendor findings remain unresolved',
                    'unresolvedCount': value.get('unresolvedCount')}
        verify(directory / role, role, revision, datetime.now(timezone.utc))
        return {'state': 'passed', 'assessmentSha256': digest(path.read_bytes())}
    except (ValueError, OSError, TypeError, KeyError):
        return {'state': 'rejected', 'reason': 'vendor evidence verification failed'}


def collect(runtime_raw, revision, tree, image, audit, runner=command, vendor_audit=None):
    runtime = json.loads(runtime_raw)
    runtime_binding(runtime, revision, image)
    require(re.fullmatch(r'[a-f0-9]{40}', tree or '') is not None, 'full source tree required')
    images = []
    for role, image_id in [('application', image), *[(k, v['id']) for k, v in VENDORS.items()]]:
        try:
            entry = image_inventory(role, image_id, runner)
        except (ValueError, OSError, TypeError, KeyError, UnicodeError) as error:
            entry = {'role': role, 'imageID': image_id, 'inventoryComplete': False,
                     'source': VENDORS[role]['source'] if role in VENDORS else image_id,
                     'error': str(error)[:256] if isinstance(error, ValueError) else 'invalid image inventory metadata'}
        entry['assessment'] = (application_assessment(audit, image_id, revision) if role == 'application'
                               else vendor_assessment(vendor_audit or audit / 'vendors', role, revision))
        images.append(entry)
    complete = all(i['inventoryComplete'] for i in images)
    blockers = [{'role': i['role'], 'kind': 'inventory'} for i in images if not i['inventoryComplete']]
    blockers += [{'role': i['role'], 'kind': 'assessment', **i['assessment']}
                 for i in images if i['assessment']['state'] != 'passed']
    ready = complete and not blockers
    return {'schema': SCHEMA, 'createdAt': datetime.now(timezone.utc).isoformat(),
            'sourceRevision': revision, 'sourceTree': tree, 'runtimeEvidenceSha256': digest(runtime_raw),
            'canonicalRuntimeChecks': sorted(CHECKS), 'images': images, 'inventoryComplete': complete,
            'status': 'INVENTORIED' if complete else 'INCOMPLETE', 'releaseReady': ready,
            'releaseStatus': 'READY_FOR_PACKAGING' if ready else 'BLOCKED', 'blockers': blockers,
            'limits': ['No image export/import or release approval is implemented by this inventory.',
                       'Source binding uses Docker daemon resolution, not independent registry attestation.',
                       'OS package inventory is not a vulnerability assessment or complete language/binary SBOM.',
                       'Vendor OS and Go assessments use their own locked coverage; application policy is never inherited.',
                       'The host, deployed settings, real people and external services remain outside this proof.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--os-audit', type=Path, required=True)
    parser.add_argument('--vendor-audit', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-release-ready', action='store_true')
    args = parser.parse_args()
    try:
        require(not command(['git', 'status', '--porcelain']).strip(), 'clean source checkout required')
        revision = command(['git', 'rev-parse', 'HEAD']).decode().strip()
        tree = command(['git', 'rev-parse', 'HEAD^{tree}']).decode().strip()
        options = {'vendor_audit': args.vendor_audit} if args.vendor_audit is not None else {}
        report = collect(args.runtime.read_bytes(), revision, tree, args.image, args.os_audit, **options)
    except (ValueError, OSError, TypeError, KeyError, UnicodeError):
        report = {'schema': SCHEMA, 'status': 'INCOMPLETE', 'inventoryComplete': False,
                  'releaseReady': False, 'releaseStatus': 'BLOCKED',
                  'error': 'source checkout or canonical runtime binding could not be verified'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print('Three-image inventory: ' + report['status'] + '; release: ' + report['releaseStatus'])
    return 2 if args.require_release_ready and not report['releaseReady'] else (0 if report['inventoryComplete'] else 1)


if __name__ == '__main__':
    sys.exit(main())
