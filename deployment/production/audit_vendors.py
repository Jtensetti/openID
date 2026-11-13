"""Exact-image vendor assessment. Every unresolved OS or Go finding blocks delivery."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from contract import VENDORS
import vendor_source_advisories as source_advisories

ROOT = Path(__file__).resolve().parents[2]
LOCK = Path(__file__).with_name('vendor-images.lock.json')
_spec = importlib.util.spec_from_file_location('tjipp_os_scanner', ROOT / '.github/scripts/audit_image_os.py')
scanner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scanner)
FILES = {'vendor-lock.json', 'scanner-lock.json', 'scanner-sbom.json', 'database-metadata.json',
         'inventory.json', 'trivy.json', 'sbom.cdx.json', 'source-advisories.json'}
SCHEMA = 'tjipp-vendor-assessment-v1'


def require(value, message):
    if not value: raise ValueError(message)


def digest(path):
    return scanner.digest(path)


def save(path, value):
    scanner.save(path, value)


def assess(scan, inventory, role, scanner_version, now, source_report):
    vendor = VENDORS[role]
    require(scan.get('SchemaVersion') == 2 and scan.get('ArtifactType') == 'container_image'
            and scan.get('Trivy', {}).get('Version') == scanner_version, 'vendor scanner identity mismatch')
    require(-timedelta(minutes=5) <= now-scanner.timestamp(scan.get('CreatedAt')) <= timedelta(hours=1),
            'vendor scan is stale or future-dated')
    metadata = scan['Metadata']; system = metadata['OS']
    require(metadata.get('ImageID') == vendor['id'] and metadata.get('ImageConfig', {}).get('architecture') == 'amd64',
            'vendor image identity or architecture mismatch')
    require(system.get('Family') == vendor['osFamily'] and
            re.fullmatch(re.escape(vendor['osVersion'])+r'(?:\.\d+)?', system.get('Name', ''))
            and system.get('EOSL', False) is False, 'unsupported vendor operating system')
    require(inventory.get('role') == role and inventory.get('imageID') == vendor['id']
            and inventory.get('source') == vendor['source'] and inventory.get('platform') == 'linux/amd64'
            and inventory.get('inventoryComplete') is True and inventory.get('packageManager') == 'apk',
            'vendor inventory identity mismatch')
    require(inventory.get('osRelease', {}).get('ID') == vendor['osFamily'] and
            inventory['osRelease'].get('VERSION_ID') == system['Name'], 'vendor OS inventory mismatch')
    results = scan.get('Results')
    require(isinstance(results, list), 'vendor scan results missing')
    os_results = [r for r in results if r.get('Class') == 'os-pkgs']
    language = [r for r in results if r.get('Class') == 'lang-pkgs']
    require(len(os_results) == 1 and os_results[0].get('Type') == vendor['osFamily']
            and len(results) == len(language)+1, 'vendor scan coverage changed')
    require(len(language) == len(vendor['languageTargets']) and
            {r.get('Target') for r in language} == set(vendor['languageTargets']) and
            all(r.get('Type') == 'gobinary' for r in language), 'vendor binary scan missing or changed')
    installed = [(p['name'], p['version'], p['architecture']) for p in inventory['packages']]
    packages = os_results[0].get('Packages', [])
    scanned = [(p['Name'], p['Version'], p['Arch']) for p in packages]
    require(installed and len(installed) == len(set(installed)) and len(scanned) == len(set(scanned))
            and set(installed) == set(scanned), 'vendor installed package coverage mismatch')
    findings = source_advisories.verify(source_report, role, now, scanner.timestamp); language_count = 0
    for result in results:
        require(not result.get('ExperimentalModifiedFindings') and not result.get('Misconfigurations'),
                'suppressed or modified vendor findings')
        packages = result.get('Packages')
        require(isinstance(packages, list) and packages, 'vendor package inventory missing')
        local = {p['Name'] for p in packages if not p.get('Version')}
        expected_local = set(vendor['localGoModules']) | set(vendor.get('sourceGoModules', {}))
        require(local == (expected_local if result in language else set()),
                'unversioned vendor modules changed')
        identities = {(p['Name'], p.get('Version')) for p in packages}
        if result in language:
            require(any(p['Name'] == 'stdlib' for p in packages), 'Go runtime inventory missing')
            language_count += len(packages)
        vulnerabilities = result.get('Vulnerabilities', [])
        require(isinstance(vulnerabilities, list), 'invalid vendor findings')
        for finding in vulnerabilities:
            require(isinstance(finding.get('VulnerabilityID'), str) and finding['VulnerabilityID']
                    and (finding.get('PkgName'), finding.get('InstalledVersion')) in identities
                    and finding.get('Severity') in {'UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'},
                    'unbound vendor vulnerability')
            findings.append({'id': finding['VulnerabilityID'], 'target': result['Target'],
                             'package': finding['PkgName'], 'version': finding['InstalledVersion'],
                             'severity': finding['Severity'], 'status': 'under_investigation'})
    return {'operatingSystem': system, 'packageCount': len(installed), 'languagePackageCount': language_count,
            'findingCount': len(findings), 'unresolvedCount': len(findings), 'findings': findings,
            'complete': True, 'passed': not findings}


def verify(directory, role, revision, at):
    report = json.loads((directory/'assessment.json').read_text())
    require(report.get('schema') == SCHEMA and report.get('role') == role and
            report.get('sourceRevision') == revision and report.get('imageID') == VENDORS[role]['id'],
            'vendor assessment source mismatch')
    require(report.get('complete') is True and report.get('passed') is True, 'vendor assessment has unresolved findings')
    checked = scanner.timestamp(report['checkedAt'])
    require(-timedelta(minutes=5) <= at-checked <= timedelta(hours=1), 'vendor assessment stale at packaging')
    require(set(report.get('files', {})) == FILES, 'vendor assessment evidence incomplete')
    for name in FILES:
        path = directory/name
        require(path.is_file() and not path.is_symlink() and digest(path) == report['files'][name],
                'vendor evidence hash mismatch')
    require((directory/'vendor-lock.json').read_bytes() == LOCK.read_bytes(), 'vendor source lock changed')
    require((directory/'scanner-lock.json').read_bytes() == scanner.LOCK.read_bytes(), 'vendor scanner lock changed')
    lock = json.loads(scanner.LOCK.read_text())
    require(digest(directory/'scanner-sbom.json') == lock['sbom']['sha256'], 'scanner SBOM mismatch')
    scanner.check_database(json.loads((directory/'database-metadata.json').read_text()), checked)
    require(re.fullmatch('[a-f0-9]{64}', report.get('databaseSha256', '')), 'missing advisory database digest')
    scan = json.loads((directory/'trivy.json').read_text())
    assessment = assess(scan, json.loads((directory/'inventory.json').read_text()), role, lock['version'], checked,
                        json.loads((directory/'source-advisories.json').read_text()))
    require(all(report.get(k) == v for k, v in assessment.items()), 'vendor result does not match raw evidence')
    bom = json.loads((directory/'sbom.cdx.json').read_text())
    require(bom.get('bomFormat') == 'CycloneDX' and isinstance(bom.get('components'), list), 'vendor SBOM missing')
    purls = {p.get('Identifier', {}).get('PURL') for r in scan['Results'] for p in r['Packages']}
    require(purls - {None} <= {p.get('purl') for p in bom['components']} and
            set(VENDORS[role]['localGoModules']) <= {p.get('name') for p in bom['components']},
            'vendor SBOM package coverage missing')
    return report


def audit(role, output):
    from delivery_inventory import image_inventory
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': SCHEMA, 'role': role, 'imageID': VENDORS[role]['id'],
              'sourceRevision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'checkedAt': datetime.now(timezone.utc).isoformat(), 'complete': False, 'passed': False,
              'limits': ['All OS and discovered Go module findings remain blocking; no application exceptions apply.',
                         'Package matching is not independent review or proof of runtime exploitability.',
                         'Other copied files, host configuration and external services require separate review.']}
    try:
        (output/'vendor-lock.json').write_bytes(LOCK.read_bytes())
        (output/'scanner-lock.json').write_bytes(scanner.LOCK.read_bytes())
        lock = json.loads(scanner.LOCK.read_text())
        inventory = image_inventory(role, VENDORS[role]['id'])
        save(output/'inventory.json', inventory)
        with tempfile.TemporaryDirectory(prefix='tjipp-vendor-audit-') as temp:
            work = Path(temp); binary = scanner.install(lock, work, output)
            env = {k:v for k,v in os.environ.items() if not k.startswith('TRIVY_')}
            prefix = [str(binary), '--config', '', '--cache-dir', str(work/'cache'), '--timeout', '8m']
            flags = ['image', '--disable-telemetry', '--skip-version-check', '--no-progress', '--module-dir',
                     str(work/'modules'), '--db-repository', scanner.DB_REPOSITORY]
            subprocess.run(prefix+flags+['--download-db-only'], env=env, cwd=work, check=True, timeout=540)
            database = work/'cache/db'
            metadata = json.loads((database/'metadata.json').read_text())
            save(output/'database-metadata.json', metadata)
            scanner.check_database(metadata, datetime.now(timezone.utc))
            report['databaseSha256'] = digest(database/'trivy.db')
            subprocess.run(prefix+flags+['--skip-db-update', '--skip-java-db-update', '--offline-scan',
                '--image-src', 'docker', '--scanners', 'vuln', '--pkg-types', 'os,library', '--ignorefile', '',
                '--ignore-unfixed=false', '--ignore-status', '', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
                '--list-all-pkgs', '--show-suppressed', '--format', 'json', '--exit-code', '0',
                '--output', str(output/'trivy.json'), VENDORS[role]['id']], env=env, cwd=work, check=True, timeout=540)
            subprocess.run(prefix+['convert', '--format', 'cyclonedx', '--output', str(output/'sbom.cdx.json'),
                str(output/'trivy.json')], env=env, cwd=work, check=True, timeout=60)
            report['checkedAt'] = datetime.now(timezone.utc).isoformat()
            source_report = source_advisories.collect(role, scanner.timestamp(report['checkedAt']))
            save(output/'source-advisories.json', source_report)
            report.update(assess(json.loads((output/'trivy.json').read_text()), inventory, role, lock['version'],
                                 scanner.timestamp(report['checkedAt']), source_report))
    except Exception as error:
        report['errorType'] = type(error).__name__
        if isinstance(error, ValueError): report['error'] = str(error)[:200]
    report['files'] = {p.name:digest(p) for p in sorted(output.iterdir()) if p.is_file()}
    save(output/'assessment.json', report)
    print(f"{role}: complete={report['complete']}; passed={report['passed']}; unresolved={report.get('unresolvedCount', 'unknown')}")
    return report['complete'] and report['passed']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    results = [audit(role, args.output.resolve()/role) for role in VENDORS]
    return 0 if all(results) else 1


if __name__ == '__main__': raise SystemExit(main())
