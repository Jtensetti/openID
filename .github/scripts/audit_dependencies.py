"""Check exact repository locks against OSV. An unavailable/partial answer never passes."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

ENDPOINT = 'https://api.osv.dev/v1/querybatch'
ROOT = Path(__file__).resolve().parents[2]


def inventory(root):
    queries = {}
    manifests = {}

    def add(query, source):
        key = json.dumps(query, sort_keys=True)
        queries.setdefault(key, {'query': query, 'sources': set()})['sources'].add(source)

    def read(path):
        raw = path.read_bytes()
        source = path.relative_to(root).as_posix()
        manifests[source] = hashlib.sha256(raw).hexdigest()
        return source, raw.decode()

    source, raw = read(root/'prototype/dependencies.lock.json')
    for item in json.loads(raw)['dependencies']:
        parts = item['coordinate'].split(':')
        if len(parts) not in (4, 5): raise ValueError('invalid Maven lock')
        add({'package': {'ecosystem': 'Maven', 'name': ':'.join(parts[:2])}, 'version': parts[-1]}, source)
    locks = sorted((root/'verification').glob('*requirements.lock')) + [root/'deployment/aws/requirements.lock']
    if len(locks) != 5: raise ValueError('missing Python lock')
    for path in locks:
        source, raw = read(path)
        for line in raw.splitlines():
            if not line or line.startswith(('#', '--')): continue
            match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([^\s]+)(?: --hash=sha256:[a-f0-9]{64})+', line)
            if not match: raise ValueError('unpinned Python dependency')
            name, version = match.groups()
            for value in {version, version.split('+')[0]}:
                add({'package': {'ecosystem': 'PyPI', 'name': name}, 'version': value}, source)
    for directory in ('prototype', 'verification'):
        source, raw = read(root/directory/'package-lock.json')
        packages = json.loads(raw)['packages']
        if not packages: raise ValueError('empty npm lock')
        for location, item in packages.items():
            if not location: continue
            name = location.rsplit('node_modules/', 1)[-1]
            if not item.get('version') or item.get('link'): raise ValueError('unresolved npm dependency')
            add({'package': {'ecosystem': 'npm', 'name': name}, 'version': item['version']}, source)
    source, raw = read(root/'ios/PassportCapture.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved')
    for pin in json.loads(raw)['pins']:
        revision = pin['state']['revision']
        if not re.fullmatch('[a-f0-9]{40}', revision): raise ValueError('unpinned Swift dependency')
        add({'commit': revision}, source)
    for path in sorted((root/'.github/workflows').glob('*.yml')):
        source, raw = read(path)
        for reference in re.findall(r'uses:\s*([^\s#]+)', raw):
            if reference.startswith('./.github/workflows/'): continue
            match = re.fullmatch(r'[^@]+@([a-f0-9]{40})', reference)
            if not match: raise ValueError('unpinned workflow dependency')
            add({'commit': match[1]}, source)
    if not queries: raise ValueError('empty dependency inventory')
    return [dict(query=v['query'], sources=sorted(v['sources'])) for _, v in sorted(queries.items())], manifests


def request_osv(payload):
    request = urllib.request.Request(ENDPOINT, data=json.dumps(payload).encode(),
        headers={'Content-Type': 'application/json', 'User-Agent': 'openid-lock-audit/1'})
    with urllib.request.urlopen(request, timeout=45) as response:
        raw = response.read(8 * 1024 * 1024 + 1)
        if response.status != 200 or len(raw) > 8 * 1024 * 1024: raise ValueError('OSV response limit')
    return json.loads(raw)


def query_all(items, fetch=request_osv):
    findings = [set() for _ in items]
    pending = [(i, item['query']) for i, item in enumerate(items)]
    tokens = [set() for _ in items]
    requests = 0
    while pending:
        batch, pending = pending[:100], pending[100:]
        response = fetch({'queries': [query for _, query in batch]})
        requests += 1
        if not isinstance(response, dict) or set(response) != {'results'}:
            raise ValueError('invalid OSV response')
        results = response['results']
        if not isinstance(results, list) or len(results) != len(batch): raise ValueError('partial OSV response')
        for (index, query), result in zip(batch, results):
            if not isinstance(result, dict) or set(result) - {'vulns', 'next_page_token'}:
                raise ValueError('OSV query error')
            vulns = result.get('vulns', [])
            if not isinstance(vulns, list): raise ValueError('invalid OSV findings')
            for vuln in vulns:
                ident = vuln.get('id') if isinstance(vuln, dict) else None
                if not isinstance(ident, str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}', ident):
                    raise ValueError('invalid OSV finding')
                findings[index].add(ident)
            if 'next_page_token' in result:
                token = result['next_page_token']
                if not isinstance(token, str) or not 1 <= len(token) <= 8192 or token in tokens[index] or len(tokens[index]) >= 20:
                    raise ValueError('incomplete OSV pagination')
                tokens[index].add(token)
                pending.append((index, dict(items[index]['query'], page_token=token)))
    return [dict(item, vulnerabilities=sorted(found)) for item, found in zip(items, findings)], requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = {'format': 1, 'complete': False, 'checkedAt': datetime.now(timezone.utc).isoformat(),
        'sourceRevision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'service': ENDPOINT,
        'limits': ['OSV has incomplete advisory coverage, including source-commit mappings.',
            'Base images, OS packages, JDK, Node, OpenBao, PostgreSQL, models and deployed configuration require separate monitoring.']}
    code = 2
    try:
        items, report['manifests'] = inventory(ROOT)
        report['results'], report['requests'] = query_all(items)
        report['complete'] = True
        count = sum(bool(item['vulnerabilities']) for item in report['results'])
        report['affectedQueries'] = count
        code = 1 if count else 0
    except Exception as error:
        report['errorType'] = type(error).__name__
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
    print('OSV audit: '+('complete' if report['complete'] else 'INCOMPLETE')+f'; exit={code}')
    return code


if __name__ == '__main__': sys.exit(main())
