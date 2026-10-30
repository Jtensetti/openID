"""Complement Trivy's fixed-version Wolfi feed with all unresolved vendor statuses."""
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
import io
import json
import re
import tarfile
import urllib.request
from urllib.parse import unquote

BASE = 'https://advisories.cgr.dev/chainguard/v2/osv/'
UNRESOLVED = {'detection', 'true_positive_determination', 'pending_upstream_fix', 'fix_not_planned'}


def modified_second(value):
    # The index preserves milliseconds; v2 records truncate to whole seconds.
    value = re.sub(r'\.\d+(?=Z|[+-])', '', value)
    instant = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if instant.tzinfo is None:
        raise ValueError('vendor modification time needs timezone')
    return instant.replace(microsecond=0)


def fetch(name, limit, now):
    with urllib.request.urlopen(BASE + name, timeout=120) as response:
        modified = parsedate_to_datetime(response.headers['Last-Modified'])
        if not -timedelta(minutes=5) <= now - modified <= timedelta(hours=24):
            raise ValueError('vendor advisory feed is stale or future-dated')
        raw = response.read(limit + 1)
        if len(raw) > limit:
            raise ValueError('vendor advisory feed exceeds size limit')
    return raw, {'url': BASE + name, 'lastModified': modified.isoformat(),
                 'sha256': hashlib.sha256(raw).hexdigest()}


def unresolved(records, installed):
    """Fixed ranges stay covered by Trivy; every open-ended range blocks here.

    No severity or vendor-status exemptions. A non-zero introduction is also
    blocked conservatively rather than guessing APK version ordering.
    """
    names = {(name, arch): version for name, version, arch in installed}
    findings = []
    for record in records:
        if record.get('schema_version') != '1.7.5' or not record.get('id'):
            raise ValueError('unsupported vendor advisory record')
        for affected in record['affected']:
            package = affected['package']
            if package['ecosystem'] != 'Wolfi':
                continue
            purl = unquote(package.get('purl', ''))
            if not purl.startswith('pkg:apk/wolfi/' + package['name'] + '?arch='):
                raise ValueError('ambiguous vendor package identity')
            arch = purl.split('?arch=', 1)[1]
            if arch not in ('x86_64', 'aarch64', 'noarch'):
                raise ValueError('unknown vendor package architecture')
            identity = (package['name'], arch)
            if identity not in names:
                continue
            ranges = affected['ranges']
            if len(ranges) != 1 or ranges[0].get('type') != 'ECOSYSTEM':
                raise ValueError('unsupported vendor advisory range')
            events = ranges[0]['events']
            if (not events or any(len(e) != 1 or set(e) - {'introduced', 'fixed'} for e in events)
                    or 'introduced' not in events[0]):
                raise ValueError('invalid vendor advisory events')
            components = affected['ecosystem_specific']['components']
            statuses = {c['latest_event_status'] for c in components}
            if not statuses or statuses - UNRESOLVED - {'fixed', 'false_positive_determination'}:
                raise ValueError('unknown vendor advisory status')
            if 'introduced' in events[-1] or statuses & UNRESOLVED:
                findings.append({'id': record['id'], 'upstream': record.get('upstream', []),
                                 'package': identity[0], 'version': names[identity], 'architecture': arch,
                                 'statuses': sorted(statuses)})
    return sorted(findings, key=lambda f: (f['package'], f['id']))


def collect(installed, now):
    raw_index, index_meta = fetch('all.json', 16 * 1024 * 1024, now)
    index = json.loads(raw_index)
    expected = {r['id']: r['modified'] for r in index}
    if len(expected) != len(index) or not expected:
        raise ValueError('empty or duplicate vendor advisory index')
    raw_archive, archive_meta = fetch('chainguard-osv.tar.gz', 96 * 1024 * 1024, now)
    names = {p[0] for p in installed}
    records, seen, total, embedded_index = [], set(), 0, False
    with tarfile.open(fileobj=io.BytesIO(raw_archive), mode='r:gz') as archive:
        for member in archive:
            if member.isdir():
                continue
            if not member.isfile() or not member.name.endswith('.json') or member.size > 32 * 1024 * 1024:
                raise ValueError('unexpected vendor advisory archive member')
            total += member.size
            if total > 2 * 1024 * 1024 * 1024:
                raise ValueError('expanded advisory archive too large')
            record = json.load(archive.extractfile(member))
            if member.name == 'all.json':
                if embedded_index or record != index:
                    raise ValueError('vendor embedded index mismatch')
                embedded_index = True
                continue
            identity = record['id']
            if (identity in seen or identity not in expected
                    or modified_second(expected[identity]) != modified_second(record['modified'])):
                raise ValueError('vendor index/archive mismatch')
            seen.add(identity)
            if any(a['package']['ecosystem'] == 'Wolfi' and a['package']['name'] in names
                   for a in record['affected']):
                records.append(record)
    if not embedded_index or seen != set(expected):
        raise ValueError('vendor advisory archive is incomplete')
    findings = unresolved(records, installed)
    return {'format': 1, 'complete': True, 'checkedAt': now.isoformat(),
            'index': index_meta, 'archive': archive_meta, 'recordCount': len(seen),
            'packages': [list(p) for p in sorted(installed)], 'records': records,
            'findings': findings,
            'scope': 'Unresolved vendor statuses; Trivy separately evaluates fixed-version ranges.'}
