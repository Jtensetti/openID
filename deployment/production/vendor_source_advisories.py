"""Cover source-built Go main modules whose binary metadata says (devel)."""
from datetime import timedelta
import importlib.util
from pathlib import Path

from contract import VENDORS

_spec = importlib.util.spec_from_file_location('vendor_osv',
    Path(__file__).resolve().parents[2]/'.github/scripts/audit_dependencies.py')
osv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(osv)


def queries(role):
    vendor = VENDORS[role]
    modules = vendor.get('sourceGoModules', {})
    if any(version != vendor['version'] for version in modules.values()):
        raise ValueError('source module version differs from locked release')
    items = [{'query': {'package': {'ecosystem': 'Go', 'name': name}, 'version': 'v'+version}}
             for name, version in sorted(modules.items())]
    if modules:
        items.append({'query': {'commit': vendor['sourceRevision']}})
    return items


def collect(role, now, fetch=osv.request_osv):
    pages = []
    def recorded(payload):
        response = fetch(payload)
        pages.append({'request': payload, 'response': response})
        return response
    results, requests = osv.query_all(queries(role), recorded)
    return {'schema': 1, 'role': role, 'imageID': VENDORS[role]['id'],
            'sourceRevision': VENDORS[role]['sourceRevision'], 'checkedAt': now.isoformat(),
            'service': osv.ENDPOINT, 'results': results, 'requests': requests, 'pages': pages,
            'limits': ['OSV coverage and commit mappings are incomplete; this supplements the image scan.',
                       'The exact locked upstream release and commit are queried; patched dependencies are scanned in the binary.']}


def verify(report, role, now, timestamp):
    vendor = VENDORS[role]
    if (report.get('schema') != 1 or report.get('role') != role
            or report.get('imageID') != vendor['id']
            or report.get('sourceRevision') != vendor['sourceRevision']
            or report.get('service') != osv.ENDPOINT
            or not -timedelta(minutes=5) <= now-timestamp(report['checkedAt']) <= timedelta(hours=1)):
        raise ValueError('source advisory evidence identity or time changed')
    pages = iter(report['pages'])
    def replay(payload):
        page = next(pages)
        if page.get('request') != payload:
            raise ValueError('source advisory query coverage changed')
        return page['response']
    results, requests = osv.query_all(queries(role), replay)
    if (next(pages, None) is not None or results != report.get('results')
            or requests != report.get('requests')):
        raise ValueError('source advisory result differs from complete raw responses')
    return [{'id': identity, 'target': 'locked-upstream-source', 'query': item['query'],
             'status': 'under_investigation'}
            for item in results for identity in item['vulnerabilities']]
