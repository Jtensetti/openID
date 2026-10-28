"""Bounded inventory for a locally built ncurses evaluation candidate."""
import urllib.parse


def sbom(lock, packages, installed):
    components = []
    for item in lock['inputs']:
        components.append({'type': 'file', 'bom-ref': 'source:' + item['filename'],
                           'name': item['filename'],
                           'hashes': [{'alg': 'SHA-256', 'content': item['sha256']}],
                           'externalReferences': [{'type': 'distribution', 'url': item['url']}]})
    exported = set(lock['runtimePackages'])
    for item in packages:
        components.append({'type': 'library', 'bom-ref': 'built:' + item['Package'],
                           'name': item['Package'], 'version': item['Version'],
                           'hashes': [{'alg': 'SHA-256', 'content': item['sha256']}],
                           'licenses': [{'license': {'name': 'See preserved upstream and Debian copyright notices'}}],
                           'properties': [
                               {'name': 'openid:origin', 'value': 'Local evaluation build, not an official Debian binary'},
                               {'name': 'openid:artifact-exported',
                                'value': str(item['Package'] in exported).lower()}]})
    for line in installed.splitlines():
        name, version, architecture, state = line.split('\t')
        if state != 'installed':
            raise ValueError('incomplete toolchain inventory')
        components.append({'type': 'library', 'bom-ref': 'toolchain:' + name + ':' + architecture,
                           'name': name, 'version': version,
                           'purl': 'pkg:deb/debian/' + name + '@'
                                   + urllib.parse.quote(version, safe='') + '?arch=' + architecture,
                           'properties': [{'name': 'openid:scope',
                                           'value': 'Disposable builder only; not installed in an application image'}]})
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'component': {'type': 'application', 'bom-ref': 'candidate:ncurses',
                                       'name': 'openid-ncurses-package-evaluation',
                                       'version': lock['candidateVersion']},
                         'properties': [{'name': 'openid:scope',
                                         'value': 'Source inputs, produced Debian packages and builder dpkg inventory only. '
                                         'Not an application SBOM or advisory decision.'}]},
            'components': components}
