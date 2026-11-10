"""Render fixed ingress rules from three explicit HTTPS origins; no network or service changes."""
import argparse
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


def render(runtime, origins):
    if set(origins) != {'idp', 'sp'}:
        raise ValueError('Explicit IdP and recipient origins required')
    hosts = {}
    for name, origin in {'API': runtime['origin'], 'IDP': origins['idp'], 'SP': origins['sp']}.items():
        url = urlsplit(origin)
        if (url.scheme != 'https' or not url.hostname or url.netloc != url.hostname
                or url.path or url.query or url.fragment
                or not re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*\.[a-z]{2,}', url.hostname)):
            raise ValueError('Canonical HTTPS DNS origin required')
        hosts[name] = url.hostname
    if len(set(hosts.values())) != 3:
        raise ValueError('Distinct service hosts required')
    config = Path(__file__).with_name('nginx.conf.in').read_text()
    for name, host in hosts.items():
        config = config.replace(f'@{name}_HOST@', host)
    return config


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    print(render(json.loads((args.directory / 'runtime.json').read_text()),
                 json.loads((args.directory / 'origins.json').read_text())), end='')
