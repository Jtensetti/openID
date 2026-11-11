"""Host-only, atomic IMDS isolation for every non-root process."""
import argparse
import fcntl
import json
import os
import subprocess
import sys

TABLE = 'tjipp_metadata'
ADDRESSES = {'ip': '169.254.169.254', 'ip6': 'fd00:ec2::254'}


def rules(replace=False):
    prefix = f'delete table inet {TABLE}\n' if replace else ''
    statements = '\n'.join(f'{protocol} daddr {address} meta skuid != 0 counter reject with icmpx type admin-prohibited'
                           for protocol, address in ADDRESSES.items())
    return prefix + f'table inet {TABLE} {{\n chain output {{\n type filter hook output priority -10; policy accept;\n{statements}\n }}\n}}\n'


def verify(value):
    tables, chains, records = [], [], []
    for item in value.get('nftables', []):
        if 'metainfo' in item: continue
        if 'table' in item: tables.append(item['table'])
        elif 'chain' in item: chains.append(item['chain'])
        elif 'rule' in item: records.append(item['rule'])
        else: raise ValueError('unexpected metadata filter element')
    if len(tables) != 1 or tables[0].get('family') != 'inet' or tables[0].get('name') != TABLE or len(chains) != 1:
        raise ValueError('metadata filter table required')
    chain = chains[0]
    if any(chain.get(k) != v for k, v in {'family': 'inet', 'table': TABLE, 'name': 'output',
            'type': 'filter', 'hook': 'output', 'prio': -10, 'policy': 'accept'}.items()) or len(records) != 2:
        raise ValueError('metadata output filter required')
    seen = set()
    for record in records:
        if any(record.get(k) != v for k, v in {'family': 'inet', 'table': TABLE, 'chain': 'output'}.items()):
            raise ValueError('metadata filter chain mismatch')
        expr = [e for e in record['expr'] if 'counter' not in e]
        # --numeric may emit Linux NFT_REJECT_ICMPX_ADMIN_PROHIBITED (3).
        verdicts = [{'reject': {'type': 'icmpx', 'expr': code}} for code in ('admin-prohibited', 3)]
        if len(expr) != 3 or expr[-1] not in verdicts:
            raise ValueError('metadata rejection required: '+json.dumps(expr, sort_keys=True))
        uid = {'match': {'op': '!=', 'left': {'meta': {'key': 'skuid'}}, 'right': 0}}
        if expr[1] != uid: raise ValueError('all non-root processes must be isolated')
        for protocol, address in ADDRESSES.items():
            expected = {'match': {'op': '==', 'left': {'payload': {'protocol': protocol, 'field': 'daddr'}}, 'right': address}}
            if expr[0] == expected: seen.add(protocol); break
        else: raise ValueError('metadata destination mismatch')
    if seen != set(ADDRESSES): raise ValueError('both metadata families required')


def check():
    result = subprocess.run(['nft', '--json', '--numeric', 'list', 'table', 'inet', TABLE], check=True,
                            capture_output=True, text=True, timeout=5)
    verify(json.loads(result.stdout))


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('action', choices=['install', 'check'])
    args = parser.parse_args()
    try:
        if os.geteuid() != 0: raise ValueError('host administrator required')
        with open('/run/lock/tjipp-metadata.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if args.action == 'install':
                exists = subprocess.run(['nft', 'list', 'table', 'inet', TABLE], capture_output=True, timeout=5).returncode == 0
                subprocess.run(['nft', '-f', '-'], input=rules(exists), check=True, capture_output=True, text=True, timeout=5)
            check()
        print('Host metadata isolation verified.'); return 0
    except Exception as error:
        # nftables rules contain only fixed addresses, UIDs and verdicts.
        # Keep their parsing/startup reason visible without any app config.
        print('Host metadata isolation unavailable; do not start Docker. '+str(error), file=sys.stderr); return 2


if __name__ == '__main__':
    sys.exit(main())
