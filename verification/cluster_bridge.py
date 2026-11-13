"""One PostgreSQL wallet behind the shared federation and notification surfaces."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import sys
import threading

from crypto_runtime import CryptoRuntime
from federation import FederationServer
from federation_config import read_profile, read_origins
from ipc_support import prepare_socket, _verify_parent
from native import unique_object
from notice_ipc import serve as serve_notices
from runtime import validate_origin
from serve import private_file


FIELDS = {'databaseFile', 'baoAddress', 'baoTokenFile', 'baoCA', 'origin',
          'socket', 'federationGroup', 'noticeSocket', 'noticeGroup',
          'continuityFile', 'federationFile', 'originsFile'}
LEGACY = {'OPENID_SWEDEN_CONNECT_SANDBOX', 'OPENID_FEDERATION_CONFIG',
          'OPENID_PILOT_ORIGINS', 'OPENID_FEDERATION_SOCKET', 'OPENID_FEDERATION_GROUP',
          'OPENID_NOTICE_SOCKET', 'OPENID_NOTICE_GROUP'}


def config_file(path):
    if not Path(path).is_absolute():
        raise ValueError('absolute bridge configuration required')
    config = json.loads(private_file(path), object_pairs_hook=unique_object)
    if type(config) is not dict or set(config) != FIELDS or LEGACY & os.environ.keys():
        raise ValueError('explicit bridge configuration required; environment overrides unsupported')
    validate_origin(config['origin'])
    for key in ('databaseFile', 'baoTokenFile', 'baoCA', 'continuityFile', 'federationFile', 'originsFile'):
        if not isinstance(config[key], str) or not Path(config[key]).is_absolute():
            raise ValueError('absolute dependency paths required')
    for key in ('federationGroup', 'noticeGroup'):
        if type(config[key]) is not int or config[key] < 1:
            raise ValueError('explicit socket group required')
    for key in ('socket', 'noticeSocket'):
        if (not isinstance(config[key], str) or not Path(config[key]).is_absolute()
                or Path(config[key]).parent != Path(config[key]).parent.resolve(strict=True)):
            raise ValueError('real absolute socket directory required')
    if Path(config['socket']).parent == Path(config['noticeSocket']).parent:
        raise ValueError('separate federation and notification directories required')
    # Read these before any socket can be removed or an external client opened.
    read_profile(config['federationFile'])
    read_origins(config['originsFile'])
    return config


class RegistryBridge:
    def __init__(self, config, wallet):
        self.resources = ExitStack()
        self.wallet = wallet
        self.closed = False
        try:
            sandbox = read_profile(config['federationFile'])
            audience = read_origins(config['originsFile'])['sp']+'/sp'
            # Validate BOTH parents before cleaning either endpoint.
            for key, group in (('socket', 'federationGroup'), ('noticeSocket', 'noticeGroup')):
                _verify_parent(config[key], config[group])
            prepare_socket(config['socket'], config['federationGroup'])
            self.federation = FederationServer(config['socket'], wallet, audience,
                shared_group=config['federationGroup'], sandbox=sandbox)
            self.resources.callback(self.federation.close)
            self.notice = serve_notices(config['noticeSocket'], config['noticeGroup'], wallet)
            worker = threading.Thread(target=self.notice.serve_forever, daemon=True)
            worker.start()
            self.resources.callback(worker.join, 5)
            self.resources.callback(self.notice.close)
        except BaseException:
            self.resources.close()
            raise

    def close(self):
        if not self.closed:
            self.closed = True
            self.resources.close()


def run(config):
    from postgres import PostgresWallet
    from postgres_continuity import configured_client
    from transit import TransitVault
    stop = threading.Event()
    for name in (signal.SIGTERM, signal.SIGINT):
        signal.signal(name, lambda *_: stop.set())
    with ExitStack() as resources:
        crypto = CryptoRuntime()
        resources.callback(crypto.close)
        vault = TransitVault(config['baoAddress'], config['baoTokenFile'], config['baoCA'])
        vault.start_renewal('wallet')
        resources.callback(vault.close)
        wallet = PostgresWallet(private_file(config['databaseFile']).decode().strip(), config['origin'], vault,
            crypto=crypto.device, revocation=configured_client(config['continuityFile']))
        resources.callback(wallet.close)
        bridge = RegistryBridge(config, wallet)
        resources.callback(bridge.close)
        stop.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    try:
        run(config_file(args.config))
    except Exception:
        print('Federation bridge unavailable.', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
