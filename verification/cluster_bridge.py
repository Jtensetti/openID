"""Connect the existing local SAML IPC protocol to the shared registry."""
import argparse
import json
from pathlib import Path
import signal
import sys
import threading
from urllib.parse import urlsplit
from crypto_runtime import CryptoRuntime
from federation import FederationServer
from postgres import PostgresWallet
from runtime import validate_origin
from serve import private_file
from transit import TransitVault


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);args=parser.parse_args()
    config=json.loads(Path(args.config).read_text())
    if set(config)!={'databaseFile','baoAddress','baoTokenFile','baoCA','origin','socket','audience'}:raise ValueError('configuration')
    validate_origin(config['origin']);audience=urlsplit(config['audience'])
    if audience.scheme!='https' or not audience.hostname or audience.username or audience.password or audience.query or audience.fragment:
        raise ValueError('fixed HTTPS audience required')
    if not Path(config['socket']).is_absolute():raise ValueError('absolute socket path required')
    crypto=CryptoRuntime();wallet=None;bridge=None
    stop=threading.Event()
    for name in (signal.SIGTERM,signal.SIGINT):signal.signal(name,lambda *_:stop.set())
    try:
        vault=TransitVault(config['baoAddress'],config['baoTokenFile'],config['baoCA'])
        wallet=PostgresWallet(private_file(config['databaseFile']).decode().strip(),config['origin'],vault,crypto=crypto.device)
        bridge=FederationServer(config['socket'],wallet,config['audience'])
        stop.wait()
    finally:
        if bridge is not None:bridge.close()
        if wallet is not None:wallet.close()
        crypto.close()


if __name__=='__main__':
    try:main()
    except Exception:
        print('Federation bridge unavailable.',file=sys.stderr);raise SystemExit(2)
