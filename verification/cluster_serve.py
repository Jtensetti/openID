"""TLS workers for the shared registry; proofing remains a separate single-worker service."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import sys
from runtime import Runtime, validate_origin
from serve import private_file, bounded_worker, close_worker, reject_duplicate_headers, score_frames


def config_file(path):
    config=json.loads(Path(path).read_text())
    fields={'role','bind','port','origin','workers','databaseFile','baoAddress','baoTokenFile','baoCA',
        'tlsCert','tlsKey','pairingFile','metricsFile'}
    proofing={'team','bundle','developmentAttestation','csca','jar'}
    if config.get('role')=='proofing': fields |= proofing
    if set(config)!=fields or config['role'] not in ('wallet','proofing'): raise ValueError('configuration fields')
    validate_origin(config['origin'])
    address=ipaddress.ip_address(config['bind'])
    if address.is_unspecified or address.is_multicast or not address.is_private: raise ValueError('explicit private bind required')
    if type(config['port']) is not int or not 1024<=config['port']<=65535: raise ValueError('port')
    if type(config['workers']) is not int or not 1<=config['workers']<=4: raise ValueError('workers')
    if config['role']=='proofing':
        if config['workers']!=1: raise ValueError('proofing requires one worker')
        if not re.fullmatch('[A-Z0-9]{10}',config['team']) or not re.fullmatch('[A-Za-z0-9.-]{3,128}',config['bundle']): raise ValueError('Apple identifiers')
        if type(config['developmentAttestation']) is not bool: raise ValueError('attestation environment')
    for field in fields & {'databaseFile','baoTokenFile','baoCA','tlsCert','tlsKey','pairingFile','metricsFile','csca','jar'}:
        if not Path(config[field]).is_absolute() or not Path(config[field]).is_file(): raise ValueError('absolute existing path required')
    private_file(config['tlsKey'])
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(config['tlsCert'],config['tlsKey'])
    for field in ('pairingFile','metricsFile'):
        if not re.fullmatch('[A-Za-z0-9_-]{43,128}',private_file(config[field]).decode().strip()): raise ValueError('secret format')
    return config


def create_app(config, *, local_test=False):
    from crypto_runtime import CryptoRuntime
    from postgres import PostgresWallet
    from transit import TransitVault
    crypto=CryptoRuntime()
    wallet=None
    try:
        vault=TransitVault(config['baoAddress'],config['baoTokenFile'],config['baoCA'],local_test=local_test)
        wallet=PostgresWallet(private_file(config['databaseFile']).decode().strip(),config['origin'],vault,
            crypto=crypto.device,local_test=local_test)
        native=None
        if config['role']=='proofing':
            from native import NativeSessions, AppAttest
            from chip import ChipProcess
            from server import verify_document
            command=['java','-Xmx128m','-jar',config['jar'],'verify-passport',config['csca']]
            native=NativeSessions(AppAttest(config['team'],config['bundle'],config['developmentAttestation']),
                lambda data:verify_document(command,data),None,None,wallet=wallet,
                chip_factory=lambda data:ChipProcess([*command[:-2],'authenticate-chip',command[-1]],data),biometrics=score_frames)
        app=Runtime(native,wallet,config['origin'],private_file(config['pairingFile']).decode().strip(),
            metrics_token=private_file(config['metricsFile']).decode().strip(),role=config['role'])
        app.crypto=crypto
        return app
    except BaseException:
        crypto.close()
        if wallet is not None: wallet.close()
        raise


def run(config, *, local_test=False):
    from gunicorn.app.base import BaseApplication
    class Application(BaseApplication):
        def load_config(self):
            bind=f"[{config['bind']}]" if ':' in config['bind'] else config['bind']
            for key,value in {'bind':f"{bind}:{config['port']}",'workers':config['workers'],'threads':16,
                'worker_class':bounded_worker(),'worker_connections':32,'backlog':64,
                'timeout':90,'graceful_timeout':60,'keepalive':2,'limit_request_line':1024,
                'limit_request_fields':32,'limit_request_field_size':4096,'certfile':config['tlsCert'],'keyfile':config['tlsKey'],
                'forwarded_allow_ips':'','forwarder_headers':'','secure_scheme_headers':{},'control_socket_disable':True,
                'accesslog':None,'errorlog':'-','umask':0o077,'preload_app':False,
                'worker_exit':close_worker,'pre_request':reject_duplicate_headers}.items():self.cfg.set(key,value)
        def load(self):return create_app(config,local_test=local_test)
    Application().run()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);args=parser.parse_args()
    if os.environ.get('GUNICORN_CMD_ARGS'):raise ValueError('Gunicorn overrides are unsupported')
    config=config_file(args.config)
    if config['role']=='proofing':
        import subprocess
        subprocess.run([sys.executable,str(Path(__file__).with_name('biometric_worker.py')),'--check'],
            check=True,timeout=60,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    run(config)


if __name__=='__main__':
    try:main()
    except Exception:
        print('Startup rejected. Check configuration and dependency availability.',file=sys.stderr)
        raise SystemExit(2)
