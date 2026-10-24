"""Create private pilot files outside the checkout. Never supplies passport trust anchors."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--address', required=True, help='Explicit private IPv4 address of the Linux host')
    parser.add_argument('--team', required=True)
    parser.add_argument('--bundle', default='se.openid.PassportCapture')
    parser.add_argument('--csca', type=Path, required=True, help='Independently obtained trusted CSCA PEM bundle')
    parser.add_argument('--csca-crl', type=Path, help='CRL from the same CSCA (e.g. cert.polisen.se/CSCA/SWE.crl); revocation then fails closed')
    args = parser.parse_args()
    address = ipaddress.IPv4Address(args.address)
    if address.is_unspecified or address.is_multicast or not address.is_private: parser.error('Private IPv4 address required')
    if not re.fullmatch('[A-Z0-9]{10}', args.team): parser.error('Apple Team ID required')
    if not re.fullmatch('[A-Za-z0-9.-]{3,128}', args.bundle): parser.error('Bundle ID required')
    root = args.directory.absolute()
    repo = Path(__file__).resolve().parent.parent
    if root == repo or repo in root.parents or root.exists() or root.is_symlink():
        parser.error('Choose a new directory outside the repository')
    if not args.csca.is_file(): parser.error('Trusted CSCA PEM bundle missing')
    # Parse the supplied bundle; this does not establish its provenance or trustworthiness.
    subprocess.run(['openssl','crl2pkcs7','-nocrl','-certfile',str(args.csca),'-out','/dev/null'],check=True)
    if args.csca_crl:
        if not args.csca_crl.is_file(): parser.error('CSCA CRL missing')
        # Parse only; the verifier checks the CRL signature against the provisioned CSCA at every start.
        subprocess.run(['openssl','crl','-inform','DER','-in',str(args.csca_crl),'-noout'],check=True)
    os.umask(0o077)
    root.mkdir(mode=0o700, parents=True)
    try:
        secret_dir = root/'secrets'; secret_dir.mkdir(mode=0o700)
        (root/'data').mkdir(mode=0o700)
        shutil.copyfile(args.csca, secret_dir/'trusted-csca.pem')
        if args.csca_crl: shutil.copyfile(args.csca_crl, secret_dir/'csca.crl')
        subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-sha256','-nodes','-days','30',
            '-subj','/CN=openID private pilot','-addext',f'subjectAltName=IP:{address}',
            '-addext','extendedKeyUsage=serverAuth','-keyout',str(secret_dir/'server-key.pem'),
            '-out',str(secret_dir/'server.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (secret_dir/'pairing').write_text(secrets.token_urlsafe(32)+'\n')
        config = {'bind': str(address), 'origin': f'https://{address}:8765', 'team': args.team,
            'bundle': args.bundle, 'developmentAttestation': True,
            **{k: '/srv/openid/secrets/'+v for k,v in {'tlsCert':'server.pem','tlsKey':'server-key.pem',
                'csca':'trusted-csca.pem','pairingFile':'pairing'}.items()},
            'database':'/srv/openid/data/wallet.sqlite',
            **({'cscaCrl':'/srv/openid/secrets/csca.crl'} if args.csca_crl else {})}
        (root/'runtime.json').write_text(json.dumps(config,indent=2)+'\n')
        print('Private configuration created. Trust secrets/server.pem on the test iPhone before connecting.')
        print('Use your own UID/GID for Docker Compose. The pairing code is in secrets/pairing.')
    except BaseException:
        shutil.rmtree(root)
        raise


if __name__ == '__main__': main()
