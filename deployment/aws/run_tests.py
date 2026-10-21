"""Run the existing registry suite from an SSM runner inside the test VPC."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import boto3
import psycopg
from psycopg.conninfo import make_conninfo


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--secret', required=True)
    parser.add_argument('--ca', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'openid-aws-check-[a-f0-9]{12}\.[a-z0-9]+\.eu-north-1\.rds\.amazonaws\.com', args.host):
        raise ValueError('disposable Stockholm database required')
    secret = json.loads(boto3.client('secretsmanager', region_name='eu-north-1').get_secret_value(SecretId=args.secret)['SecretString'])
    dsn = make_conninfo(host=args.host, dbname='openid_test', user=secret['username'], password=secret['password'],
                       sslmode='verify-full', sslrootcert=args.ca, connect_timeout=10)
    with psycopg.connect(dsn) as db:
        if db.info.server_version // 10000 != 18:
            raise ValueError('PostgreSQL 18 required')
        if db.execute("SELECT count(*) FROM pg_namespace WHERE nspname='openid'").fetchone()[0]:
            raise ValueError('test runner requires an unused database')
        print(json.dumps({'serverVersion': db.info.server_version,
            'tls': db.execute('SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()').fetchone()[0]}), flush=True)
    try:
        with psycopg.connect(dsn, sslmode='disable'):
            raise AssertionError('unencrypted database connection accepted')
    except psycopg.OperationalError:
        print('Unencrypted database connection rejected', flush=True)
    root = Path(__file__).resolve().parents[2]
    env = os.environ | {'OPENID_TEST_POSTGRES': dsn, 'OPENID_TEST_BAO': '/opt/openid-tools/bao',
                        'OPENID_TEST_SOAK_SECONDS': '120', 'OPENID_TEST_REPORT': '/var/tmp/openid-aws/capacity.json'}
    result = subprocess.run([sys.executable, '-m', 'unittest', 'test_cluster', '-v'],
                            cwd=root/'verification', env=env, timeout=1200)
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
