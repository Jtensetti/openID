"""Operator and relying-party commands for the local wallet database."""
import argparse
import json
import sys
from pathlib import Path
from wallet import Wallet

def main():
    parser = argparse.ArgumentParser(description='openID private pilot operations')
    parser.add_argument('--db', required=True, type=Path)
    sub = parser.add_subparsers(dest='operation', required=True)
    sub.add_parser('pending')
    activate = sub.add_parser('activate')
    activate.add_argument('credential')
    activate.add_argument('--decision', required=True, help='Non-personal review reference, not a name/passport number')
    activate.add_argument('--hours', type=int, default=24)
    activate.add_argument('--private-pilot-only', action='store_true', required=True)
    revoke = sub.add_parser('revoke'); revoke.add_argument('credential')
    request = sub.add_parser('request'); request.add_argument('credential')
    result = sub.add_parser('consume'); result.add_argument('request')
    args = parser.parse_args()
    if not args.db.is_file():parser.error('Existing wallet database required')
    wallet = Wallet(args.db, 'local-operator')
    try:
        if args.operation == 'pending':
            with wallet.transaction() as db:
                value = [dict(row) for row in db.execute("SELECT id,state,created FROM credentials WHERE state='PENDING_REVIEW'")]
        elif args.operation == 'activate':
            wallet.activate(args.credential, args.decision, args.hours); value={'state':'ACTIVE','scope':'PRIVATE_PILOT'}
        elif args.operation == 'revoke':
            wallet.revoke(args.credential); value={'state':'REVOKED'}
        elif args.operation == 'request':value=wallet.start_request(args.credential)
        else:
            # Secret via stdin rather than command line / shell history / process listing.
            secret=sys.stdin.readline(128).strip()
            value=wallet.consume_result(args.request,secret)
        print(json.dumps(value,indent=2))
    except (ValueError, OSError):
        print('Operation rejected; no credential activated or authentication returned.',file=sys.stderr)
        raise SystemExit(2)

if __name__=='__main__':main()
