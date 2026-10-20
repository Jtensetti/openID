"""Operator functions use each person's own database login, never a service account."""
import argparse
import sys
import psycopg
from postgres import connection_options
from serve import private_file


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--database-file',required=True)
    commands=parser.add_subparsers(dest='command',required=True)
    request=commands.add_parser('request');request.add_argument('credential');request.add_argument('reference');request.add_argument('--hours',type=int,default=24)
    approve=commands.add_parser('approve');approve.add_argument('proposal')
    revoke=commands.add_parser('revoke');revoke.add_argument('credential')
    commands.add_parser('revoke-after-restore')
    args=parser.parse_args()
    with psycopg.connect(**connection_options(private_file(args.database_file).decode().strip())) as db:
        if args.command=='request':
            row=db.execute('SELECT request_activation(%s,%s,%s)',(args.credential,args.reference,args.hours)).fetchone()
            print(row[0])
        elif args.command=='approve':db.execute('SELECT approve_activation(%s)',(args.proposal,))
        elif args.command=='revoke':db.execute('SELECT revoke_credential(%s)',(args.credential,))
        else:db.execute('SELECT revoke_all_after_restore()')


if __name__=='__main__':
    try:main()
    except Exception:
        print('Operation rejected. Check role, reference and current state.',file=sys.stderr);raise SystemExit(2)
