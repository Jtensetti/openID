"""Operator functions use each person's own database login, never a service account."""
import argparse
import sys
import time
import psycopg
from postgres import connection_options
from serve import private_file


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--database-file')
    parser.add_argument('--continuity-file')
    commands=parser.add_subparsers(dest='command',required=True)
    request=commands.add_parser('request');request.add_argument('credential');request.add_argument('reference');request.add_argument('--hours',type=int,default=24)
    approve=commands.add_parser('approve');approve.add_argument('proposal')
    revoke=commands.add_parser('revoke');revoke.add_argument('credential')
    complete=commands.add_parser('complete');complete.add_argument('intent')
    args=parser.parse_args()
    if args.command in ('complete','revoke'):
        from postgres_continuity import configured_client
        if not args.continuity_file:raise ValueError('controller configuration required')
        controller=configured_client(args.continuity_file)
        if args.command=='complete':
            deadline=time.monotonic()+300
            for _ in range(1001):
                if time.monotonic()>=deadline:break
                if controller.advance(args.intent)['completed']:
                    print('COMPLETED');return
            raise ValueError('activation incomplete; resume the same intent')
        controller.revoke(args.credential)
    if not args.database_file:raise ValueError('operator database login required')
    output=None
    with psycopg.connect(**connection_options(private_file(args.database_file).decode().strip())) as db:
        if args.command=='request':
            row=db.execute('SELECT request_activation(%s,%s,%s)',(args.credential,args.reference,args.hours)).fetchone()
            output=row[0]
        elif args.command=='approve':output=db.execute('SELECT approve_activation(%s)',(args.proposal,)).fetchone()[0]
        elif args.command=='revoke':db.execute('SELECT revoke_credential(%s)',(args.credential,))
    if output is not None:print(output)


if __name__=='__main__':
    try:main()
    except Exception:
        print('Operation rejected. Check role, reference and current state.',file=sys.stderr);raise SystemExit(2)
