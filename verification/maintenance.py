"""Bounded, restartable profile rewrap and retention jobs. No plaintext access is needed."""
import argparse
import json
from pathlib import Path
import sys
import time
from postgres import PostgresWallet
from serve import private_file
from transit import TransitVault


def maintain(wallet, *, profile_days, event_days, batch=100):
    if any(type(v) is not int or not 1<=v<=3650 for v in (profile_days,event_days)):
        raise ValueError('explicit retention periods required')
    if type(batch) is not int or not 1<=batch<=1000:raise ValueError('batch')
    now=int(time.time()); changed=removed=0
    latest=wallet.vault.request('transit/keys/openid-profile')['latest_version']
    with wallet.transaction() as db:
        # One short batch per job; an interrupted transaction is safely resumed by the next invocation.
        rows=db.execute("SELECT * FROM profiles WHERE split_part(sealed::jsonb->>'transit',':',2)!=? ORDER BY credential LIMIT ? FOR UPDATE SKIP LOCKED",
            ('v'+str(latest),batch)).fetchall()
        for row in rows:
            sealed=wallet.vault.rewrap(row['credential'],row['person'],json.loads(row['sealed']))
            db.execute('UPDATE profiles SET sealed=? WHERE credential=?',(json.dumps(sealed),row['credential']));changed+=1
    with wallet.transaction() as db:
        # Retain tombstones and person links; deleting a profile never makes an old key enrollable again.
        removed+=db.execute('''DELETE FROM profiles WHERE credential IN (
            SELECT p.credential FROM profiles p JOIN credentials c ON c.id=p.credential
            WHERE coalesce(c.expires,c.created+86400)<? ORDER BY p.credential LIMIT ? FOR UPDATE OF p SKIP LOCKED)''',
            (now-profile_days*86400,batch)).rowcount
        for table,field,cutoff in (('challenges','expires',now),('requests','expires',now-3600),
            ('federation_requests','expires',now-3600),('events','time',now-event_days*86400),
            ('activation_proposals','expires',now-event_days*86400)):
            # Table/column names are fixed above, never taken from configuration or requests.
            removed+=db.execute(f'DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE {field}<? ORDER BY id LIMIT ? FOR UPDATE SKIP LOCKED)',
                (cutoff,batch)).rowcount
        db.execute('INSERT INTO maintenance_runs VALUES(1,clock_timestamp(),?) ON CONFLICT(id) DO UPDATE SET completed_at=excluded.completed_at,removed=excluded.removed',(removed,))
    return {'rewrapped':changed,'removed':removed}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True)
    parser.add_argument('--profile-days',type=int,required=True);parser.add_argument('--event-days',type=int,required=True)
    args=parser.parse_args();config=json.loads(Path(args.config).read_text())
    if set(config)!={'databaseFile','baoAddress','baoTokenFile','baoCA'}:raise ValueError('configuration fields')
    vault=TransitVault(config['baoAddress'],config['baoTokenFile'],config['baoCA'])
    wallet=PostgresWallet(private_file(config['databaseFile']).decode().strip(),'maintenance',vault)
    try:print(json.dumps(maintain(wallet,profile_days=args.profile_days,event_days=args.event_days)))
    finally:wallet.close()


if __name__=='__main__':
    try:main()
    except Exception:
        print('Maintenance failed; no sensitive details logged.',file=sys.stderr);raise SystemExit(2)
