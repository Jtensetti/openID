"""Bounded, restartable profile rewrap and retention jobs. No plaintext access is needed."""
import argparse
import json
from pathlib import Path
import sys
from postgres import PostgresWallet
from serve import private_file
from transit import TransitVault


def maintain(wallet, *, profile_days, event_days, batch=100):
    if any(type(v) is not int or not 1<=v<=3650 for v in (profile_days,event_days)):
        raise ValueError('explicit retention periods required')
    if type(batch) is not int or not 1<=batch<=1000:raise ValueError('batch')
    changed=removed=0
    latest=wallet.vault.request('transit/keys/openid-profile')['latest_version']
    with wallet.transaction() as db:
        # One short batch per job; an interrupted transaction is safely resumed by the next invocation.
        rows=db.execute("SELECT * FROM profiles WHERE split_part(sealed::jsonb->>'transit',':',2)!=? ORDER BY credential LIMIT ? FOR UPDATE SKIP LOCKED",
            ('v'+str(latest),batch)).fetchall()
        for row in rows:
            sealed=wallet.vault.rewrap(row['credential'],row['person'],json.loads(row['sealed']))
            db.execute('UPDATE profiles SET sealed=? WHERE credential=?',(json.dumps(sealed),row['credential']));changed+=1
    with wallet.transaction() as db:
        removed=db.execute('SELECT purge_expired(?,?,?)',(profile_days,event_days,batch)).fetchone()[0]
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
