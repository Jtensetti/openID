"""Explicit retention of expired consent evidence; no automatic schedule or legal decision.

Plan is read-only. Apply is one bounded transaction with a durable policy journal.
Credentials, revocation, identity profiles and authentication history are untouched.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time

from enrollment_policy import canonical, unique_object
from sqlite_retention import database_identity

DAY = 86400
TABLES = ('credential_consents', 'enrollment_consents', 'enrollment_policies')
FIELDS = {'version','reference','regime','unboundDays','boundDays','protectedReceipts'}


def policy(value):
    if (not isinstance(value,dict) or set(value)!=FIELDS or type(value['version']) is not int or value['version']!=1
            or not isinstance(value['reference'],str) or not re.fullmatch('[A-Za-z0-9_-]{8,96}',value['reference'])
            or value['regime'] not in ('private-beta','digg')
            or any(type(value[k]) is not int or not 1<=value[k]<=3650 for k in ('unboundDays','boundDays'))
            or (value['regime']=='digg' and value['boundDays']<1827)
            or not isinstance(value['protectedReceipts'],list) or len(value['protectedReceipts'])>1000
            or any(not isinstance(v,str) or not re.fullmatch('[a-f0-9]{64}',v) for v in value['protectedReceipts'])
            or len(set(value['protectedReceipts']))!=len(value['protectedReceipts'])):
        raise ValueError('explicit consent retention policy required')
    return json.loads(canonical(value))


def read_policy(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_mode&0o077
                or info.st_uid not in (0,os.geteuid())):raise ValueError('private policy file required')
        raw=stream.read(131073)
    if len(raw)>131072:raise ValueError('policy size')
    return policy(json.loads(raw,object_pairs_hook=unique_object))


def install_sqlite(db):
    db.execute('''CREATE TABLE IF NOT EXISTS consent_retention_runs (
        id INTEGER PRIMARY KEY, time INTEGER NOT NULL, policy TEXT NOT NULL,
        policy_sha256 TEXT NOT NULL, counts TEXT NOT NULL)''')


def validate_journal(row):
    ident,at,raw,digest,counts=row
    if (type(ident) is not int or ident<1 or type(at) is not int or not 0<=at<=253402300799
            or not isinstance(raw,str) or len(raw.encode())>131072 or not isinstance(counts,str)):
        raise ValueError('consent retention journal')
    config=policy(json.loads(raw,object_pairs_hook=unique_object))
    if raw!=canonical(config).decode() or hashlib.sha256(raw.encode()).hexdigest()!=digest:
        raise ValueError('consent retention policy hash')
    values=json.loads(counts,object_pairs_hook=unique_object)
    if (not isinstance(values,dict) or set(values)!=set(TABLES)
            or any(type(v) is not int or not 0<=v<=1000 for v in values.values())):
        raise ValueError('consent retention counts')


def authorize(action,table,column,database,source):
    if source is not None:return sqlite3.SQLITE_DENY
    if action==sqlite3.SQLITE_DELETE:
        return sqlite3.SQLITE_OK if database=='main' and table in TABLES else sqlite3.SQLITE_DENY
    if action==sqlite3.SQLITE_INSERT:
        return sqlite3.SQLITE_OK if database=='main' and table=='consent_retention_runs' else sqlite3.SQLITE_DENY
    if action in (sqlite3.SQLITE_READ,sqlite3.SQLITE_SELECT,sqlite3.SQLITE_FUNCTION,sqlite3.SQLITE_TRANSACTION):return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def sqlite_maintain(path,config,*,apply=False,batch=100,clock=time.time):
    config=policy(config)
    if type(apply) is not bool or type(batch) is not int or not 1<=batch<=1000:raise ValueError('retention mode or batch')
    now=int(clock())
    if not 0<=now<=253402300799:raise ValueError('retention clock')
    path=Path(path).absolute();identity=database_identity(path)
    db=sqlite3.connect(path.as_uri()+('?mode=rw' if apply else '?mode=ro'),uri=True,isolation_level=None,timeout=3)
    end=time.monotonic()+10
    try:
        if database_identity(path)!=identity:raise ValueError('database replaced')
        db.set_progress_handler(lambda:int(time.monotonic()>=end),1000)
        db.execute('PRAGMA foreign_keys=ON')
        if apply:
            db.execute('PRAGMA synchronous=EXTRA');db.execute('PRAGMA secure_delete=ON')
        else:db.execute('PRAGMA query_only=ON')
        if db.execute('PRAGMA foreign_keys').fetchone()[0]!=1:raise ValueError('foreign keys unavailable')
        if apply and (db.execute('PRAGMA synchronous').fetchone()[0]!=3 or db.execute('PRAGMA secure_delete').fetchone()[0]!=1):
            raise ValueError('durability or secure deletion unavailable')
        db.execute('BEGIN IMMEDIATE' if apply else 'BEGIN')
        required=set(TABLES)|{'credentials','events','consent_retention_runs'}
        objects=dict(db.execute('SELECT name,type FROM sqlite_master'))
        if any(objects.get(t)!='table' for t in required):raise ValueError('current consent schema required')
        expected_links={'enrollment_policies':set(),'enrollment_consents':{('policy_digest','enrollment_policies','digest')},
            'credential_consents':{('credential','credentials','id'),('receipt','enrollment_consents','id')},
            'consent_retention_runs':set()}
        for table,expected in expected_links.items():
            links=list(db.execute('PRAGMA foreign_key_list('+table+')'))
            if ({(r[3],r[2],r[4]) for r in links}!=expected
                    or any(r[5]!='NO ACTION' or r[6]!='NO ACTION' for r in links)):
                raise ValueError('unexpected retention relationships')
        # Any trigger on selected tables could create a hidden cascade before the
        # authorizer sees it. Deny instead of running unknown executable schema.
        if db.execute('SELECT 1 FROM sqlite_master WHERE type=? AND tbl_name IN (?,?,?,?)',
            ('trigger',*TABLES,'consent_retention_runs')).fetchone():raise ValueError('unexpected retention trigger')
        db.set_authorizer(authorize)
        holds=config['protectedReceipts'];exclude=''
        if holds:exclude='AND e.id NOT IN ('+','.join('?' for _ in holds)+')'
        rows=db.execute(f'''SELECT e.id,b.credential FROM enrollment_consents e
            LEFT JOIN credential_consents b ON b.receipt=e.id LEFT JOIN credentials c ON c.id=b.credential
            WHERE typeof(e.accepted)='integer' AND e.accepted>=0 AND e.accepted<=?
              AND (e.withdrawn IS NULL OR (typeof(e.withdrawn)='integer' AND e.withdrawn>=e.accepted AND e.withdrawn<=?))
              AND ((b.receipt IS NULL AND max(e.accepted+300,coalesce(e.withdrawn,0))<?)
                OR (b.receipt IS NOT NULL AND typeof(c.created)='integer' AND c.created>=0 AND c.created<=?
                  AND ((c.expires IS NULL AND c.state IN ('PENDING_REVIEW','REVOKED'))
                    OR (typeof(c.expires)='integer' AND c.expires>=c.created AND c.state IN ('ACTIVE','REVOKED')))
                  AND max(e.accepted,coalesce(e.withdrawn,0),coalesce(c.expires,c.created+86400),
                    coalesce((SELECT max(time) FROM events WHERE credential=c.id),0))<?))
              {exclude} ORDER BY e.id LIMIT ?''',
            (now,now,now-config['unboundDays']*DAY,now,now-config['boundDays']*DAY,*holds,batch+1)).fetchall()
        selected=rows[:batch];ids=[r[0] for r in selected]
        counts={'credential_consents':sum(r[1] is not None for r in selected),'enrollment_consents':len(ids),'enrollment_policies':0}
        # Policy text is removed only when expired and no receipt will reference
        # it after this batch. Current texts remain available during enrollment.
        pending='AND e.id NOT IN ('+','.join('?' for _ in ids)+')' if ids else ''
        eligible_policies=[r[0] for r in db.execute(f'''SELECT p.digest FROM enrollment_policies p
            WHERE json_valid(p.record) AND json_type(p.record,'$.notice.notAfter')='integer'
              AND json_extract(p.record,'$.notice.notAfter') BETWEEN 0 AND ?
              AND NOT EXISTS(SELECT 1 FROM enrollment_consents e WHERE e.policy_digest=p.digest {pending})
            ORDER BY p.digest LIMIT ?''',(now,*ids,batch+1))]
        policy_ids=eligible_policies[:batch]
        counts['enrollment_policies']=len(policy_ids)
        raw_policy=canonical(config).decode();digest=hashlib.sha256(raw_policy.encode()).hexdigest()
        result={'mode':'apply' if apply else 'plan','time':now,'policyReference':config['reference'],
            'policySHA256':digest,'selected':counts,'moreEligible':len(rows)>batch or len(eligible_policies)>batch,'batch':batch}
        if apply:
            for table,key,values in (('credential_consents','receipt',ids),('enrollment_consents','id',ids),('enrollment_policies','digest',policy_ids)):
                removed=db.executemany(f'DELETE FROM {table} WHERE {key}=?',[(v,) for v in values]).rowcount
                if removed!=counts[table]:raise ValueError('consent retention count mismatch')
            entry=db.execute('INSERT INTO consent_retention_runs(time,policy,policy_sha256,counts) VALUES(?,?,?,?)',
                (now,raw_policy,digest,canonical(counts).decode()))
            result['journalId']=entry.lastrowid
        if time.monotonic()>=end or database_identity(path)!=identity:raise ValueError('retention deadline or database identity')
        db.execute('COMMIT');return result
    finally:
        db.set_progress_handler(None,0)
        if db.in_transaction:db.execute('ROLLBACK')
        db.close()


def postgres_maintain(dsn,config,*,apply=False,batch=100,local_test=False):
    import psycopg
    from postgres import connection_options
    config=policy(config)
    if type(apply) is not bool or type(batch) is not int or not 1<=batch<=1000:raise ValueError('retention mode or batch')
    with psycopg.connect(**connection_options(dsn,local_test)) as db:
        if not apply:db.execute('SET TRANSACTION READ ONLY')
        return db.execute('SELECT retain_consent_evidence(%s,%s,%s)',(canonical(config).decode(),apply,batch)).fetchone()[0]


def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('plan','apply'))
    database=parser.add_mutually_exclusive_group(required=True)
    database.add_argument('--db',type=Path);database.add_argument('--database-file',type=Path)
    parser.add_argument('--policy',type=Path,required=True);parser.add_argument('--batch',type=int,default=100)
    args=parser.parse_args();config=read_policy(args.policy)
    if args.db:result=sqlite_maintain(args.db,config,apply=args.action=='apply',batch=args.batch)
    else:
        from serve import private_file
        result=postgres_maintain(private_file(args.database_file).decode().strip(),config,apply=args.action=='apply',batch=args.batch)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    try:main()
    except Exception:
        print('Consent retention failed; no sensitive details logged.',file=sys.stderr);raise SystemExit(2)
