"""Cross-account WORM delivery, custodian confirmation and version-pinned readback.

No AWS resources or credentials are created. Confirmation runs as the configured
custodian role in the archive account, separately from the issuing account.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'verification'))
import audit_archive as archive

UTC = timezone.utc
MIN_DAYS = 1827


def digest(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
        raise ValueError('pinned digest required')
    return value


def timestamp(value):
    result = datetime.fromisoformat(value)
    if result.utcoffset() != timedelta(0): raise ValueError('UTC timestamp required')
    return result


def config(value):
    if type(value) is not dict or set(value) != {'bucket','owner','issuer','custodianRole','region','prefix','days'}:
        raise ValueError('archive configuration')
    if (not re.fullmatch('[a-z0-9][a-z0-9-]{1,61}[a-z0-9]', value['bucket'])
            or any(not re.fullmatch('[0-9]{12}', value[k]) for k in ('owner','issuer'))
            or value['owner'] == value['issuer'] or value['region'] != 'eu-north-1'
            or not re.fullmatch('[a-z0-9-]{1,40}', value['prefix'])
            or not re.fullmatch('arn:aws:iam::'+value['owner']+':role/[A-Za-z0-9_+=,.@/-]{1,128}', value['custodianRole'])
            or type(value['days']) is not int or not MIN_DAYS <= value['days'] <= 3650):
        raise ValueError('separate accounts, custodian role and explicit retention required')
    return value


def identity(sts, cfg, custodian):
    who = sts.get_caller_identity()
    expected = cfg['owner'] if custodian else cfg['issuer']
    if who['Account'] != expected: raise ValueError('unexpected AWS account')
    if custodian:
        name = cfg['custodianRole'].rsplit('/',1)[1]
        if not re.fullmatch('arn:aws:sts::'+expected+':assumed-role/'+re.escape(name)+'/[^/]+', who['Arn']):
            raise ValueError('configured custodian role required')
    return who['Arn']


def bucket_checks(s3, cfg, custodian=False):
    args = {'Bucket':cfg['bucket'], 'ExpectedBucketOwner':cfg['owner']}
    if s3.get_bucket_location(**args).get('LocationConstraint') != cfg['region']:
        raise ValueError('archive region mismatch')
    if s3.get_bucket_versioning(**args).get('Status') != 'Enabled':
        raise ValueError('versioning required')
    public = s3.get_public_access_block(**args)['PublicAccessBlockConfiguration']
    if any(public.get(k) is not True for k in ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')):
        raise ValueError('public access must be blocked')
    if s3.get_bucket_ownership_controls(**args).get('OwnershipControls',{}).get('Rules') != [{'ObjectOwnership':'BucketOwnerEnforced'}]:
        raise ValueError('archive account must control object ownership')
    lock = s3.get_object_lock_configuration(**args)['ObjectLockConfiguration']
    retention = lock.get('Rule',{}).get('DefaultRetention',{})
    if (lock.get('ObjectLockEnabled') != 'Enabled' or retention.get('Mode') != 'COMPLIANCE'
            or type(retention.get('Days')) is not int or retention['Days'] < cfg['days']):
        raise ValueError('COMPLIANCE default retention required')
    if custodian:
        # GetBucketPolicy requires the bucket owner's account. Check the live
        # denial, not just the local template, before trusting receipt provenance.
        policy = archive.decode(s3.get_bucket_policy(**args)['Policy'])
        expected = {'ArnNotEquals':{'aws:PrincipalArn':cfg['custodianRole']}}
        resource = 'arn:aws:s3:::'+cfg['bucket']+'/'+cfg['prefix']+'/receipts/*'
        def guards(statement):
            actions=statement.get('Action',[]);resources=statement.get('Resource',[])
            if isinstance(actions,str):actions=[actions]
            if isinstance(resources,str):resources=[resources]
            return (statement.get('Effect')=='Deny' and statement.get('Principal')=='*'
                and statement.get('Condition')==expected and resource in resources
                and {'s3:PutObject','s3:PutObjectRetention'} <= set(actions))
        if not any(guards(s) for s in policy.get('Statement',[])):
            raise ValueError('live custodian-only receipt policy required')


def read_private(path, maximum=65536):
    path = Path(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with archive.private_open(path.name, directory) as stream: raw = stream.read(maximum+1)
    finally: os.close(directory)
    if len(raw) > maximum: raise ValueError('private document size')
    return raw


def required_until(source, cfg, now):
    latest = now
    for name, columns in archive.TABLES.items():
        if name not in ('credentials','events','activation_proposals','operator_events'): continue
        path = Path(source)/(name+'.jsonl')
        if not path.exists(): continue
        with path.open('rb') as stream:
            for line in stream:
                row = dict(zip(columns, archive.decode(line)))
                for field in ('created','expires','approved_at','time'):
                    value = row.get(field)
                    if value is None: continue
                    instant = datetime.fromtimestamp(value, UTC) if type(value) is int else timestamp(value)
                    if instant > now+timedelta(hours=72): raise ValueError('future register time requires review')
                    latest = max(latest, instant)
    # Leave a full day for independent confirmation; do not round a retention down.
    return (latest+timedelta(days=cfg['days']+1)).replace(hour=0,minute=0,second=0,microsecond=0)+timedelta(days=1)


def version(value):
    # Version IDs are opaque SDK parameters, never filenames or shell input.
    if (not isinstance(value,str) or value == 'null' or not 1 <= len(value.encode('utf-8')) <= 1024
            or any(ord(c)<32 or ord(c)==127 for c in value)):
        raise ValueError('immutable object version required')
    return value


def get_bytes(s3, cfg, key, object_version, expected_sha, size, until, destination=None):
    response = s3.get_object(Bucket=cfg['bucket'], Key=key, VersionId=version(object_version),
                             ExpectedBucketOwner=cfg['owner'])
    body = response['Body']
    try:
        if (response.get('VersionId') != object_version or response.get('ContentLength') != size
                or response.get('ServerSideEncryption') != 'AES256'
                or response.get('ObjectLockMode') != 'COMPLIANCE'
                or response.get('ObjectLockRetainUntilDate',datetime.min.replace(tzinfo=UTC)) < until):
            raise ValueError('stored version, encryption or retention mismatch')
        hashed = hashlib.sha256(); count = 0; chunks = []
        while True:
            chunk = body.read(min(65536,size-count+1))
            if not chunk: break
            count += len(chunk)
            if count > size: raise ValueError('remote object exceeds declared size')
            hashed.update(chunk)
            if destination is not None: destination.write(chunk)
            elif size <= 65536: chunks.append(chunk)
        if count != size or hashed.hexdigest() != digest(expected_sha): raise ValueError('remote content mismatch')
        return b''.join(chunks)
    finally: body.close()


def put(s3, cfg, key, stream, size, sha, until):
    # A single conditional PutObject preserves a precise VersionId. Archives are
    # capped at 1 GiB, below S3's single-request limit; no multipart ambiguity.
    response = s3.put_object(Bucket=cfg['bucket'], Key=key, Body=stream, ContentLength=size,
        ExpectedBucketOwner=cfg['owner'], IfNoneMatch='*', ServerSideEncryption='AES256',
        ChecksumAlgorithm='SHA256', ChecksumSHA256=base64.b64encode(bytes.fromhex(sha)).decode(),
        ObjectLockMode='COMPLIANCE', ObjectLockRetainUntilDate=until)
    ident = version(response.get('VersionId'))
    get_bytes(s3,cfg,key,ident,sha,size,until)
    return ident


def deliver(source, manifest_sha, cfg, s3, sts, *, now=None):
    cfg = config(cfg); now = now or datetime.now(UTC); digest(manifest_sha)
    identity(sts,cfg,False); bucket_checks(s3,cfg)
    result = archive.verify(source,manifest_sha)
    manifest_raw = read_private(Path(source)/'manifest.json')
    if hashlib.sha256(manifest_raw).hexdigest() != manifest_sha: raise ValueError('manifest changed')
    manifest = archive.decode(manifest_raw)
    until = required_until(source,cfg,now)
    transfer = secrets.token_hex(16)
    prefix = cfg['prefix']+'/transfers/'+manifest_sha+'/'+transfer+'/'
    files = {}
    # Commit marker last. Partial delivery never becomes a custodian receipt.
    inventory = {**manifest['files'], 'manifest.json':{'bytes':len(manifest_raw),'sha256':manifest_sha}}
    directory = os.open(source,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name, info in inventory.items():
            with archive.private_open(name,directory) as stream:
                ident = put(s3,cfg,prefix+name,stream,info['bytes'],info['sha256'],until)
            files[name] = {'version':ident,'bytes':info['bytes'],'sha256':info['sha256']}
    finally: os.close(directory)
    return {'format':1,'kind':'DELIVERY','manifestSha256':manifest_sha,'bucket':cfg['bucket'],
        'owner':cfg['owner'],'transfer':transfer,'retainUntil':until.isoformat(),'files':files}


def validate_delivery(value, manifest_sha, cfg):
    if (type(value) is not dict or set(value) != {'format','kind','manifestSha256','bucket','owner','transfer','retainUntil','files'}
            or type(value['format']) is not int or value['format'] != 1 or value['kind'] != 'DELIVERY'
            or value['manifestSha256'] != digest(manifest_sha) or value['bucket'] != cfg['bucket']
            or value['owner'] != cfg['owner'] or not re.fullmatch('[a-f0-9]{32}',value['transfer'])
            or type(value['files']) is not dict or not 4 <= len(value['files']) <= 6
            or 'manifest.json' not in value['files']):
        raise ValueError('delivery binding')
    timestamp(value['retainUntil'])
    for name, info in value['files'].items():
        if name not in {n+'.jsonl' for n in archive.TABLES} | {'manifest.json'}:
            raise ValueError('delivery file inventory')
        if (type(info) is not dict or set(info) != {'version','bytes','sha256'} or type(info['bytes']) is not int
                or not 0 <= info['bytes'] <= archive.MAX_BYTES): raise ValueError('delivery object description')
        version(info['version']); digest(info['sha256'])
    if sum(f['bytes'] for f in value['files'].values()) > archive.MAX_BYTES: raise ValueError('delivery limit')
    if value['files']['manifest.json']['bytes'] > 65536: raise ValueError('manifest limit')


def readback(delivery, manifest_sha, cfg, s3, *, confirm_at=None):
    validate_delivery(delivery,manifest_sha,cfg)
    until = timestamp(delivery['retainUntil'])
    prefix = cfg['prefix']+'/transfers/'+manifest_sha+'/'+delivery['transfer']+'/'
    with tempfile.TemporaryDirectory(prefix='openid-archive-check-') as temporary:
        root = Path(temporary)
        for name, info in delivery['files'].items():
            path = root/name
            with path.open('xb') as stream:
                path.chmod(0o600)
                get_bytes(s3,cfg,prefix+name,info['version'],info['sha256'],info['bytes'],until,stream)
        result = archive.verify(root,manifest_sha)
        if confirm_at is not None and until < required_until(root,cfg,confirm_at)-timedelta(days=1):
            raise ValueError('insufficient remaining retention for confirmation')
    return result


def confirm(delivery, manifest_sha, cfg, s3, sts, *, now=None):
    cfg = config(cfg); now = now or datetime.now(UTC)
    actor = identity(sts,cfg,True); bucket_checks(s3,cfg,True)
    result = readback(delivery,manifest_sha,cfg,s3,confirm_at=now)
    receipt = {'format':1,'kind':'CUSTODIAN_RECEIPT','confirmedAt':now.isoformat(),
               'custodian':actor,'delivery':delivery,'rows':result['rows']}
    raw = archive.encoded(receipt); sha = hashlib.sha256(raw).hexdigest()
    until = timestamp(delivery['retainUntil'])
    key = cfg['prefix']+'/receipts/'+manifest_sha+'/'+secrets.token_hex(16)+'.json'
    import io
    ident = put(s3,cfg,key,io.BytesIO(raw),len(raw),sha,until)
    return {'format':1,'kind':'RECEIPT_LOCATION','key':key,'version':ident,
            'sha256':sha,'bytes':len(raw),'retainUntil':until.isoformat(),'manifestSha256':manifest_sha}


def check(location, manifest_sha, cfg, s3, sts, *, now=None):
    cfg = config(cfg); now = now or datetime.now(UTC)
    identity(sts,cfg,True); bucket_checks(s3,cfg,True); digest(manifest_sha)
    if (type(location) is not dict or set(location) != {'format','kind','key','version','sha256','bytes','retainUntil','manifestSha256'}
            or type(location['format']) is not int or location['format'] != 1
            or location['kind'] != 'RECEIPT_LOCATION' or location['manifestSha256'] != manifest_sha
            or not re.fullmatch(re.escape(cfg['prefix']+'/receipts/'+manifest_sha+'/')+'[a-f0-9]{32}\\.json',location['key'])
            or type(location['bytes']) is not int or not 1 <= location['bytes'] <= 65536):
        raise ValueError('receipt binding')
    until = timestamp(location['retainUntil'])
    if until <= now: raise ValueError('receipt retention expired')
    raw = get_bytes(s3,cfg,location['key'],location['version'],location['sha256'],location['bytes'],until)
    receipt = archive.decode(raw)
    name = cfg['custodianRole'].rsplit('/',1)[1]
    if (type(receipt) is not dict or set(receipt) != {'format','kind','confirmedAt','custodian','delivery','rows'}
            or type(receipt['format']) is not int or receipt['format'] != 1 or receipt['kind'] != 'CUSTODIAN_RECEIPT'
            or not re.fullmatch('arn:aws:sts::'+cfg['owner']+':assumed-role/'+re.escape(name)+'/[^/]+',receipt['custodian'])
            or timestamp(receipt['confirmedAt']) > now+timedelta(minutes=5)
            or receipt['delivery']['retainUntil'] != location['retainUntil']):
        raise ValueError('custodian receipt format')
    result = readback(receipt['delivery'],manifest_sha,cfg,s3)
    if type(receipt['rows']) is not int or receipt['rows'] != result['rows']: raise ValueError('receipt population')
    return {'state':'READABLE','manifestSha256':manifest_sha,'rows':result['rows'],
            'checkedAt':now.isoformat(),'receiptVersion':location['version']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('deliver','confirm','check'))
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--manifest-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--profile')
    args = parser.parse_args()
    try:
        cfg = config(archive.decode(read_private(args.config)))
        # Claim the output before network operations; never repeat a delivery just
        # because its requested local output already exists.
        with args.output.open('xb') as output:
            args.output.chmod(0o600)
            try:
                import boto3
                from botocore.config import Config
                session = boto3.Session(profile_name=args.profile,region_name=cfg['region'])
                options = Config(ignore_configured_endpoint_urls=True,connect_timeout=4,read_timeout=15,
                    retries={'total_max_attempts':3,'mode':'standard'},signature_version='s3v4')
                s3 = session.client('s3',config=options)
                sts = session.client('sts',config=options.merge(Config(signature_version='v4')))
                source = args.source if args.operation=='deliver' else archive.decode(read_private(args.source))
                result = globals()[args.operation](source,args.manifest_sha256,cfg,s3,sts)
                output.write(archive.encoded(result)); output.flush(); os.fsync(output.fileno())
            except BaseException:
                args.output.unlink(); raise
        print('Archive operation verified; private result saved.')
        return 0
    except Exception:
        print('Archive operation failed. No confirmation is implied; inspect private inputs and AWS access.',file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
