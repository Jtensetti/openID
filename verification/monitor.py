"""Scheduled readiness probe with acknowledged, debounced webhook delivery."""
import argparse
import http.client
import json
import os
from pathlib import Path
import ssl
import sys
from urllib.parse import urlsplit
from serve import private_file


def connection(url, ca):
    parsed=urlsplit(url)
    if parsed.scheme!='https' or parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError('HTTPS required; credentials belong in a separate file')
    return http.client.HTTPSConnection(parsed.hostname,parsed.port,timeout=4,context=ssl.create_default_context(cafile=ca)),parsed.path


def read_status(url, ca):
    client,path=connection(url,ca)
    if path:raise ValueError('service origin required')
    try:
        client.request('GET','/health/ready');response=client.getresponse();body=response.read(4097)
        return response.status==200 and len(body)<=4096 and json.loads(body)=={'status':'READY'}
    except Exception:return False
    finally:client.close()


def notify(url, ca, token, label, state):
    client,path=connection(url,ca)
    try:
        client.request('POST',path or '/',json.dumps({'service':label,'state':state}),
            {'Content-Type':'application/json','Authorization':'Bearer '+token})
        response=client.getresponse();response.read(4097)
        if not 200<=response.status<300:raise RuntimeError('alert not acknowledged')
    finally:client.close()


def update(previous, ready):
    failures=0 if ready else min(previous.get('failures',0)+1,3)
    alert=previous.get('alert',False)
    changed=(failures>=3 and not alert) or (ready and alert)
    return {'failures':failures,'alert':failures>=3 or (alert and not ready)},changed


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);args=parser.parse_args()
    config=json.loads(Path(args.config).read_text())
    if set(config)!={'services','webhook','webhookCA','webhookTokenFile','stateFile'}:raise ValueError('configuration')
    state_path=Path(config['stateFile'])
    if not state_path.is_absolute() or state_path.parent.stat().st_mode&0o077:raise ValueError('private state directory required')
    import fcntl,re
    fd=os.open(str(state_path)+'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        previous=json.loads(private_file(state_path)) if state_path.exists() else {}
        result={};failed=False
        for service in config['services']:
            if set(service)!={'label','origin','ca'} or not re.fullmatch('[a-z0-9-]{1,40}',service['label']):raise ValueError('service configuration')
            label=service['label'];ready=read_status(service['origin'],service['ca'])
            value,changed=update(previous.get(label,{}),ready)
            if changed:
                notify(config['webhook'],config['webhookCA'],private_file(config['webhookTokenFile']).decode().strip(),label,
                    'RECOVERED' if ready else 'UNAVAILABLE')
            result[label]=value;failed|=not ready
        # A delivery failure leaves the old state in place for retry on the next invocation.
        fd=os.open(str(state_path)+'.new',os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:json.dump(result,stream);stream.flush();os.fsync(stream.fileno())
        os.replace(str(state_path)+'.new',state_path)
        if failed:raise SystemExit(1)


if __name__=='__main__':
    try:main()
    except Exception:
        print('Monitoring or alert delivery failed.',file=sys.stderr);raise SystemExit(2)
