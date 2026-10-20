"""Capacity probe: real signatures and SQLite contention, generated keys only."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import statistics
import tempfile
import time
from wallet import Wallet
from test_wallet import crypt
from test_identity import document


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--requests',type=int,default=100)
    parser.add_argument('--concurrency',type=int,default=8)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if not 1<=args.requests<=10000 or not 1<=args.concurrency<=32:parser.error('Bounded probe required')
    with tempfile.TemporaryDirectory(prefix='openid-load-') as temp:
        wallet=Wallet(Path(temp)/'wallet.sqlite','https://localhost:8765')
        key=json.loads(crypt(op='new'));ident=wallet.enroll(key['publicKey'], document())['id']
        wallet.activate(ident,'LOAD-GENERATED-KEY')
        def operation(_):
            start=time.monotonic()
            challenge=wallet.challenge({'credentialId':ident,'action':'snapshot','requestId':None})
            signature=crypt(op='sign',key=key['privateKey'],payload=challenge['signingInput'])
            result=wallet.execute({'challengeId':challenge['id'],'signature':signature})
            if result['state']!='ACTIVE':raise AssertionError('Unexpected state')
            return (time.monotonic()-start)*1000
        start=time.monotonic()
        with ThreadPoolExecutor(args.concurrency) as pool:latencies=list(pool.map(operation,range(args.requests)))
        elapsed=time.monotonic()-start
        request=wallet.start_request(ident)
        challenge=wallet.challenge({'credentialId':ident,'action':'approve','requestId':request['id']})
        wallet.execute({'challengeId':challenge['id'],'signature':crypt(op='sign',key=key['privateKey'],payload=challenge['signingInput'])})
        def consume(_):
            try:Wallet(wallet.path,wallet.origin).consume_result(request['id'],request['secret']);return 1
            except ValueError:return 0
        with ThreadPoolExecutor(32) as pool:winners=sum(pool.map(consume,range(32)))
        if winners!=1:raise AssertionError('One-shot violated under contention')
        wallet.revoke(ident)
        def check(_):
            try:Wallet(wallet.path,wallet.origin).check_session(ident,'no-session');return 1
            except ValueError:return 0
        with ThreadPoolExecutor(32) as pool:accepted=sum(pool.map(check,range(32)))
        if accepted:raise AssertionError('Revoked key accepted')
        ordered=sorted(latencies)
        report={'scope':'real P-256 signatures, encrypted profile reads and SQLite; excludes HTTP, passport, App Attest and biometric enrollment',
            'requests':args.requests,'concurrency':args.concurrency,'seconds':round(elapsed,3),
            'requestsPerSecond':round(args.requests/elapsed,2),'latencyMs':{'p50':round(statistics.median(latencies),2),
            'p95':round(ordered[min(len(ordered)-1,int(len(ordered)*.95))],2),'max':round(max(latencies),2)},
            'errors':0,'parallelConsumers':32,'consumptionWinners':winners,'acceptedAfterRevocation':accepted,
            'logicalCPUs':os.cpu_count()}
        text=json.dumps(report,indent=2)
        print(text)
        if args.output:args.output.write_text(text+'\n')


if __name__=='__main__':main()
