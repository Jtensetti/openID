"""Export committed activation notices to SQS; never perform ID activation."""
import json
import os
import re
import signal
import threading
from notices import submit
from revocation import configured_wallet


def main():
    import boto3
    from botocore.config import Config
    url = os.environ['OPENID_NOTICE_QUEUE_URL']
    if not re.fullmatch(r'https://sqs\.eu-north-1\.amazonaws\.com/[0-9]{12}/[A-Za-z0-9_-]{1,80}', url):
        raise ValueError('canonical notice queue URL required')
    if not os.environ.get('OPENID_CONTINUITY_CONFIG'):
        raise ValueError('continuity configuration required')
    client = boto3.client('sqs', region_name='eu-north-1',
        endpoint_url='https://sqs.eu-north-1.amazonaws.com',
        config=Config(connect_timeout=2, read_timeout=3, retries={'total_max_attempts': 1}))
    wallet = configured_wallet('/srv/openid/data/wallet.sqlite', 'notice-exporter')
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT): signal.signal(sig, lambda *_: stop.set())
    def send(event):
        return client.send_message(QueueUrl=url, MessageBody=json.dumps(event))['MessageId']
    while not stop.is_set():
        try:
            with wallet.transaction() as db: submit(db, send, limit=1)
        except Exception:
            print('notice export unavailable', flush=True)
        stop.wait(10)
    # Best-effort drain before the scheduled EC2 shutdown. Unacknowledged jobs
    # remain durable locally and are retried after restart, never marked sent.
    for _ in range(10):
        try:
            with wallet.transaction() as db:
                if not db.execute("SELECT 1 FROM notice_outbox WHERE status='PENDING' AND attempts<5 LIMIT 1").fetchone():
                    break
                submit(db, send, limit=1)
        except Exception:
            print('notice shutdown drain unavailable', flush=True)
            break


if __name__ == '__main__': main()
