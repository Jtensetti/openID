"""Export committed activation notices to SQS with no access to passport data.

The private wallet service owns the outbox. An exporter has only permission
to fetch opaque queue events and acknowledge their receipt over a Unix socket.
"""
import json
import os
import re
import signal
import threading
from ipc_support import request


def deliver_once(socket_path, sqs_client, queue_url):
    item = request(socket_path, {"operation": "next"})
    if item is None:
        return False
    if not isinstance(item, dict) or set(item) != {"event", "contactVersion", "kind", "created"}:
        raise ValueError("unexpected outbox event")
    try:
        response = sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(item))
        receipt = response["MessageId"]
    except Exception:
        # Failure count is persisted by the wallet, never by this exporter.
        request(socket_path, {"operation":"fail", "event":item["event"]})
        raise
    # If the process crashes after SQS accepted the event, retry uses the SAME
    # event ID. The queue consumer must deduplicate it.
    response = request(socket_path, {"operation":"ack", "event":item["event"], "receipt":receipt})
    if response != {"updated": True}:
        raise ValueError("notice acknowledgement refused")
    return True


def main():
    import boto3
    from botocore.config import Config
    url = os.environ["OPENID_NOTICE_QUEUE_URL"]
    sock = os.environ["OPENID_NOTICE_SOCKET"]
    if not re.fullmatch(r"https://sqs\.eu-north-1\.amazonaws\.com/[0-9]{12}/[A-Za-z0-9_-]{1,80}", url):
        raise ValueError("canonical notice queue URL required")
    client = boto3.client("sqs", region_name="eu-north-1",
        endpoint_url="https://sqs.eu-north-1.amazonaws.com",
        config=Config(connect_timeout=2, read_timeout=3, retries={"total_max_attempts":1}))
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    while not stop.is_set():
        try:
            deliver_once(sock, client, url)
        except Exception:
            print("notice export unavailable", flush=True)
        stop.wait(10)
    for _ in range(10):
        try:
            if not deliver_once(sock, client, url):
                break
        except Exception:
            print("notice shutdown drain unavailable", flush=True)
            break


if __name__ == "__main__":
    main()
