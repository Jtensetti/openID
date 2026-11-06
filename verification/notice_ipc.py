"""Least-privilege notification outbox socket for an untrusted exporter.

No credentials, identity profiles, keys, activation or revocation operations.
"""
import os
import re
from ipc_support import LocalService

REFERENCE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
EVENT = re.compile(r"^[a-f0-9]{64}$")


def dispatch(wallet, request):
    op = request.get("operation")
    if op == "next" and set(request) == {"operation"}:
        with wallet.transaction() as db:
            row = db.execute(
                "SELECT event,contact_version,kind,created FROM notice_outbox "
                "WHERE status='PENDING' AND attempts<5 ORDER BY created,event LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            return {"event": row["event"], "contactVersion": row["contact_version"],
                    "kind": row["kind"], "created": row["created"]}
    if op in ("ack", "fail"):
        expected = {"operation", "event", "receipt"} if op == "ack" else {"operation", "event"}
        if set(request) != expected or not isinstance(request["event"], str) or not EVENT.fullmatch(request["event"]):
            raise ValueError("outbox event")
        if op == "ack" and (not isinstance(request["receipt"], str) or not REFERENCE.fullmatch(request["receipt"])):
            raise ValueError("queue receipt")
        with wallet.transaction() as db:
            if op == "ack":
                result = db.execute(
                    "UPDATE notice_outbox SET status='QUEUED', attempts=attempts+1, accepted_reference=? "
                    "WHERE event=? AND status='PENDING' AND attempts<5",
                    (request["receipt"], request["event"]))
            else:
                result = db.execute(
                    "UPDATE notice_outbox SET attempts=attempts+1 "
                    "WHERE event=? AND status='PENDING' AND attempts<5", (request["event"],))
            return {"updated": result.rowcount == 1}
    raise ValueError("unsupported outbox operation")


def serve(path, group, wallet):
    return LocalService(path, group, lambda data: dispatch(wallet, data))
