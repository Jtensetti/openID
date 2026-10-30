"""Explicit synthetic no-erasure assertions for existing recovery regression fixtures.

These helpers are test-only. Production restoration requires the actual current
decision ledger and an independently supplied digest, including when it is empty.
"""
from pathlib import Path
import tempfile
import time

from erasure_policy import LEDGER_FORMAT, write_ledger


def empty_ledger(path):
    return write_ledger(path, {'format': LEDGER_FORMAT, 'authorityReference': 'SYNTHETIC_EMPTY_LEDGER',
        'reviewedAt': int(time.time()), 'decisions': []})


def sqlite_restore(*args, **kwargs):
    from recovery import restore
    with tempfile.TemporaryDirectory() as root:
        path = Path(root)/'decisions.json'; anchor = empty_ledger(path)
        return restore(*args, erasure_ledger=path, erasure_ledger_sha256=anchor, **kwargs)


def postgres_restore(*args, **kwargs):
    from cluster_recovery import restore
    with tempfile.TemporaryDirectory() as root:
        path = Path(root)/'decisions.json'; anchor = empty_ledger(path)
        return restore(*args, erasure_ledger=path, erasure_ledger_sha256=anchor, **kwargs)
