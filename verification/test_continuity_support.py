"""Explicitly synthetic independent authority; never reachable by production CLI.

The ledger is outside PostgreSQL, including rollback and COPY/restore. DynamoDB
conditional-write behavior is stubbed; the PG, role and Transit tests are real.
"""
import copy
import threading
from revocation import RevocationAuthority
from test_continuity_operator import Client

REFERENCE = 'arn:aws:lambda:eu-north-1:000000000000:function:SYNTHETIC-issuer-authority'


class SyntheticContinuity(Client):
    def __init__(self):
        super().__init__()
        self.lock = threading.RLock()
        self.outage = False
        self.calls = []
        self.hook = None
        self.authority = RevocationAuthority(self.invoke, reference=REFERENCE)

    def invoke(self, request):
        credential, operation = request['credential'], request['operation']
        with self.lock:
            if self.outage:
                raise OSError('synthetic independent outage')
            if operation not in {'status', 'revoke'}:
                raise ValueError('synthetic status/revoke only')
            self.calls.append((operation, credential))
            item = self.items.get(('ledger', credential))
            if operation == 'revoke':
                item = copy.deepcopy(item) if item else {'credential': {'S': credential}}
                item['state'] = {'S': 'REVOKED'}
                self.items[('ledger', credential)] = item
            state = item['state']['S'] if item else 'UNKNOWN'
        if self.hook:
            self.hook(operation, credential)
        return {'credential': credential, 'state': state}

    def transact_write_items(self, **kwargs):
        with self.lock:
            return super().transact_write_items(**kwargs)

    def get_item(self, **kwargs):
        with self.lock:
            return super().get_item(**kwargs)
