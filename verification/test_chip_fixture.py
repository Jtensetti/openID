"""Transport double for application tests; not a cryptographic chip emulator."""
import base64
import json


class ChipFixture:
    def __init__(self, _): self.closed = False
    def next(self, response=None, sequence=None):
        if self.closed: raise ValueError('closed')
        if response is None: return {'type':'command','sequence':0,'command':'AKQMAAI/AA=='}
        if response != 'kAA=' or sequence != 0: raise ValueError('chip rejected')
        return {'type':'verified'}
    def close(self): self.closed = True


def signed(ident, payload):
    return {'id':ident, 'payload':base64.b64encode(json.dumps(payload).encode()).decode(), 'assertion':'test'}


def capture_ready(native, registered, document):
    ident = registered['id']
    result = native.begin_chip(signed(ident, {**registered, **document}))
    capture = native.chip_step({'id':ident, 'chipToken':result['chipToken'], 'sequence':0, 'response':'kAA='})
    return {'id':ident, 'nonce':capture['nonce'], 'frames':['YQ==','Yg==','Yw==']}
