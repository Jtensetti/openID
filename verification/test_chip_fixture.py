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


# Fixture frames are b'a', b'b', b'c' (see capture_ready). A double for the landmark pose check:
# frontal, turned to the subject's right, turned to the left (unmirrored convention).
FIXTURE_ORDER = ['front', 'right', 'left']
FIXTURE_RATIOS = {b'a': 0.0, b'b': -0.25, b'c': 0.25}

def fixture_order():
    return list(FIXTURE_ORDER)

def pose_matcher(matcher):
    matcher.decode_face.side_effect = lambda frame: ('image', frame)
    matcher.pose_ratio.side_effect = lambda face: FIXTURE_RATIOS[face]
    return matcher


def signed(ident, payload):
    return {'id':ident, 'payload':base64.b64encode(json.dumps(payload).encode()).decode(), 'assertion':'test'}


def capture_ready(native, registered, document):
    ident = registered['id']
    result = native.begin_chip(signed(ident, {**registered, **document}))
    capture = native.chip_step({'id':ident, 'chipToken':result['chipToken'], 'sequence':0, 'response':'kAA='})
    return {'id':ident, 'nonce':capture['nonce'], 'frames':['YQ==','Yg==','Yw==']}
