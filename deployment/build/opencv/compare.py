"""Fail closed on mismatched inputs or model/codec regressions in CI evidence."""
import base64
import json
import math
from pathlib import Path
import re
import sys


def compare(reference, candidate):
    for report, kind in ((reference, 'reference'), (candidate, 'candidate')):
        assert report['format'] == 1 and report['kind'] == kind and report['passed'] is True
        assert report['version'] == '4.14.0'
    assert reference['fixturesSHA256'] == candidate['fixturesSHA256']
    assert re.fullmatch('[a-f0-9]{64}', candidate['fixturesSHA256'])
    assert reference['modelSHA256'] == candidate['modelSHA256'] and len(candidate['modelSHA256']) == 4
    assert set(candidate['modules']) == {'core', 'imgproc', 'imgcodecs', 'dnn', 'objdetect',
                                         'calib3d', 'features2d', 'flann', 'python3'}
    assert Path(candidate['module']).parent == Path('/opt/openid-opencv/python')
    assert all(candidate['writers'][e] is False for e in ('.png', '.tiff', '.webp', '.exr'))
    assert all(candidate['writers'][e] is True for e in ('.jpg', '.jp2'))
    for extension in ('.jpg', '.jp2', '.j2k'):
        a = base64.b64decode(reference['decoded'][extension], validate=True)
        b = base64.b64decode(candidate['decoded'][extension], validate=True)
        assert len(a) == len(b) == 240*320*3
        delta = [abs(x-y) for x, y in zip(a, b)]
        if extension == '.jpg':
            assert max(delta) <= 3 and sum(delta)/len(delta) <= 1
        else:
            assert not any(delta)
    assert len(reference['features']) == len(candidate['features']) == 3
    max_feature_delta = 0.0
    for a, b in zip(reference['features'], candidate['features']):
        assert len(a) == len(b) == 128
        assert all(math.isfinite(v) for v in a+b)
        max_feature_delta = max(max_feature_delta, max(abs(x-y) for x, y in zip(a, b)))
    assert max_feature_delta <= 1e-4, ('SFace regression', max_feature_delta)
    a, b = reference['padScores'], candidate['padScores']
    assert len(a) == len(b) == 2 and all(math.isfinite(v) and 0 <= v <= 1 for v in a+b)
    max_pad_delta = max(abs(x-y) for x, y in zip(a, b))
    assert max_pad_delta <= 1e-6, ('PAD regression', max_pad_delta)
    a, b = reference['jpegDecodeMedianSeconds'], candidate['jpegDecodeMedianSeconds']
    assert math.isfinite(a) and math.isfinite(b) and a > 0 and b > 0
    assert b <= a*3+0.02, ('JPEG decode regression', a, b)
    return {'format': 1, 'passed': True, 'maxFeatureDelta': max_feature_delta,
            'maxPadDelta': max_pad_delta, 'jpegDecodeRatio': b/a,
            'limits': ['Small generated compatibility corpus; not biometric validation or independent review.']}


if __name__ == '__main__':
    import hashlib
    directory = Path(sys.argv[1])
    reference = json.loads((directory/'reference.json').read_text())
    candidate = json.loads((directory/'candidate.json').read_text())
    assert reference['fixturesSHA256'] == hashlib.sha256((directory/'fixtures.json').read_bytes()).hexdigest()
    result = compare(reference, candidate)
    result['files'] = {name: hashlib.sha256((directory/name).read_bytes()).hexdigest()
                       for name in ('reference.json', 'candidate.json', 'fixtures.json',
                                    'reference-image-id.txt', 'candidate-image-id.txt',
                                    'tested-revision.txt', 'native/manifest.json')}
    (directory/'comparison.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))
