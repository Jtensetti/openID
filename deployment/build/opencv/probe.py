"""Compare native candidates using generated pixels, never identity documents."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import statistics
import sys
import time
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('kind', choices=('reference', 'candidate'))
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    if args.kind == 'candidate':
        sys.path.insert(0, '/opt/openid-opencv/python')
    sys.path.append('/app/verification')
    # Set allocator limits before importing the native decoder.
    from image_input import decode_bounded_image
    import cv2
    import numpy as np
    from face import FaceMatcher, FaceRejected, MODELS as FACE_MODELS
    from identity import VerifiedDocument
    from pad import PresentationAttackDetector, MODELS as PAD_MODELS
    assert cv2.__version__ == '4.14.0'
    module = Path(cv2.__file__).resolve()
    if args.kind == 'candidate':
        assert module.parent == Path('/opt/openid-opencv/python')
        native_root = Path('/opt/openid-opencv')
        manifest = json.loads((native_root/'evidence/manifest.json').read_text())
        assert manifest['candidateOnly'] is True
        for relative, expected in manifest['files'].items():
            assert not relative.startswith('/') and '..' not in Path(relative).parts
            assert hashlib.sha256((native_root/relative).read_bytes()).hexdigest() == expected
    else:
        assert str(module).startswith('/usr/local/lib/python3.12/site-packages/cv2/')
    cv2.setNumThreads(1)
    rows, columns = np.indices((240, 320), dtype=np.uint16)
    pixels = np.stack(((columns*3) % 256, (rows*2) % 256, (rows+columns) % 256), axis=2).astype(np.uint8)
    fixtures_path = args.directory/'fixtures.json'
    if args.kind == 'reference':
        fixtures = {}
        for extension in ('.jpg', '.jp2', '.png', '.bmp', '.tiff', '.webp', '.ppm'):
            options = [cv2.IMWRITE_JPEG2000_COMPRESSION_X1000, 1000] if extension == '.jp2' else []
            ok, encoded = cv2.imencode(extension, pixels, options)
            assert ok
            assert cv2.imdecode(encoded, cv2.IMREAD_COLOR).shape == pixels.shape
            fixtures[extension] = base64.b64encode(encoded).decode()
        jp2 = base64.b64decode(fixtures['.jp2'])
        offset = 0
        while offset < len(jp2):
            size = int.from_bytes(jp2[offset:offset+4], 'big')
            assert 8 <= size <= len(jp2)-offset
            if jp2[offset+4:offset+8] == b'jp2c':
                fixtures['.j2k'] = base64.b64encode(jp2[offset+8:offset+size]).decode()
            offset += size
        assert '.j2k' in fixtures
        fixtures_path.write_text(json.dumps(fixtures, sort_keys=True)+'\n')
    fixtures_bytes = fixtures_path.read_bytes()
    fixtures = json.loads(fixtures_bytes)
    assert set(fixtures) == {'.jpg', '.jp2', '.j2k', '.png', '.bmp', '.tiff', '.webp', '.ppm'}
    decoded = {}
    for extension in ('.jpg', '.jp2', '.j2k'):
        raw = base64.b64decode(fixtures[extension], validate=True)
        image = decode_bounded_image(raw)
        assert image.shape == pixels.shape
        if extension != '.jpg':
            np.testing.assert_array_equal(image, pixels)
        decoded[extension] = base64.b64encode(image.tobytes()).decode()
        profile = VerifiedDocument(raw, {'givenNames': 'SYNTHETIC', 'familyName': 'TEST',
            'birthDateMrz': '900101', 'nationality': 'UTO', 'issuingState': 'UTO',
            'documentNumber': 'TEST00001', 'documentExpires': '2030-10-19'}).profile()
        thumbnail = base64.b64decode(profile['portraitJpeg'], validate=True)
        assert len(thumbnail) <= 24_000 and max(decode_bounded_image(thumbnail).shape[:2]) <= 224
        assert 'documentNumber' not in profile
    for extension in ('.png', '.bmp', '.tiff', '.webp', '.ppm'):
        with patch.object(cv2, 'imdecode') as decoder:
            try:
                decode_bounded_image(base64.b64decode(fixtures[extension], validate=True))
            except ValueError as error:
                assert str(error) == 'IMAGE_REJECTED'
            else:
                raise AssertionError('disallowed format accepted')
            decoder.assert_not_called()
    for raw in (b'\xff\xd8\xff', b'\xff\x4f\xff\x51', b'x'*2_000_001):
        try:
            decode_bounded_image(raw)
        except ValueError:
            pass
        else:
            raise AssertionError('corrupt or oversized image accepted')
    oversized = cv2.imencode('.jpg', np.zeros((1, 4097, 3), np.uint8))[1].tobytes()
    try:
        decode_bounded_image(oversized)
    except ValueError:
        pass
    else:
        raise AssertionError('native dimension limit lost')

    models = Path('/app/verification/models')
    model_hashes = dict(FACE_MODELS)
    model_hashes.update({name: sha for name, sha, _, _ in PAD_MODELS})
    for name, expected in model_hashes.items():
        assert hashlib.sha256((models/name).read_bytes()).hexdigest() == expected
    matcher = FaceMatcher(models)
    blank = cv2.imencode('.jpg', np.zeros((320, 320, 3), np.uint8))[1].tobytes()
    try:
        matcher.decode_face(blank)
    except FaceRejected as error:
        assert str(error) == 'EXACTLY_ONE_FACE_REQUIRED'
    else:
        raise AssertionError('blank image detected as a face')
    rng = np.random.default_rng(20261027)
    features = []
    for _ in range(3):
        feature = matcher.recognizer.feature(rng.integers(0, 256, (112, 112, 3), dtype=np.uint8)).copy()
        assert np.isfinite(feature).all()
        features.append(feature.reshape(-1).tolist())
    pad = PresentationAttackDetector(models)
    pad_scores = [pad.score(pixels, np.array([60, 50, 120, 120])),
                  pad.score(np.zeros_like(pixels), np.array([60, 50, 120, 120]))]
    assert all(np.isfinite(s) and 0 <= s <= 1 for s in pad_scores)
    large = cv2.resize(pixels, (1600, 1200))
    large_jpeg = cv2.imencode('.jpg', large)[1].tobytes()
    elapsed = []
    for _ in range(12):
        begin = time.perf_counter()
        assert decode_bounded_image(large_jpeg).shape == large.shape
        elapsed.append(time.perf_counter()-begin)
    information = cv2.getBuildInformation()
    modules = re.search(r'^\s*To be built:\s*(.*)$', information, re.M).group(1).split()
    writers = {}
    for extension in ('.jpg', '.jp2', '.png', '.bmp', '.tiff', '.webp', '.exr'):
        try:
            writers[extension] = cv2.haveImageWriter(extension)
        except cv2.error:
            # The reference wheel's compiled EXR codec is disabled by default.
            # A missing codec in the candidate must return false, not throw.
            if args.kind == 'candidate':
                raise
            writers[extension] = None
    if args.kind == 'candidate':
        assert set(modules) == {'core', 'imgproc', 'imgcodecs', 'dnn', 'objdetect',
                                'calib3d', 'features2d', 'flann', 'python3'}, modules
        assert not hasattr(cv2, 'VideoCapture')
        assert all(not writers[e] for e in ('.png', '.tiff', '.webp', '.exr'))
        assert writers['.jpg'] and writers['.jp2']
        assert re.search(r'JPEG 2000:.*2\.5\.4', information)
    result = {'format': 1, 'kind': args.kind, 'passed': True, 'version': cv2.__version__,
              'module': str(module), 'buildInformation': information, 'modules': modules,
              'writers': writers, 'fixturesSHA256': hashlib.sha256(fixtures_bytes).hexdigest(),
              'modelSHA256': model_hashes,
              'decoded': decoded, 'features': features, 'padScores': pad_scores,
              'jpegDecodeMedianSeconds': statistics.median(elapsed[2:]),
              'limits': ['Generated pixels test compatibility, not biometric accuracy or PAD certification.',
                         'Candidate still contains the reference wheel; no deployed-library closure.']}
    (args.directory/(args.kind+'.json')).write_text(json.dumps(result, indent=2)+'\n')
    print('PASS: '+args.kind+' codecs, profiles, boundaries, YuNet/SFace and PAD')


if __name__ == '__main__':
    main()
