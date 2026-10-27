import base64
import copy
import json
from pathlib import Path
import unittest

from compare import compare


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        pixels = base64.b64encode(bytes(240*320*3)).decode()
        self.reference = {'format': 1, 'kind': 'reference', 'passed': True, 'version': '4.14.0',
                          'fixturesSHA256': 'a'*64, 'modelSHA256': {str(i): 'b'*64 for i in range(4)},
                          'decoded': {e: pixels for e in ('.jpg', '.jp2', '.j2k')},
                          'features': [[0.0]*128 for _ in range(3)], 'padScores': [.4, .6],
                          'jpegDecodeMedianSeconds': .01}
        self.candidate = copy.deepcopy(self.reference)
        self.candidate.update(kind='candidate', module='/opt/openid-opencv/python/cv2.cpython-312-x86_64-linux-gnu.so',
                              modules=['core', 'imgproc', 'imgcodecs', 'dnn', 'objdetect', 'calib3d', 'features2d', 'flann', 'python3'],
                              writers={'.jpg': True, '.jp2': True, '.png': False, '.tiff': False, '.webp': False, '.exr': False})

    def test_equal_outputs(self):
        self.assertTrue(compare(self.reference, self.candidate)['passed'])

    def test_wrong_inputs_models_or_native_module(self):
        for key, value in (('fixturesSHA256', 'c'*64), ('modelSHA256', {}),
                           ('module', '/usr/local/lib/python3.12/site-packages/cv2/__init__.py')):
            candidate = copy.deepcopy(self.candidate); candidate[key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                compare(self.reference, candidate)

    def test_unwanted_codecs_and_modules(self):
        for key in ('.png', '.tiff', '.webp', '.exr'):
            candidate = copy.deepcopy(self.candidate); candidate['writers'][key] = True
            with self.subTest(codec=key), self.assertRaises(AssertionError): compare(self.reference, candidate)
        self.candidate['modules'].append('videoio')
        with self.assertRaises(AssertionError): compare(self.reference, self.candidate)

    def test_changed_pixels(self):
        for extension in ('.jpg', '.jp2', '.j2k'):
            candidate = copy.deepcopy(self.candidate)
            candidate['decoded'][extension] = base64.b64encode(bytes([4])+bytes(240*320*3-1)).decode()
            with self.subTest(extension=extension), self.assertRaises(AssertionError):
                compare(self.reference, candidate)

    def test_missing_or_nonfinite_model_outputs(self):
        for value in (float('nan'), float('inf'), .01):
            candidate = copy.deepcopy(self.candidate); candidate['features'][0][0] = value
            with self.subTest(value=value), self.assertRaises(AssertionError): compare(self.reference, candidate)
        self.candidate['features'].pop()
        with self.assertRaises(AssertionError): compare(self.reference, self.candidate)

    def test_pad_and_performance_regression(self):
        for key, value in (('padScores', [.5, .6]), ('padScores', [float('nan'), .6]),
                           ('jpegDecodeMedianSeconds', .1), ('jpegDecodeMedianSeconds', float('nan'))):
            candidate = copy.deepcopy(self.candidate); candidate[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(AssertionError): compare(self.reference, candidate)

    def test_failed_report(self):
        self.candidate['passed'] = False
        with self.assertRaises(AssertionError): compare(self.reference, self.candidate)

    def test_candidate_is_explicit_and_archives_are_hash_locked(self):
        root = Path(__file__).resolve().parents[3]
        dockerfile = (root/'deployment/Dockerfile').read_text()
        self.assertTrue(dockerfile.rstrip().endswith('FROM pilot AS release'))
        native = dockerfile.split(' AS opencv-build\n', 1)[1].split('FROM pilot AS opencv-candidate', 1)[0]
        self.assertIn('RUN --network=none python /build-opencv.py', native)
        lock = json.loads(Path(__file__).with_name('native.lock.json').read_text())
        for archive in lock['archives']:
            self.assertIn('ADD --checksum=sha256:'+archive['sha256']+' '+archive['url']+' /inputs/'+archive['filename'], native)
            self.assertTrue(archive['licenseFiles'])


if __name__ == '__main__': unittest.main()
