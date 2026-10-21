import base64
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from http.server import HTTPServer
import cv2
import numpy as np
from face import FaceMatcher, FaceRejected, MODELS
from server import handler, unique_object, verify_document
from identity import VerifiedDocument

class FaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matcher = FaceMatcher(Path(__file__).parent / 'models')

    def test_actual_detector_rejects_blank_image(self):
        image = cv2.imencode('.jpg', np.zeros((320,320,3), dtype=np.uint8))[1].tobytes()
        with self.assertRaisesRegex(FaceRejected, 'EXACTLY_ONE_FACE_REQUIRED'):
            self.matcher.compare(image,image)

    def test_actual_recognizer_inference_is_finite(self):
        rng = np.random.default_rng(2026)
        tensor = rng.integers(0,256,(112,112,3),dtype=np.uint8)
        a=self.matcher.recognizer.feature(tensor).copy()
        b=self.matcher.recognizer.feature(tensor).copy()
        score=self.matcher.recognizer.match(a,b,cv2.FaceRecognizerSF_FR_COSINE)
        self.assertTrue(np.isfinite(a).all())
        self.assertGreater(score,0.999)

    def test_malformed_and_oversize_images_rejected(self):
        for image in [b'',b'not an image',b'x'*2_000_001]:
            with self.subTest(size=len(image)), self.assertRaises(FaceRejected):
                self.matcher.feature(image)

    def test_modified_model_refused_before_loading(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/next(iter(MODELS))).write_bytes(b'wrong model')
            with self.assertRaisesRegex(FaceRejected,'MODEL_INTEGRITY_FAILED'):
                FaceMatcher(directory)

    def test_multiple_faces_never_selects_first(self):
        matcher=FaceMatcher.__new__(FaceMatcher)
        matcher.detector=Mock(); matcher.detector.detect.return_value=(2,np.zeros((2,15)))
        matcher.recognizer=Mock()
        image=cv2.imencode('.jpg',np.zeros((320,320,3),dtype=np.uint8))[1].tobytes()
        with self.assertRaisesRegex(FaceRejected,'EXACTLY_ONE_FACE_REQUIRED'):
            matcher.feature(image)
        matcher.recognizer.feature.assert_not_called()

    def test_large_face_detection_maps_box_and_landmarks_to_original(self):
        matcher = FaceMatcher.__new__(FaceMatcher)
        matcher.detector = Mock()
        small = np.array([[50, 60, 100, 120, 70, 90, 120, 90, 95, 115, 75, 140, 115, 140, .95]], dtype=np.float32)
        matcher.detector.detect.side_effect = [(0, None), (1, small)]
        encoded = cv2.imencode('.jpg', np.zeros((1280, 720, 3), dtype=np.uint8))[1].tobytes()
        image, face = matcher.decode_face(encoded)
        self.assertEqual(image.shape[:2], (1280, 720))
        np.testing.assert_allclose(face[:14], small[0, :14] / .375, atol=0.0001)
        self.assertAlmostEqual(float(face[14]), .95, places=5)
        self.assertEqual(matcher.detector.setInputSize.call_args.args[0], (270, 480))

    def test_two_faces_at_either_scale_are_rejected(self):
        one = np.array([[50, 50, 100, 100] + [60]*10 + [.95]], dtype=np.float32)
        for results in [[(2, np.vstack([one, one]))], [(1, one), (2, np.vstack([one, one]))]]:
            matcher = FaceMatcher.__new__(FaceMatcher); matcher.detector = Mock()
            matcher.detector.detect.side_effect = results
            encoded = cv2.imencode('.jpg', np.zeros((1280, 720, 3), dtype=np.uint8))[1].tobytes()
            with self.assertRaisesRegex(FaceRejected, 'EXACTLY_ONE_FACE_REQUIRED'): matcher.decode_face(encoded)

    def test_different_faces_across_scales_are_rejected(self):
        one = np.array([[20, 20, 100, 100] + [60]*10 + [.95]], dtype=np.float32)
        other = np.array([[150, 250, 100, 100] + [160]*10 + [.95]], dtype=np.float32)
        matcher = FaceMatcher.__new__(FaceMatcher); matcher.detector = Mock()
        matcher.detector.detect.side_effect = [(1, one), (1, other)]
        encoded = cv2.imencode('.jpg', np.zeros((1280, 720, 3), dtype=np.uint8))[1].tobytes()
        with self.assertRaisesRegex(FaceRejected, 'EXACTLY_ONE_FACE_REQUIRED'): matcher.decode_face(encoded)

    def test_actual_detector_rejects_large_blank_image(self):
        encoded = cv2.imencode('.jpg', np.zeros((1280, 720, 3), dtype=np.uint8))[1].tobytes()
        with self.assertRaisesRegex(FaceRejected, 'EXACTLY_ONE_FACE_REQUIRED'): self.matcher.decode_face(encoded)

class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.matcher=Mock();self.matcher.compare.return_value=0.99
        self.http=HTTPServer(('127.0.0.1',0),handler(self.matcher,[],0))
        self.port=self.http.server_port
        self.http.RequestHandlerClass=handler(self.matcher,[],self.port)
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True);self.thread.start()
        code,data=self.request('GET','/session')
        self.assertEqual(200,code);self.token=json.loads(data)['token']
        self.headers={'Origin':f'http://localhost:{self.port}','X-CSRF-Token':self.token,'Content-Type':'application/json'}

    def tearDown(self):
        self.http.shutdown();self.http.server_close();self.thread.join()

    def request(self,method,path,body=None,headers=None):
        c=http.client.HTTPConnection('127.0.0.1',self.port,timeout=5)
        try:
            c.request(method,path,body,{'Host':f'localhost:{self.port}',**(headers or {})})
            r=c.getresponse();return r.status,r.read()
        finally:c.close()

    def test_origin_token_and_host_required(self):
        for change in [{'Origin':'https://attacker.invalid'},{'X-CSRF-Token':'wrong'},{'Host':'attacker.invalid'},{'Forwarded':'host=localhost'}]:
            with self.subTest(change=change):
                self.assertEqual(403,self.request('POST','/verify','{}',{**self.headers,**change})[0])
        self.matcher.compare.assert_not_called()

    def test_no_upload_or_client_approval_endpoint(self):
        self.assertEqual(404,self.request('POST','/approve','{}',self.headers)[0])
        self.assertEqual(400,self.request('POST','/verify',json.dumps({'verified':True}),self.headers)[0])

    def test_duplicate_fields_and_size_rejected(self):
        self.assertEqual(400,self.request('POST','/verify','{"sod":"YQ==","sod":"Yg=="}',self.headers)[0])
        self.assertEqual(413,self.request('POST','/verify',None,{**self.headers,'Content-Length':'6000001'})[0])

    def test_document_failure_prevents_face_comparison(self):
        data=json.dumps({key:'YQ==' for key in ['sod','dg1','dg2','camera']})
        with patch('server.verify_document',side_effect=ValueError('rejected')):
            self.assertEqual(400,self.request('POST','/verify',data,self.headers)[0])
        self.matcher.compare.assert_not_called()

    def test_even_high_similarity_cannot_issue_identity(self):
        data=json.dumps({key:'YQ==' for key in ['sod','dg1','dg2','camera']})
        with patch('server.verify_document',return_value=VerifiedDocument(b'signed portrait', {})):
            code,body=self.request('POST','/verify',data,self.headers)
        self.assertEqual(200,code);result=json.loads(body)
        self.assertFalse(result['identityVerified']);self.assertFalse(result['issuanceEnabled'])
        self.assertEqual('NOT_PERFORMED',result['liveness'])
        self.matcher.compare.assert_called_once_with(b'signed portrait',b'a')

class CliTests(unittest.TestCase):
    def test_real_java_pipeline(self):
        directory=Path(os.environ['PROOFING_FIXTURES'])
        request={key:base64.b64encode((directory/(key+'.bin')).read_bytes()).decode() for key in ['sod','dg1','dg2']}
        command=[os.environ['PROOFING_JAVA'],'-jar',str(Path(__file__).parent.parent/'prototype/target/isolated-eid-lab.jar'),'verify-passport',str(directory/'csca.der')]
        document=verify_document(command,request)
        self.assertEqual((directory/'portrait.jpg').read_bytes(), document.portrait)
        self.assertEqual('ALICE', document.identity['givenNames'])
        self.assertEqual('900101', document.identity['birthDateMrz'])
        request['dg2']='YQ=='
        with self.assertRaises(ValueError):verify_document(command,request)

if __name__=='__main__':unittest.main()
