"""Local 1:1 inference. Not a liveness detector or an identity-issuance decision."""
import hashlib
import math
import os
from pathlib import Path

# Set before loading OpenCV: decoded-image allocation limits, including JPEG2000.
os.environ['OPENCV_IO_MAX_IMAGE_PIXELS'] = '8000000'
os.environ['OPENCV_IO_MAX_IMAGE_WIDTH'] = '4096'
os.environ['OPENCV_IO_MAX_IMAGE_HEIGHT'] = '4096'
import cv2
import numpy as np

MODELS = {
    'face_detection_yunet_2023mar.onnx': '8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4',
    'face_recognition_sface_2021dec.onnx': '0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79',
}

class FaceRejected(ValueError):
    pass

class FaceMatcher:
    def __init__(self, directory):
        directory = Path(directory)
        for name, expected in MODELS.items():
            if hashlib.sha256((directory / name).read_bytes()).hexdigest() != expected:
                raise FaceRejected('MODEL_INTEGRITY_FAILED')
        self.detector = cv2.FaceDetectorYN.create(str(directory / next(iter(MODELS))), '', (320, 320), 0.9, 0.3, 5000)
        self.recognizer = cv2.FaceRecognizerSF.create(str(directory / 'face_recognition_sface_2021dec.onnx'), '')

    def decode_face(self, encoded):
        if not isinstance(encoded, bytes) or not 0 < len(encoded) <= 2_000_000:
            raise FaceRejected('IMAGE_SIZE_REJECTED')
        try:
            image = cv2.imdecode(np.frombuffer(encoded, dtype=np.uint8), cv2.IMREAD_COLOR)
            if image is None or min(image.shape[:2]) < 80 or max(image.shape[:2]) > 4096:
                raise FaceRejected('IMAGE_REJECTED')
            self.detector.setInputSize((image.shape[1], image.shape[0]))
            _, faces = self.detector.detect(image)
            if faces is None or len(faces) != 1:
                raise FaceRejected('EXACTLY_ONE_FACE_REQUIRED')
            if not np.isfinite(faces).all() or min(faces[0][2:4]) < 60:
                raise FaceRejected('FACE_QUALITY_REJECTED')
            return image, faces[0]
        except cv2.error:
            raise FaceRejected('IMAGE_REJECTED') from None

    def feature(self, encoded):
        image, face = self.decode_face(encoded)
        return self.recognizer.feature(self.recognizer.alignCrop(image, face)).copy()

    def compare(self, signed_portrait, camera_image):
        reference = self.feature(signed_portrait)
        candidate = self.feature(camera_image)
        score = float(self.recognizer.match(reference, candidate, cv2.FaceRecognizerSF_FR_COSINE))
        if not math.isfinite(score) or not -1.00001 <= score <= 1.00001:
            raise FaceRejected('INVALID_SCORE')
        return max(-1.0, min(1.0, score))
