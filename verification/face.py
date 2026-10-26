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

def pose_ratio(face):
    """Signed horizontal nose offset from the eye midpoint, along the eye line, in inter-eye distances.

    A real head turn moves the protruding nose tip relative to the eyes (parallax). A photo or screen that is
    turned or tilted keeps the nose between the eyes, because all five landmarks lie in one plane.
    In an unmirrored front-camera image a turn to the subject's right gives a negative value.
    YuNet landmark order: subject's right eye, left eye, nose tip, right and left mouth corner.
    """
    values = np.asarray(face, dtype=np.float64)
    if values.shape != (15,) or not np.isfinite(values).all(): raise FaceRejected('FACE_QUALITY_REJECTED')
    right_eye, left_eye, nose = values[4:6], values[6:8], values[8:10]
    axis = left_eye - right_eye
    distance = float(np.hypot(*axis))
    if distance < 8: raise FaceRejected('FACE_QUALITY_REJECTED')
    ratio = float(np.dot(nose - (right_eye + left_eye) / 2, axis / distance) / distance)
    if not math.isfinite(ratio) or abs(ratio) > 2: raise FaceRejected('FACE_QUALITY_REJECTED')
    return ratio

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
        # Camera JPEG and passport JPEG/JPEG 2000 only. Reject other formats
        # before dispatching to native codecs. This is a format gate, not a
        # validity check: malformed allowed formats must still fail decoding.
        if not encoded.startswith((b'\xff\xd8\xff', b'\x00\x00\x00\x0cjP  \r\n\x87\n', b'\xff\x4f\xff\x51')):
            raise FaceRejected('IMAGE_REJECTED')
        try:
            image = cv2.imdecode(np.frombuffer(encoded, dtype=np.uint8), cv2.IMREAD_COLOR)
            if image is None or min(image.shape[:2]) < 80 or max(image.shape[:2]) > 4096:
                raise FaceRejected('IMAGE_REJECTED')
            # YuNet's training covers faces around 10–300 pixels. Check both
            # full frame scales; never crop away another face to obtain a match.
            candidates = []
            views = [image]
            height, width = image.shape[:2]
            if max(height, width) > 480:
                scale = 480 / max(height, width)
                views.append(cv2.resize(image, (max(1, round(width * scale)), max(1, round(height * scale))), interpolation=cv2.INTER_AREA))
            for view in views:
                self.detector.setInputSize((view.shape[1], view.shape[0]))
                _, faces = self.detector.detect(view)
                if faces is None or len(faces) == 0: continue
                if len(faces) != 1:
                    raise FaceRejected('EXACTLY_ONE_FACE_REQUIRED')
                if faces.shape != (1, 15) or not np.isfinite(faces).all():
                    raise FaceRejected('FACE_QUALITY_REJECTED')
                face = faces[0].copy()
                # Box and five landmark coordinates return to original pixels.
                face[:14:2] *= width / view.shape[1]
                face[1:14:2] *= height / view.shape[0]
                if min(face[2:4]) < 60 or face[0] < 0 or face[1] < 0 or not 0.9 <= face[14] <= 1:
                    raise FaceRejected('FACE_QUALITY_REJECTED')
                candidates.append(face)
            if not candidates:
                raise FaceRejected('EXACTLY_ONE_FACE_REQUIRED')
            if len(candidates) == 2:
                a, b = candidates
                intersection = max(0, min(a[0]+a[2], b[0]+b[2])-max(a[0], b[0])) * max(0, min(a[1]+a[3], b[1]+b[3])-max(a[1], b[1]))
                union = a[2]*a[3] + b[2]*b[3] - intersection
                if union <= 0 or intersection / union < 0.5:
                    raise FaceRejected('EXACTLY_ONE_FACE_REQUIRED')
            return image, candidates[0]
        except cv2.error:
            raise FaceRejected('IMAGE_REJECTED') from None

    @staticmethod
    def pose_ratio(face):
        return pose_ratio(face)

    def feature(self, encoded):
        image, face = self.decode_face(encoded)
        return self.feature_from_face(image, face)

    def feature_from_face(self, image, face):
        """Use only the image/landmarks returned by decode_face in this request."""
        return self.recognizer.feature(self.recognizer.alignCrop(image, face)).copy()

    def compare(self, signed_portrait, camera_image):
        reference = self.feature(signed_portrait)
        candidate = self.feature(camera_image)
        return self.compare_features(reference, candidate)

    def compare_features(self, reference, candidate):
        # OpenCV may normalize its inputs in place. Keep the reference unchanged
        # when it is reused for the three frames of a single capture.
        score = float(self.recognizer.match(reference.copy(), candidate.copy(), cv2.FaceRecognizerSF_FR_COSINE))
        if not math.isfinite(score) or not -1.00001 <= score <= 1.00001:
            raise FaceRejected('INVALID_SCORE')
        return max(-1.0, min(1.0, score))
