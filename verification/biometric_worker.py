"""Short-lived process: image decoding/inference cannot hang the HTTP worker."""
import base64
import json
from pathlib import Path
import sys
from bounded_process import disable_worker_core_dumps


STAGES = {'MODEL_LOAD', 'INPUT', 'FACE_MATCH', 'PORTRAIT_FACE', 'CAMERA_FACE', 'CAMERA_FACE_1', 'CAMERA_FACE_2', 'CAMERA_FACE_3', 'PAD'}
REASONS = {'MODEL_INTEGRITY_FAILED', 'PAD_MODEL_INTEGRITY_FAILED', 'IMAGE_SIZE_REJECTED',
           'IMAGE_REJECTED', 'EXACTLY_ONE_FACE_REQUIRED', 'FACE_QUALITY_REJECTED',
           'PAD_FACE_QUALITY_REJECTED', 'INVALID_SCORE', 'INVALID_PAD_SCORE'}


class CameraImageRejected(ValueError):
    def __init__(self, frame):
        if type(frame) is not int or frame not in (1, 2, 3): raise ValueError('frame')
        self.frame = frame
        super().__init__('camera image rejected')


def run_stage(stage, operation):
    try:
        return operation()
    except Exception as error:
        reason = str(error)
        # Never serialize arbitrary exception messages or image contents.
        print(json.dumps({'stage': stage, 'reason': reason if reason in REASONS else 'FAILED'}), flush=True)
        raise SystemExit(2) from None


def score_capture(matcher, pad, portrait, frames):
    if len(frames) != 3: raise ValueError('frames')
    image, face = run_stage('PORTRAIT_FACE', lambda: matcher.decode_face(portrait))
    reference = run_stage('FACE_MATCH', lambda: matcher.feature_from_face(image, face))
    face_scores, pad_scores, poses = [], [], []
    for index, frame in enumerate(frames):
        image, face = run_stage(f'CAMERA_FACE_{index + 1}', lambda: matcher.decode_face(frame))
        candidate = run_stage('FACE_MATCH', lambda: matcher.feature_from_face(image, face))
        face_scores.append(run_stage('FACE_MATCH', lambda: matcher.compare_features(reference, candidate)))
        pad_scores.append(run_stage('PAD', lambda: pad.score(image, face)))
        poses.append(run_stage(f'CAMERA_FACE_{index + 1}', lambda: matcher.pose_ratio(face)))
    return {'face': face_scores, 'pad': pad_scores, 'pose': poses}


def main():
    from face import FaceMatcher
    from pad import PresentationAttackDetector
    matcher = run_stage('MODEL_LOAD', lambda: FaceMatcher(Path(__file__).parent/'models'))
    pad = run_stage('MODEL_LOAD', lambda: PresentationAttackDetector(Path(__file__).parent/'models'))
    if sys.argv[1:] == ['--check']:
        print('{"ready":true}')
        return
    raw = sys.stdin.buffer.read(11_000_001)
    if len(raw) > 11_000_000: raise ValueError('size')
    data = json.loads(raw)
    portrait = base64.b64decode(data['portrait'], validate=True)
    frames = [base64.b64decode(frame, validate=True) for frame in data['frames']]
    print(json.dumps(score_capture(matcher, pad, portrait, frames), allow_nan=False))


if __name__ == '__main__':
    try:
        disable_worker_core_dumps()
        main()
    except Exception: raise SystemExit(2)
