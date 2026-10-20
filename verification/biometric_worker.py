"""Short-lived process: image decoding/inference cannot hang the HTTP worker."""
import base64
import json
from pathlib import Path
import sys


def main():
    from face import FaceMatcher
    from pad import PresentationAttackDetector
    matcher = FaceMatcher(Path(__file__).parent/'models')
    pad = PresentationAttackDetector(Path(__file__).parent/'models')
    if sys.argv[1:] == ['--check']:
        print('{"ready":true}')
        return
    raw = sys.stdin.buffer.read(11_000_001)
    if len(raw) > 11_000_000: raise ValueError('size')
    data = json.loads(raw)
    portrait = base64.b64decode(data['portrait'], validate=True)
    frames = [base64.b64decode(frame, validate=True) for frame in data['frames']]
    if len(frames) != 3: raise ValueError('frames')
    face_scores, pad_scores = [], []
    for frame in frames:
        face_scores.append(matcher.compare(portrait, frame))
        image, face = matcher.decode_face(frame)
        pad_scores.append(pad.score(image, face))
    print(json.dumps({'face': face_scores, 'pad': pad_scores}, allow_nan=False))


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit(2)
