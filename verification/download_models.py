"""Explicit provisioning only: immutable source revision plus independently pinned SHA-256."""
import hashlib
from pathlib import Path
import urllib.request

REVISION = '47534e27c9851bb1128ccc0102f1145e27f23f98'
FILES = [
    ('face_detection_yunet', 'face_detection_yunet_2023mar.onnx', '8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4'),
    ('face_recognition_sface', 'face_recognition_sface_2021dec.onnx', '0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79'),
    ('PAD', '2.7_80x80_MiniFASNetV2.pth', 'a5eb02e1843f19b5386b953cc4c9f011c3f985d0ee2bb9819eea9a142099bec0'),
    ('PAD', '4_0_0_80x80_MiniFASNetV1SE.pth', '84ee1d37d96894d5e82de5a57df044ef80a58be2b218b5ed7cdfd875ec2f5990'),
]
def main():
    destination = Path(__file__).parent / 'models'
    destination.mkdir(exist_ok=True)
    for folder, name, checksum in FILES:
        url = f'https://media.githubusercontent.com/media/opencv/opencv_zoo/{REVISION}/models/{folder}/{name}'
        if folder == 'PAD':
            url=f'https://raw.githubusercontent.com/minivision-ai/Silent-Face-Anti-Spoofing/b6d5f04ad78778917853b25c778acef6d5626d15/resources/anti_spoof_models/{name}'
        with urllib.request.urlopen(url, timeout=90) as response:
            content = response.read(40_000_001)
        if len(content) > 40_000_000 or hashlib.sha256(content).hexdigest() != checksum:
            raise RuntimeError('Model integrity check failed')
        temporary = destination / (name + '.partial')
        temporary.write_bytes(content)
        temporary.replace(destination / name)
        print(name + ': SHA-256 verified')
if __name__ == '__main__':
    main()
