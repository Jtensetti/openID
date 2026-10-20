"""Authenticated passport fields and encrypted credential profiles."""
import base64
from dataclasses import dataclass
from datetime import date
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

FIELDS = {'givenNames', 'familyName', 'birthDateMrz', 'nationality', 'issuingState', 'documentNumber', 'documentExpires'}

@dataclass(frozen=True)
class VerifiedDocument:
    portrait: bytes
    identity: dict

    @classmethod
    def from_verifier(cls, value):
        if value.get('passiveAuthentication') is not True or set(value.get('identity', {})) != FIELDS:
            raise ValueError('passport identity missing')
        identity = value['identity']
        if any(not isinstance(v, str) for v in identity.values()): raise ValueError('identity fields')
        for field in ('givenNames', 'familyName'):
            if not re.fullmatch('[A-Z ]{0,44}', identity[field]): raise ValueError('name')
        if not (identity['givenNames'] or identity['familyName']): raise ValueError('name')
        if not re.fullmatch('[0-9]{6}', identity['birthDateMrz']): raise ValueError('birth date')
        date(2000+int(identity['birthDateMrz'][:2]), int(identity['birthDateMrz'][2:4]), int(identity['birthDateMrz'][4:6]))
        for field in ('nationality', 'issuingState'):
            if not re.fullmatch('[A-Z<]{3}', identity[field]): raise ValueError('country')
        if not re.fullmatch('[A-Z0-9]{1,9}', identity['documentNumber']): raise ValueError('document number')
        if not re.fullmatch('[0-9]{4}-[0-9]{2}-[0-9]{2}', identity['documentExpires']): raise ValueError('expiry')
        date.fromisoformat(identity['documentExpires'])
        portrait = base64.b64decode(value['portrait'], validate=True)
        if not 0 < len(portrait) <= 2_000_000: raise ValueError('portrait size')
        return cls(portrait, dict(identity))

    def profile(self):
        import cv2
        import numpy as np
        image = cv2.imdecode(np.frombuffer(self.portrait, dtype=np.uint8), cv2.IMREAD_COLOR)
        if image is None or max(image.shape[:2]) > 8000: raise ValueError('portrait')
        height, width = image.shape[:2]
        scale = min(1, 224 / max(height, width))
        image = cv2.resize(image, (max(1, round(width*scale)), max(1, round(height*scale))))
        success, encoded = cv2.imencode('.jpg', image, [cv2.IMWRITE_JPEG_QUALITY, 75])
        if not success or len(encoded) > 24_000: raise ValueError('portrait size')
        return {k: v for k, v in self.identity.items() if k != 'documentNumber'} | {
            'displayName': ' '.join(filter(None, (self.identity['givenNames'], self.identity['familyName']))),
            'portraitJpeg': base64.b64encode(encoded).decode()}

class IdentityVault:
    def __init__(self, path, runner=None):
        self.path = Path(path)
        self.runner = runner

    def key(self, create=False):
        if create:
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(secrets.token_bytes(64)); stream.flush(); os.fsync(stream.fileno())
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            if os.fstat(stream.fileno()).st_mode & 0o077: raise ValueError('identity key must be private (0600)')
            key = stream.read(65)
        if len(key) != 64: raise ValueError('identity key unavailable')
        return key

    def reference(self, domain, value):
        return hmac.new(self.key()[32:], (domain+'\0'+value).encode(), hashlib.sha256).hexdigest()

    def document_tag(self, document):
        identity = document.identity
        return self.reference('document-v1', json.dumps([identity[k] for k in
            ('issuingState', 'documentNumber', 'birthDateMrz')], separators=(',', ':')))

    def crypt(self, operation, credential, person, value):
        request = {'operation': operation, 'key': base64.b64encode(self.key()[:32]).decode(),
            'aad': f'openid-profile-v1:{credential}:{person}', 'value': value}
        if self.runner is not None: return self.runner(request)['value']
        result = subprocess.run(['node', str(Path(__file__).parent/'profile-crypto.mjs')],
            input=json.dumps(request).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
        if result.returncode: raise ValueError('identity profile unavailable')
        return json.loads(result.stdout)['value']
