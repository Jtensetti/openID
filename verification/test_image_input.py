"""Generated image boundaries; these tests do not establish biometric quality."""
import base64
import unittest
from unittest.mock import patch

from image_input import MAX_ENCODED_BYTES, decode_bounded_image, validate_encoded_image
from identity import VerifiedDocument


class EncodedImageTests(unittest.TestCase):
    def test_wrong_type_empty_and_oversize_are_rejected_before_importing_decoder(self):
        for value in (None, 'jpeg', bytearray(b'\xff\xd8\xff'), b'', b'\xff\xd8\xff'+b'x'*MAX_ENCODED_BYTES):
            with self.subTest(kind=type(value).__name__), self.assertRaisesRegex(ValueError, 'IMAGE_SIZE_REJECTED'):
                decode_bounded_image(value)

    def test_disallowed_signatures_do_not_reach_decoder(self):
        for value in (b'\x89PNG\r\n\x1a\n', b'GIF89a', b'BM', b'II*\0', b'RIFF0000WEBP', b'not an image'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'IMAGE_REJECTED'):
                decode_bounded_image(value)

    def test_format_gate_alone_does_not_claim_valid_decoding(self):
        for value in (b'\xff\xd8\xff', b'\x00\x00\x00\x0cjP  \r\n\x87\n', b'\xff\x4f\xff\x51'):
            validate_encoded_image(value)


class ImageDecoderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import cv2
        import numpy as np
        cls.cv2, cls.np = cv2, np
        cls.pixels = np.zeros((96, 96, 3), dtype=np.uint8)

    def document(self, encoded):
        return VerifiedDocument(encoded, {'givenNames': 'ALICE', 'familyName': 'SYNTHETIC',
            'birthDateMrz': '900101', 'nationality': 'UTO', 'issuingState': 'UTO',
            'documentNumber': 'TEST00001', 'documentExpires': '2030-10-19'})

    def test_jpeg_jp2_and_raw_jpeg2000_decode_and_make_bounded_jpeg_profile(self):
        jpeg = self.cv2.imencode('.jpg', self.pixels)[1].tobytes()
        jp2 = self.cv2.imencode('.jp2', self.pixels, [self.cv2.IMWRITE_JPEG2000_COMPRESSION_X1000, 1000])[1].tobytes()
        # Extract the actual JP2 codestream box, not an arbitrary byte occurrence.
        offset = 0
        raw = None
        while offset < len(jp2):
            size = int.from_bytes(jp2[offset:offset+4], 'big')
            self.assertGreaterEqual(size, 8)
            self.assertLessEqual(offset+size, len(jp2))
            if jp2[offset+4:offset+8] == b'jp2c': raw = jp2[offset+8:offset+size]
            offset += size
        self.assertIsNotNone(raw)
        for encoded in (jpeg, jp2, raw):
            with self.subTest(signature=encoded[:12]):
                self.assertEqual((96, 96, 3), decode_bounded_image(encoded).shape)
                profile = self.document(encoded).profile()
                thumbnail = base64.b64decode(profile['portraitJpeg'], validate=True)
                self.assertTrue(thumbnail.startswith(b'\xff\xd8\xff'))
                self.assertLessEqual(len(thumbnail), 24_000)
                self.assertLessEqual(max(decode_bounded_image(thumbnail).shape[:2]), 224)
                self.assertNotIn('documentNumber', profile)

    def test_profile_rejects_other_formats_before_native_decoder(self):
        png = self.cv2.imencode('.png', self.pixels)[1].tobytes()
        with patch.object(self.cv2, 'imdecode') as decoder:
            with self.assertRaisesRegex(ValueError, 'IMAGE_REJECTED'):
                self.document(png).profile()
            decoder.assert_not_called()

    def test_truncated_allowed_formats_are_rejected_by_both_callers(self):
        from face import FaceMatcher, FaceRejected
        matcher = object.__new__(FaceMatcher)
        for raw in (b'\xff\xd8\xff', b'\x00\x00\x00\x0cjP  \r\n\x87\n', b'\xff\x4f\xff\x51'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError): self.document(raw).profile()
                with self.assertRaises(FaceRejected): matcher.decode_face(raw)

    def test_oversize_dimensions_and_native_errors_never_make_profile(self):
        # Fake decoded metadata avoids allocating oversized test images.
        from types import SimpleNamespace
        for shape in ((4097, 1, 3), (1, 4097, 3), (3000, 3000, 3), (0, 1, 3), (96, 96, 4)):
            image = SimpleNamespace(ndim=3, shape=shape)
            with self.subTest(shape=shape), patch.object(self.cv2, 'imdecode', return_value=image), patch.object(self.cv2, 'imencode') as encoder:
                with self.assertRaises(ValueError): self.document(b'\xff\xd8\xff').profile()
                encoder.assert_not_called()
        with patch.object(self.cv2, 'imdecode', side_effect=self.cv2.error('synthetic decoder failure')):
            with self.assertRaisesRegex(ValueError, 'IMAGE_REJECTED'):
                self.document(b'\xff\xd8\xff').profile()


if __name__ == '__main__': unittest.main()
