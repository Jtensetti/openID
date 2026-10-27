"""One bounded JPEG/JPEG 2000 input boundary for faces and profile thumbnails."""
import os


MAX_ENCODED_BYTES = 2_000_000
MAX_SIDE = 4096
MAX_PIXELS = 8_000_000
# Configure the native allocator before either application caller imports cv2.
os.environ['OPENCV_IO_MAX_IMAGE_PIXELS'] = str(MAX_PIXELS)
os.environ['OPENCV_IO_MAX_IMAGE_WIDTH'] = str(MAX_SIDE)
os.environ['OPENCV_IO_MAX_IMAGE_HEIGHT'] = str(MAX_SIDE)


def validate_encoded_image(encoded):
    if not isinstance(encoded, bytes) or not 0 < len(encoded) <= MAX_ENCODED_BYTES:
        raise ValueError('IMAGE_SIZE_REJECTED')
    # This selects a parser; it does not establish that the image is valid.
    if not encoded.startswith((b'\xff\xd8\xff', b'\x00\x00\x00\x0cjP  \r\n\x87\n', b'\xff\x4f\xff\x51')):
        raise ValueError('IMAGE_REJECTED')


def decode_bounded_image(encoded):
    validate_encoded_image(encoded)
    import cv2
    import numpy as np
    try:
        image = cv2.imdecode(np.frombuffer(encoded, dtype=np.uint8), cv2.IMREAD_COLOR)
    except cv2.error:
        raise ValueError('IMAGE_REJECTED') from None
    if image is None or image.ndim != 3 or image.shape[2] != 3:
        raise ValueError('IMAGE_REJECTED')
    height, width = image.shape[:2]
    if min(height, width) < 1 or max(height, width) > MAX_SIDE or height*width > MAX_PIXELS:
        raise ValueError('IMAGE_REJECTED')
    return image
