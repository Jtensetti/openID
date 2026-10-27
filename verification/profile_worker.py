"""Create a thumbnail outside the registry process; no identity fields or keys."""
from pathlib import Path
import resource
import sys

from bounded_process import disable_worker_core_dumps, image_worker_environment, run_bounded
from image_input import MAX_ENCODED_BYTES, decode_bounded_image, validate_encoded_image


MAX_THUMBNAIL_BYTES = 24_000


def thumbnail(encoded):
    validate_encoded_image(encoded)
    result = run_bounded([sys.executable, str(Path(__file__).resolve())], input=encoded,
        timeout=15, max_input=MAX_ENCODED_BYTES, max_output=MAX_THUMBNAIL_BYTES,
        env=image_worker_environment())
    if (result.returncode or not 0 < len(result.stdout) <= MAX_THUMBNAIL_BYTES
            or not result.stdout.startswith(b'\xff\xd8\xff') or not result.stdout.endswith(b'\xff\xd9')):
        raise ValueError('IMAGE_REJECTED')
    return result.stdout


def create_thumbnail(encoded):
    image = decode_bounded_image(encoded)
    import cv2
    cv2.setNumThreads(1)
    height, width = image.shape[:2]
    scale = min(1, 224 / max(height, width))
    image = cv2.resize(image, (max(1, round(width*scale)), max(1, round(height*scale))))
    success, result = cv2.imencode('.jpg', image, [cv2.IMWRITE_JPEG_QUALITY, 75])
    if not success or not 0 < len(result) <= MAX_THUMBNAIL_BYTES:
        raise ValueError('IMAGE_REJECTED')
    return result.tobytes()


def limit_resources():
    bounds = [(resource.RLIMIT_CPU, 10)]
    if sys.platform == 'linux':
        bounds.append((resource.RLIMIT_AS, 1024 * 1024 * 1024))
    for kind, ceiling in bounds:
        soft, hard = resource.getrlimit(kind)
        limit = min([ceiling]+[v for v in (soft, hard) if v != resource.RLIM_INFINITY])
        resource.setrlimit(kind, (limit, limit))


if __name__ == '__main__':
    try:
        disable_worker_core_dumps()
        limit_resources()
        raw = sys.stdin.buffer.read(MAX_ENCODED_BYTES + 1)
        sys.stdout.buffer.write(create_thumbnail(raw))
    except Exception:
        raise SystemExit(2) from None
