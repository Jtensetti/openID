import contextlib
import io
import json
import subprocess
import unittest
from unittest.mock import patch
from biometric_worker import run_stage
from serve import score_frames

class DiagnosticTests(unittest.TestCase):
    def test_worker_never_reports_arbitrary_exception_text(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
            run_stage('FACE_MATCH', lambda: (_ for _ in ()).throw(ValueError('PRIVATE IMAGE DATA')))
        self.assertEqual(json.loads(output.getvalue()), {'stage': 'FACE_MATCH', 'reason': 'FAILED'})

    def test_parent_sanitizes_worker_output(self):
        for output in [b'{"stage":"secret","reason":"private"}', b'["private"]', b'private', b'x'*5000]:
            log = io.StringIO()
            with patch('serve.subprocess.run', return_value=subprocess.CompletedProcess([], 2, output)), contextlib.redirect_stderr(log), self.assertRaises(OSError):
                score_frames(b'portrait', [b'a', b'b', b'c'])
            self.assertEqual(json.loads(log.getvalue()), {'event': 'biometric_failure', 'stage': 'WORKER', 'reason': 'FAILED'})

    def test_known_face_failure_stays_rejected(self):
        log = io.StringIO()
        output = b'{"stage":"FACE_MATCH","reason":"EXACTLY_ONE_FACE_REQUIRED"}'
        with patch('serve.subprocess.run', return_value=subprocess.CompletedProcess([], 2, output)), contextlib.redirect_stderr(log), self.assertRaises(ValueError):
            score_frames(b'portrait', [b'a', b'b', b'c'])
        self.assertEqual(json.loads(log.getvalue())['reason'], 'EXACTLY_ONE_FACE_REQUIRED')

    def test_timeout_does_not_log_payload(self):
        log = io.StringIO()
        with patch('serve.subprocess.run', side_effect=subprocess.TimeoutExpired('private', 45)), contextlib.redirect_stderr(log), self.assertRaises(subprocess.TimeoutExpired):
            score_frames(b'portrait', [b'a', b'b', b'c'])
        self.assertEqual(json.loads(log.getvalue())['reason'], 'TIMEOUT')

    def test_success_returns_scores_without_diagnostics(self):
        output = b'{"face":[0.9,0.9,0.9],"pad":[0.95,0.95,0.95]}'
        log = io.StringIO()
        with patch('serve.subprocess.run', return_value=subprocess.CompletedProcess([], 0, output)), contextlib.redirect_stderr(log):
            self.assertEqual(score_frames(b'p', [b'a', b'b', b'c']), ([.9]*3, [.95]*3))
        self.assertEqual(log.getvalue(), '')

    def test_camera_frame_error_is_bounded_and_typed(self):
        from biometric_worker import CameraImageRejected
        for frame in (1, 2, 3):
            output = json.dumps({'stage': 'CAMERA_FACE_' + str(frame), 'reason': 'EXACTLY_ONE_FACE_REQUIRED'}).encode()
            with patch('serve.subprocess.run', return_value=subprocess.CompletedProcess([], 2, output)), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(CameraImageRejected) as caught:
                score_frames(b'p', [b'a', b'b', b'c'])
            self.assertEqual(caught.exception.frame, frame)
