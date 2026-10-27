import contextlib
import io
import json
import subprocess
import unittest
from unittest.mock import Mock, patch
from biometric_worker import run_stage, score_capture
from serve import score_frames

class DiagnosticTests(unittest.TestCase):
    def test_capture_rejects_each_invalid_image_before_returning_scores(self):
        for index, stage in enumerate(('PORTRAIT_FACE', 'CAMERA_FACE_1', 'CAMERA_FACE_2', 'CAMERA_FACE_3')):
            matcher, pad = Mock(), Mock()
            matcher.decode_face.side_effect = [(object(), object())] * index + [ValueError('EXACTLY_ONE_FACE_REQUIRED')]
            output = io.StringIO()
            with contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
                score_capture(matcher, pad, b'p', [b'a', b'b', b'c'])
            self.assertEqual({'stage': stage, 'reason': 'EXACTLY_ONE_FACE_REQUIRED'}, json.loads(output.getvalue()))
            self.assertEqual(max(0, index-1), pad.score.call_count)

    def test_capture_requires_exactly_three_frames_before_analysis(self):
        matcher, pad = Mock(), Mock()
        for frames in ([], [b'a'], [b'a']*4):
            with self.assertRaises(ValueError): score_capture(matcher, pad, b'p', frames)
        matcher.decode_face.assert_not_called()
        pad.score.assert_not_called()

    def test_worker_never_reports_arbitrary_exception_text(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
            run_stage('FACE_MATCH', lambda: (_ for _ in ()).throw(ValueError('PRIVATE IMAGE DATA')))
        self.assertEqual(json.loads(output.getvalue()), {'stage': 'FACE_MATCH', 'reason': 'FAILED'})

    def test_parent_sanitizes_worker_output(self):
        for output in [b'{"stage":"secret","reason":"private"}', b'["private"]', b'private', b'x'*5000]:
            log = io.StringIO()
            with patch('serve.run_bounded', return_value=subprocess.CompletedProcess([], 2, output)), contextlib.redirect_stderr(log), self.assertRaises(OSError):
                score_frames(b'portrait', [b'a', b'b', b'c'])
            self.assertEqual(json.loads(log.getvalue()), {'event': 'biometric_failure', 'stage': 'WORKER', 'reason': 'FAILED'})

    def test_known_face_failure_stays_rejected(self):
        log = io.StringIO()
        output = b'{"stage":"FACE_MATCH","reason":"EXACTLY_ONE_FACE_REQUIRED"}'
        with patch('serve.run_bounded', return_value=subprocess.CompletedProcess([], 2, output)), contextlib.redirect_stderr(log), self.assertRaises(ValueError):
            score_frames(b'portrait', [b'a', b'b', b'c'])
        self.assertEqual(json.loads(log.getvalue())['reason'], 'EXACTLY_ONE_FACE_REQUIRED')

    def test_timeout_does_not_log_payload(self):
        log = io.StringIO()
        with patch('serve.run_bounded', side_effect=subprocess.TimeoutExpired('private', 45)), contextlib.redirect_stderr(log), self.assertRaises(subprocess.TimeoutExpired):
            score_frames(b'portrait', [b'a', b'b', b'c'])
        self.assertEqual(json.loads(log.getvalue())['reason'], 'TIMEOUT')

    def test_success_returns_scores_without_diagnostics(self):
        output = b'{"face":[0.9,0.9,0.9],"pad":[0.95,0.95,0.95],"pose":[0.0,-0.25,0.25]}'
        log = io.StringIO()
        with patch('serve.run_bounded', return_value=subprocess.CompletedProcess([], 0, output)), contextlib.redirect_stderr(log):
            self.assertEqual(score_frames(b'p', [b'a', b'b', b'c']), ([.9]*3, [.95]*3, [0.0, -0.25, 0.25]))
        self.assertEqual(log.getvalue(), '')

    def test_camera_frame_error_is_bounded_and_typed(self):
        from biometric_worker import CameraImageRejected
        for frame in (1, 2, 3):
            output = json.dumps({'stage': 'CAMERA_FACE_' + str(frame), 'reason': 'EXACTLY_ONE_FACE_REQUIRED'}).encode()
            with patch('serve.run_bounded', return_value=subprocess.CompletedProcess([], 2, output)), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(CameraImageRejected) as caught:
                score_frames(b'p', [b'a', b'b', b'c'])
            self.assertEqual(caught.exception.frame, frame)
