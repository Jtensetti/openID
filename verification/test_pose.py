"""Server-side head-turn check from landmark parallax and the per-passport attempt limit."""
import base64
import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
import numpy as np
from face import FaceRejected, pose_ratio
from native import NativeSessions, POSES, check_poses, random_pose_order
from test_chip_fixture import ChipFixture, capture_ready, pose_matcher, FIXTURE_RATIOS
from test_identity import document
from test_wallet import crypt
from wallet import Wallet, BIOMETRIC_ATTEMPTS


def face(nose_dx=0.0, roll=0.0, scale=60.0, depth=0.5):
    """YuNet-shaped row: box, five landmarks, score. A 3D head turn moves the nose by depth*sin(yaw)."""
    centre = np.array([200.0, 220.0])
    points = {'re': np.array([-0.5, 0]), 'le': np.array([0.5, 0]), 'no': np.array([nose_dx * depth / 0.5, 0.45]),
              'rm': np.array([-0.4, 0.9]), 'lm': np.array([0.4, 0.9])}
    rotation = np.array([[math.cos(roll), -math.sin(roll)], [math.sin(roll), math.cos(roll)]])
    xy = [centre + scale * rotation @ points[k] for k in ('re', 'le', 'no', 'rm', 'lm')]
    return np.array([150, 150, 120, 140, *np.concatenate(xy), 0.95])


def turned_photo(yaw, scale=60.0):
    """A flat picture turned in front of the camera: every landmark is compressed together; no parallax."""
    row = face(0.0, scale=scale)
    landmarks = row[4:14].reshape(5, 2)
    centre = landmarks.mean(axis=0)
    landmarks[:, 0] = centre[0] + (landmarks[:, 0] - centre[0]) * math.cos(yaw)
    row[4:14] = landmarks.reshape(-1)
    return row


class PoseRatioTests(unittest.TestCase):
    def test_parallax_sign_and_roll_invariance(self):
        self.assertAlmostEqual(0.0, pose_ratio(face()), places=6)
        self.assertLess(pose_ratio(face(-0.2)), -0.15)  # subject's right: nose towards image left
        self.assertGreater(pose_ratio(face(0.2)), 0.15)
        for roll in (-0.4, 0.3):
            self.assertAlmostEqual(pose_ratio(face(0.2)), pose_ratio(face(0.2, roll=roll)), places=6)
        self.assertAlmostEqual(pose_ratio(face(0.2, scale=30)), pose_ratio(face(0.2, scale=120)), places=6)

    def test_turned_flat_photo_has_no_parallax(self):
        for yaw in (0.3, 0.6, 0.9):
            self.assertLess(abs(pose_ratio(turned_photo(yaw))), 1e-9)

    def test_invalid_landmarks_rejected(self):
        bad = face(); bad[6:8] = bad[4:6]
        for row in (bad, np.array([1.0] * 14), np.array([float('nan')] * 15)):
            with self.assertRaises(FaceRejected): pose_ratio(row)


class PoseCheckTests(unittest.TestCase):
    order = ['right', 'front', 'left']

    def test_requested_order_with_real_turns_passes(self):
        self.assertTrue(check_poses(self.order, [-0.22, 0.02, 0.25]))
        self.assertTrue(check_poses(self.order, [-0.22, 0.02, 0.25], direction=True))

    def test_static_photo_screen_and_wrong_order_fail(self):
        cases = {
            'three frontal frames': [0.01, 0.0, -0.02],
            'turned photo, no parallax': [0.0, 0.0, 0.0],
            'only one side turned': [-0.25, 0.0, -0.22],
            'frontal frame turned': [-0.22, 0.25, 0.01],
            'too small turns': [-0.05, 0.0, 0.05],
            'NaN': [float('nan'), 0.0, 0.2],
            'boolean': [True, 0.0, 0.2],
        }
        for name, ratios in cases.items():
            with self.subTest(name): self.assertFalse(check_poses(self.order, ratios))
        # Mirrored direction is only rejected when the calibrated direction check is enabled.
        self.assertTrue(check_poses(self.order, [0.22, 0.02, -0.25]))
        self.assertFalse(check_poses(self.order, [0.22, 0.02, -0.25], direction=True))
        self.assertFalse(check_poses(['front', 'front', 'left'], [0.0, 0.0, 0.2]))

    def test_order_is_a_server_random_permutation(self):
        seen = {tuple(random_pose_order()) for _ in range(300)}
        self.assertEqual(6, len(seen))
        self.assertTrue(all(sorted(order) == sorted(POSES) for order in seen))


class CaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = json.loads(crypt(op='new'))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.time = 1792454400
        self.wallet = Wallet(Path(self.tmp.name)/'wallet.sqlite', 'https://localhost:8765', clock=lambda: self.time)
        self.attest = Mock(); self.attest.check.side_effect = lambda op, **kw: {'publicKey': 'k'} if op == 'attestation' else {'signCount': kw['signCount']+1}
        self.matcher = pose_matcher(Mock()); self.matcher.compare.return_value = 0.95
        self.pad = Mock(); self.pad.score.return_value = 0.95
        self.order = ['front', 'right', 'left']
        self.native = NativeSessions(self.attest, lambda _: document(), self.matcher, self.pad, wallet=self.wallet,
            chip_factory=ChipFixture, pose_order=lambda: list(self.order))
        self.addCleanup(self.native.close)

    def finish(self):
        start = self.native.start(); registered = self.native.register({'id': start['id'], 'keyId': 'k', 'attestation': 't'})
        payload = capture_ready(self.native, registered, dict(sod='YQ==', dg1='YQ==', dg2='YQ==', dg14='YQ==', devicePublicKey=self.key['publicKey']))
        return self.native.finish({'id': start['id'], 'payload': base64.b64encode(json.dumps(payload).encode()).decode(), 'assertion': 't'})

    def test_order_is_sent_after_chip_and_scores_never_returned(self):
        start = self.native.start(); registered = self.native.register({'id': start['id'], 'keyId': 'k', 'attestation': 't'})
        from test_chip_fixture import signed
        chip = self.native.begin_chip(signed(start['id'], {**registered, 'sod': 'YQ==', 'dg1': 'YQ==', 'dg2': 'YQ==', 'dg14': 'YQ=='}))
        self.assertNotIn('poses', chip)
        verified = self.native.chip_step({'id': start['id'], 'chipToken': chip['chipToken'], 'sequence': 0, 'response': 'kAA='})
        self.assertEqual(self.order, verified['poses'])
        self.native.discard(start['id'])
        result = self.finish()
        self.assertTrue(result['checksPassed']); self.assertEqual('PASSED', result['poseCheck'])
        for leaked in ('faceScores', 'padLiveScores', 'poses'): self.assertNotIn(leaked, result)

    def test_frames_in_another_order_than_requested_fail(self):
        self.order = ['left', 'front', 'right']  # frames are still frontal, right, left
        result = self.finish()
        self.assertFalse(result['checksPassed']); self.assertEqual('FAILED', result['poseCheck']); self.assertIsNone(result['credential'])

    def test_attempts_per_passport_are_limited_and_persist_over_restart(self):
        self.pad.score.return_value = 0.2
        for _ in range(BIOMETRIC_ATTEMPTS): self.assertFalse(self.finish()['checksPassed'])
        self.pad.score.return_value = 0.95
        with self.assertRaises(ValueError): self.finish()
        self.matcher.compare.reset_mock()
        restarted = Wallet(self.wallet.path, 'https://localhost:8765', clock=lambda: self.time)
        self.native.wallet = restarted
        with self.assertRaises(ValueError): self.finish()
        self.matcher.compare.assert_not_called()  # no analysis once the limit is reached
        self.time += 24 * 3600 + 1
        self.assertTrue(self.finish()['checksPassed'])

    def test_limit_is_per_passport_not_global(self):
        self.pad.score.return_value = 0.2
        for _ in range(BIOMETRIC_ATTEMPTS): self.finish()
        other = NativeSessions(self.attest, lambda _: document(documentNumber='TEST00009'), self.matcher, self.pad,
            wallet=self.wallet, chip_factory=ChipFixture, pose_order=lambda: list(self.order))
        self.addCleanup(other.close)
        self.native = other; self.pad.score.return_value = 0.95
        self.assertTrue(self.finish()['checksPassed'])


if __name__ == '__main__':
    unittest.main()
