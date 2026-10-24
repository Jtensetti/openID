import concurrent.futures
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock
from runtime import Runtime, RateLimit, validate_origin
from wallet import Wallet
from recovery import backup, restore
from serve import Lease, reject_duplicate_headers, open_wallet


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.native, self.wallet = Mock(), Mock()
        self.native.start.return_value = {'id': 'session'}
        self.wallet.challenge.return_value = {'id': 'challenge'}
        self.app = Runtime(self.native, self.wallet, 'https://localhost:8765', 'a'*43)

    def request(self, path='/native/start', method='POST', body=b'{}', **updates):
        env = {'REQUEST_METHOD': method, 'PATH_INFO': path, 'HTTP_HOST': 'localhost:8765',
            'wsgi.url_scheme': 'https', 'HTTP_ORIGIN': 'https://localhost:8765', 'HTTP_X_CSRF_TOKEN': 'a'*43,
            'CONTENT_TYPE': 'application/json', 'CONTENT_LENGTH': str(len(body)), 'REMOTE_ADDR': '127.0.0.1',
            'wsgi.input': io.BytesIO(body)}
        env.update(updates)
        response = []
        result = b''.join(self.app(env, lambda status, headers: response.append((int(status[:3]), dict(headers)))))
        return response[0][0], json.loads(result), response[0][1]

    def test_public_admission_keeps_metrics_admin_and_origin_closed(self):
        self.app = Runtime(self.native, self.wallet, 'https://localhost:8765', 'a'*43, public_enrollment=True)
        self.assertEqual(200, self.request(HTTP_X_CSRF_TOKEN='')[0])
        self.assertEqual(403, self.request('/metrics', 'GET', HTTP_X_CSRF_TOKEN='')[0])
        self.assertEqual(403, self.request('/activate', HTTP_X_CSRF_TOKEN='')[0])
        self.assertEqual(403, self.request(HTTP_ORIGIN='https://evil.invalid', HTTP_X_CSRF_TOKEN='')[0])
        self.assertEqual(403, self.request(HTTP_HOST='evil.invalid', HTTP_X_CSRF_TOKEN='')[0])
        self.native.start.assert_called_once()
        self.wallet.activate.assert_not_called()

    def test_public_admission_does_not_skip_attestation_or_wallet_signature(self):
        from native import NativeSessions
        attest = Mock(); attest.verify.side_effect = ValueError('invalid attestation')
        native = NativeSessions(attest, Mock(), Mock(), Mock())
        self.app = Runtime(native, self.wallet, 'https://localhost:8765', 'a'*43, public_enrollment=True)
        _, session, _ = self.request(HTTP_X_CSRF_TOKEN='')
        body = json.dumps({'id': session['id']}).encode()
        for route in ['/native/chip/start', '/native/finish']:
            self.assertEqual(400, self.request(route, body=body, HTTP_X_CSRF_TOKEN='')[0])
        self.wallet.execute.side_effect = ValueError('signature missing')
        self.assertEqual(400, self.request('/wallet/execute', HTTP_X_CSRF_TOKEN='')[0])
        self.wallet.activate.assert_not_called()

    def test_public_configuration_forbids_development_attestation(self):
        from serve import load_config
        fields = dict(bind='127.0.0.1', origin='https://api.openid.tensetti.io', team='A'*10,
            bundle='se.openid.PassportCapture', developmentAttestation=True, tlsCert='/missing',
            tlsKey='/missing', csca='/missing', database='/missing', pairingFile='/missing', publicEnrollment=True)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'config.json'; path.write_text(json.dumps(fields))
            with self.assertRaisesRegex(ValueError, 'production App Attest'): load_config(path)
            fields.update(developmentAttestation=False, origin='https://localhost:8765')
            path.write_text(json.dumps(fields))
            with self.assertRaisesRegex(ValueError, 'canonical origin'): load_config(path)

    def test_csca_crl_is_optional_but_must_be_an_absolute_existing_file(self):
        from serve import load_config
        fields = dict(bind='127.0.0.1', origin='https://localhost:8765', team='A'*10, bundle='se.openid.PassportCapture',
            developmentAttestation=True, tlsCert='/missing', tlsKey='/missing', csca='/missing', database='/missing', pairingFile='/missing')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'config.json'
            for crl, message in (('relative.crl', 'Absolute paths'), ('/missing.crl', 'Absolute paths|missing'), ):
                path.write_text(json.dumps(fields | {'cscaCrl': crl}))
                with self.assertRaisesRegex(ValueError, message): load_config(path)
            path.write_text(json.dumps(fields | {'unknownCrl': '/x'}))
            with self.assertRaisesRegex(ValueError, 'do not match'): load_config(path)

    def test_camera_rejection_returns_only_safe_frame_code(self):
        from biometric_worker import CameraImageRejected
        self.native.finish.side_effect = CameraImageRejected(2)
        code, result, headers = self.request('/native/finish')
        self.assertEqual(code, 422)
        self.assertEqual(result, {'error': 'CAMERA_IMAGE_REJECTED', 'frame': 2})
        self.assertEqual(headers['Cache-Control'], 'no-store')

    def test_chip_command_is_independent_of_the_optional_crl(self):
        from serve import proofing_commands
        config = {'jar': '/app/lab.jar', 'csca': '/s/csca.pem'}
        self.assertEqual(proofing_commands(config)[1], ['java', '-Xmx128m', '-jar', '/app/lab.jar', 'authenticate-chip', '/s/csca.pem'])
        passport, chip = proofing_commands(config | {'cscaCrl': '/s/csca.crl'})
        self.assertEqual(passport[-3:], ['verify-passport', '/s/csca.pem', '/s/csca.crl'])
        self.assertEqual(chip, ['java', '-Xmx128m', '-jar', '/app/lab.jar', 'authenticate-chip', '/s/csca.pem'])

    def test_security_code_errors_are_distinct_and_carry_only_a_count(self):
        from wallet import SecurityCodeError
        self.wallet.execute.side_effect = SecurityCodeError('PIN_INCORRECT', 3)
        self.assertEqual((403, {'error': 'PIN_INCORRECT', 'attemptsRemaining': 3}), self.request('/wallet/execute')[:2])
        self.wallet.execute.side_effect = SecurityCodeError('PIN_WEAK')
        self.assertEqual((403, {'error': 'PIN_WEAK'}), self.request('/wallet/execute')[:2])

    def test_attempt_limit_is_a_distinct_safe_error(self):
        from wallet import BiometricAttemptLimit
        self.native.finish.side_effect = BiometricAttemptLimit('biometric attempt limit')
        code, result, _ = self.request('/native/finish')
        self.assertEqual((403, {'error': 'ATTEMPT_LIMIT'}), (code, result))

    def test_complete_dispatch_and_security_headers(self):
        code, result, headers = self.request()
        self.assertEqual((200, {'id': 'session'}), (code, result))
        self.assertEqual('no-store', headers['Cache-Control'])
        self.assertIn('max-age', headers['Strict-Transport-Security'])
        self.native.start.assert_called_once_with()

    def test_boundary_and_input_rejections_never_call_service(self):
        self.app.enrollment_rate = RateLimit(burst=100)
        for change in [{'HTTP_HOST': 'evil.invalid'}, {'HTTP_ORIGIN': 'https://evil.invalid'},
                {'HTTP_X_CSRF_TOKEN': 'no'}, {'HTTP_X_CSRF_TOKEN': 'å'*43}, {'HTTP_X_FORWARDED_FOR': '127.0.0.1'},
                {'wsgi.url_scheme': 'http'}, {'QUERY_STRING': 'activate=true'}]:
            with self.subTest(change=change): self.assertEqual(403, self.request(**change)[0])
        for raw in [b'[]', b'{"id":1,"id":2}', b'{"value":NaN}', b'no json', b'{"unexpected":true}']:
            with self.subTest(raw=raw): self.assertEqual(400, self.request(body=raw)[0])
        self.assertEqual(413, self.request(CONTENT_LENGTH='14000001')[0])
        self.assertEqual(400, self.request(CONTENT_LENGTH='3')[0])
        self.assertEqual(415, self.request(HTTP_TRANSFER_ENCODING='chunked')[0])
        self.native.start.assert_not_called()

    def test_analysis_does_not_block_wallet_or_health_and_excess_is_rejected(self):
        entered, release = threading.Event(), threading.Event()
        def block(request): entered.set(); release.wait(5); return {'checksPassed': False}
        self.native.finish.side_effect = block
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            pending = pool.submit(self.request, '/native/finish')
            self.assertTrue(entered.wait(2))
            try:
                self.assertEqual(503, self.request('/native/finish')[0])
                self.assertEqual(200, self.request('/wallet/challenge')[0])
                self.assertEqual(200, self.request('/health/ready', 'GET')[0])
            finally: release.set()
            self.assertEqual(200, pending.result()[0])

    def test_shutdown_rejects_new_work_and_readiness(self):
        self.app.drain()
        self.assertEqual(503, self.request()[0])
        self.assertEqual(503, self.request('/health/ready', 'GET')[0])
        self.assertEqual(200, self.request('/health/live', 'GET')[0])
        self.native.start.assert_not_called()

    def test_stop_during_worker_boot_does_not_require_a_loaded_app(self):
        import signal
        from serve import bounded_worker
        Worker = bounded_worker()
        worker = Worker.__new__(Worker)
        worker.alive = True
        worker.method_queue = Mock()
        worker.handle_exit(signal.SIGTERM, None)
        self.assertFalse(worker.alive)
        worker.method_queue.defer.assert_called_once()
        worker.wsgi = self.app
        worker.handle_exit(signal.SIGTERM, None)
        self.assertEqual(503, self.request('/health/ready', 'GET')[0])

    def test_database_failure_readiness_and_errors_do_not_leak(self):
        self.wallet.health.side_effect = OSError('SECRET-PATH')
        self.assertEqual(503, self.request('/health/ready', 'GET')[0])
        self.native.start.side_effect = RuntimeError('PASSPORT SECRET')
        code, body, headers = self.request()
        self.assertEqual(503, code); self.assertEqual({'error': 'UNAVAILABLE'}, body)
        self.assertEqual('2', headers['Retry-After'])

    def test_metrics_have_bounded_labels_and_need_pairing(self):
        self.request('/private-secret-path')
        code, data, _ = self.request('/metrics', 'GET')
        self.assertEqual(200, code); self.assertNotIn('private-secret', json.dumps(data))
        self.assertEqual(403, self.request('/metrics', 'GET', HTTP_X_CSRF_TOKEN='wrong')[0])

    def test_start_rate_limit_and_recovery(self):
        now = [0]
        self.app.enrollment_rate = RateLimit(rate=1, burst=1, clock=lambda: now[0])
        self.assertEqual(200, self.request()[0]); self.assertEqual(429, self.request()[0])
        now[0] += 1
        self.assertEqual(200, self.request()[0])

    def test_global_rate_limit_capacity_does_not_evict_active_clients(self):
        limit = RateLimit(rate=1, burst=1, capacity=1)
        self.assertTrue(limit.allow('first')); self.assertFalse(limit.allow('second')); self.assertFalse(limit.allow('first'))

    def test_bad_origin_configuration(self):
        for value in ['http://localhost:8765', 'https://user@host:8765', 'https://host:8765/', 'https://host:80', 'https://host:8765?x=1']:
            with self.subTest(value=value), self.assertRaises(ValueError): validate_origin(value)

    def test_duplicate_and_forwarded_headers_rejected(self):
        from gunicorn.http.errors import InvalidHeader
        for headers in [[('HOST','one'),('HOST','two')], [('X-FORWARDED-FOR','one')], [('TRANSFER-ENCODING','chunked')]]:
            with self.assertRaises(InvalidHeader): reject_duplicate_headers(None, Mock(headers=headers))


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.wallet = Wallet(self.root/'live'/'wallet.sqlite', 'https://localhost:8765', crypto=lambda *a, **kw: None)
        import base64
        self.ident = self.wallet.enroll(base64.b64encode(b'key').decode())['id']
        self.wallet.activate(self.ident, 'TEST-REVIEW')

    def test_restore_old_backup_revokes_all_keys_and_requests(self):
        request = self.wallet.start_request(self.ident)
        snap = backup(self.wallet, self.root/'backup')
        self.wallet.revoke(self.ident)
        target = restore(snap, self.root/'restored')
        recovered = Wallet(target, self.wallet.origin)
        with self.assertRaises(ValueError): recovered.check_session(self.ident, 'anything')
        with recovered.transaction() as db:
            self.assertEqual('REVOKED', recovered.credential(db, self.ident)['state'])
            self.assertEqual('CANCELLED', db.execute('SELECT state FROM requests WHERE id=?',(request['id'],)).fetchone()[0])
        self.assertFalse((snap.parent/'wallet.identity-key').exists())

    def test_never_overwrites_live_database(self):
        snap = backup(self.wallet, self.root/'backup')
        with self.assertRaises(ValueError): restore(snap, self.root/'live')
        with self.wallet.transaction() as db: self.assertEqual('ACTIVE', self.wallet.state(self.wallet.credential(db,self.ident)))

    def test_corrupt_backup_leaves_no_destination(self):
        source = self.root/'bad'; source.write_bytes(b'bad SQLite')
        with self.assertRaises(Exception): restore(source, self.root/'restored')
        self.assertFalse((self.root/'restored').exists())

    def test_only_one_runtime_lease_and_released_after_close(self):
        lease = Lease(self.wallet.path)
        try:
            with self.assertRaises(ValueError): Lease(self.wallet.path)
        finally: lease.close()
        Lease(self.wallet.path).close()

    def test_health_does_not_recreate_deleted_database(self):
        import sqlite3
        self.wallet.path.unlink()
        with self.assertRaises(ValueError): self.wallet.health()
        with self.assertRaises(sqlite3.OperationalError):
            with self.wallet.transaction(): pass
        self.assertFalse(self.wallet.path.exists())

    def test_restart_does_not_reinitialize_a_lost_database(self):
        wallet = open_wallet(self.wallet.path, self.wallet.origin)
        open_wallet(wallet.path, wallet.origin).health()
        wallet.path.unlink()
        with self.assertRaises(ValueError): open_wallet(wallet.path, wallet.origin)
        self.assertFalse(wallet.path.exists())


class EncryptedRecoveryTests(unittest.TestCase):
    def test_restore_requires_correct_separate_key_and_revokes_profile(self):
        from test_identity import document
        from test_wallet import crypt
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wallet = Wallet(root/'live'/'wallet.sqlite', 'https://localhost:8765')
            key = json.loads(crypt(op='new'))
            ident = wallet.enroll(key['publicKey'], document())['id']
            wallet.activate(ident, 'TEST-PRIVATE-REVIEW')
            saved = backup(wallet, root/'backup')
            with self.assertRaises(ValueError): restore(saved, root/'missing-key')
            wrong = root/'wrong-key'; wrong.write_bytes(b'x'*64); wrong.chmod(0o600)
            with self.assertRaises(ValueError): restore(saved, root/'wrong', wrong)
            self.assertFalse((root/'wrong').exists())
            target = restore(saved, root/'restored', wallet.vault.path)
            recovered = Wallet(target, wallet.origin)
            with recovered.transaction() as db:
                snapshot = recovered.snapshot(db, ident)
                self.assertEqual('REVOKED', snapshot['state'])
                self.assertIsNone(snapshot['identity'])
                self.assertEqual('REVOKED', snapshot['events'][0]['kind'])
            with self.assertRaises(ValueError): recovered.activate(ident, 'TEST-REACTIVATE')

class PublicOriginTests(unittest.TestCase):
    def test_default_https_origin_keeps_exact_boundary(self):
        app = Runtime(Mock(), Mock(), 'https://api.example.org', 'a'*43)
        self.assertEqual(app.authority, 'api.example.org')
        self.assertEqual(app.origin, 'https://api.example.org')
        self.assertEqual(validate_origin('https://api.example.org:443').port, 443)
