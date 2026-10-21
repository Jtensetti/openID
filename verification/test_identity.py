import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import tempfile
import unittest

import cv2
import numpy as np
from identity import VerifiedDocument
from federation import FederationServer
from test_wallet import crypt
from wallet import Wallet, FEDERATION_PURPOSE

AUDIENCE = 'https://localhost:8444/sp'

def document(**changes):
    identity = dict(givenNames='ALICE', familyName='SYNTHETIC', birthDateMrz='900101', nationality='UTO',
        issuingState='UTO', documentNumber='TEST00001', documentExpires='2030-10-19') | changes
    image = cv2.imencode('.jpg', np.zeros((32,32,3), dtype=np.uint8))[1].tobytes()
    return VerifiedDocument.from_verifier({'passiveAuthentication': True, 'portrait': base64.b64encode(image).decode(), 'identity': identity})

class IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = [json.loads(crypt(op='new')) for _ in range(3)]
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.time = 1792454400
        self.db = Path(self.tmp.name)/'wallet.sqlite'
        self.wallet = Wallet(self.db, 'https://localhost:8765', clock=lambda:self.time)
        self.ident = self.wallet.enroll(self.keys[0]['publicKey'], document())['id']
        self.wallet.activate(self.ident, 'REVIEW-fixture-001')
    def sign(self, action, request=None, key=0, wallet=None):
        wallet = wallet or self.wallet
        import hashlib
        ident = hashlib.sha256(base64.b64decode(self.keys[key]['publicKey'])).hexdigest()
        challenge = wallet.challenge({'credentialId':ident, 'action':action, 'requestId':request})
        return {'challengeId':challenge['id'], 'signature':crypt(op='sign', key=self.keys[key]['privateKey'], payload=challenge['signingInput'])}
    def execute(self, action='snapshot', request=None, key=0): return self.wallet.execute(self.sign(action, request, key))
    def start(self): return self.wallet.federation_start('_signed_saml_flow', AUDIENCE)
    def result(self, request, operation='consume', **changes):
        args = dict(request=request['id'], secret=request['secret'], binding='_signed_saml_flow', audience=AUDIENCE) | changes
        return self.wallet.federation_result(operation, **args)
    def login(self, key=0):
        request = self.start(); self.execute('approve', request['id'], key); return self.result(request)

    def test_verified_fields_encrypted_at_rest_and_returned_only_to_signed_owner(self):
        identity = self.execute()['identity']
        self.assertEqual('ALICE SYNTHETIC', identity['displayName']); self.assertEqual('900101', identity['birthDateMrz'])
        self.assertNotIn('documentNumber', identity)
        data = self.db.read_bytes()
        for value in (b'ALICE', b'SYNTHETIC', b'900101', b'TEST00001', identity['portraitJpeg'].encode()): self.assertNotIn(value, data)
        self.assertEqual(0, self.wallet.vault.path.stat().st_mode & 0o077)
    def test_no_century_or_person_number_is_inferred(self):
        value = document(birthDateMrz='000229').profile()
        self.assertEqual('000229', value['birthDateMrz']); self.assertNotIn('birthDate', value); self.assertNotIn('personalIdentityNumber', value)
        for dob in ('19000101', '001332', '000230', '900229', 'ABCDEF'):
            with self.assertRaises(ValueError): document(birthDateMrz=dob)
    def test_key_only_credential_cannot_approve_federation(self):
        legacy = self.wallet.enroll(self.keys[1]['publicKey'])['id']; self.wallet.activate(legacy, 'REVIEW-legacy-001')
        request = self.start()
        for action in ('inspect', 'approve', 'reject'):
            with self.assertRaises(ValueError): self.sign(action, request['id'], 1)
    def test_inspect_never_approves_and_signs_exact_disclosed_fields(self):
        request = self.start(); snapshot = self.execute('inspect', request['id'])
        self.assertEqual(request['id'], snapshot['requests'][0]['id'])
        self.assertEqual(FEDERATION_PURPOSE, snapshot['requests'][0]['purpose'])
        self.assertEqual('PENDING', self.result(request, 'poll')['state'])
        challenge = self.wallet.challenge({'credentialId':self.ident, 'action':'approve', 'requestId':request['id']})
        data = json.loads(base64.b64decode(challenge['signingInput']))
        self.assertEqual(snapshot['requests'][0]['purpose'], data['purpose']); self.assertEqual(request['code'], data['code'])
        data['purpose'] = 'Different consent'
        forged = crypt(op='sign', key=self.keys[0]['privateKey'], payload=base64.b64encode(json.dumps(data).encode()).decode())
        with self.assertRaises(ValueError): self.wallet.execute({'challengeId':challenge['id'], 'signature':forged})
        self.assertEqual('PENDING', self.result(request, 'poll')['state'])
    def test_binding_secret_audience_and_one_time_consumption(self):
        request = self.start(); self.execute('approve', request['id'])
        for change in ({'binding':'other'}, {'audience':'https://other.invalid/sp'}, {'secret':'x'*43}):
            with self.assertRaises(ValueError): self.result(request, **change)
        result = self.result(request)
        self.assertEqual('ALICE SYNTHETIC', result['identity']['displayName'])
        self.assertEqual('ACTIVE', self.wallet.federation_check(self.ident, result['subject'], result['version'], AUDIENCE)['state'])
        for change in ({'subject':'a'*64}, {'version':'b'*64}, {'audience':'https://other.invalid/sp'}):
            args = dict(ident=self.ident, subject=result['subject'], version=result['version'], audience=AUDIENCE) | change
            with self.assertRaises(ValueError): self.wallet.federation_check(**args)
        with self.assertRaises(ValueError): self.result(request)
    def test_same_passport_replacement_preserves_subject_and_revokes_old_key_and_session(self):
        old = self.login()
        replacement = self.wallet.enroll(self.keys[1]['publicKey'], document())['id']
        self.assertEqual('ACTIVE', self.execute()['state'])
        self.wallet.activate(replacement, 'REVIEW-replacement-001')
        self.assertEqual('REVOKED', self.execute()['state']); self.assertIsNone(self.execute()['identity'])
        with self.assertRaises(ValueError): self.wallet.federation_check(self.ident, old['subject'], old['version'], AUDIENCE)
        new = self.login(1); self.assertEqual(old['subject'], new['subject']); self.assertNotEqual(old['version'], new['version'])
    def test_same_name_and_birth_on_different_document_do_not_merge(self):
        first = self.login()
        second = self.wallet.enroll(self.keys[1]['publicKey'], document(documentNumber='TEST00002'))['id']
        self.wallet.activate(second, 'REVIEW-second-001')
        self.assertNotEqual(first['subject'], self.login(1)['subject']); self.assertEqual('ACTIVE', self.execute()['state'])
    def test_revocation_after_approval_and_backend_restart(self):
        request = self.start(); self.execute('approve', request['id'])
        other = Wallet(self.db, self.wallet.origin, clock=lambda:self.time); other.revoke(self.ident)
        with self.assertRaises(ValueError): self.result(request)
        self.wallet = other; self.assertEqual('REVOKED', self.execute()['state'])
    def test_rejection_cancellation_and_expiry_are_terminal(self):
        for operation in ('reject', 'cancel', 'expire'):
            request = self.start(); signed = self.sign('approve', request['id'])
            if operation == 'reject': self.execute('reject', request['id'])
            elif operation == 'cancel': self.result(request, 'cancel')
            else: self.time += 121
            expected = {'reject':'REJECTED', 'cancel':'CANCELLED', 'expire':'EXPIRED'}[operation]
            self.assertEqual(expected, self.result(request, 'poll')['state'])
            with self.assertRaises(ValueError): self.result(request, 'poll', secret='x'*43)
            with self.assertRaises(ValueError): self.wallet.execute(signed)
            with self.assertRaises(ValueError): self.result(request)
    def test_competing_devices_and_consumers_have_only_one_winner(self):
        second = self.wallet.enroll(self.keys[1]['publicKey'], document(documentNumber='TEST00002'))['id']; self.wallet.activate(second, 'REVIEW-second-002')
        request = self.start(); signed = [self.sign('approve', request['id'], i) for i in (0,1)]
        def approve(value):
            try: self.wallet.execute(value); return True
            except ValueError: return False
        with ThreadPoolExecutor(2) as pool: self.assertEqual(1, sum(pool.map(approve, signed)))
        def consume(_):
            try: self.result(request); return True
            except ValueError: return False
        with ThreadPoolExecutor(2) as pool: self.assertEqual(1, sum(pool.map(consume, range(2))))
    def test_tampering_swapped_ciphertext_and_missing_key_fail_closed(self):
        other = self.wallet.enroll(self.keys[1]['publicKey'], document(documentNumber='TEST00002'))['id']
        with self.wallet.transaction() as db:
            sealed = db.execute('SELECT sealed FROM profiles WHERE credential=?', (other,)).fetchone()[0]
            db.execute('UPDATE profiles SET sealed=? WHERE credential=?', (sealed, self.ident))
        with self.assertRaises(ValueError): self.execute()
        self.wallet.vault.path.unlink()
        with self.assertRaises(OSError): self.execute()
        with self.assertRaises(OSError): self.wallet.enroll(self.keys[2]['publicKey'], document())
        self.assertFalse(self.wallet.vault.path.exists())
    def test_wrong_encryption_key_and_modified_version_are_rejected(self):
        original = self.wallet.vault.path.read_bytes()
        self.wallet.vault.path.write_bytes(b'0'*64)
        with self.assertRaises(ValueError): self.execute()
        self.wallet.vault.path.write_bytes(original)
        with self.wallet.transaction() as db:
            value = json.loads(db.execute('SELECT sealed FROM profiles').fetchone()[0]); value['version'] = 2
            db.execute('UPDATE profiles SET sealed=?', (json.dumps(value),))
        with self.assertRaises(ValueError): self.execute()
    def test_no_profile_after_expiry_and_document_bounds_activation(self):
        other = self.wallet.enroll(self.keys[1]['publicKey'], document(documentExpires='2026-10-20'))['id']
        self.wallet.activate(other, 'REVIEW-expiry-001', hours=72)
        with self.wallet.transaction() as db: expiry = self.wallet.credential(db, other)['expires']
        self.assertLess(expiry, self.time+72*3600)
        self.time = expiry
        self.assertIsNone(self.execute(key=1)['identity'])
        with self.assertRaises(ValueError): self.sign('approve', self.start()['id'], 1)
    def test_bridge_is_private_bounded_and_has_no_activation_endpoint(self):
        bridge = FederationServer(Path(self.tmp.name)/'bridge.sock', self.wallet); self.addCleanup(bridge.close)
        self.assertEqual(0, bridge.path.stat().st_mode & 0o077)
        def call(data):
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(2); client.connect(str(bridge.path))
                client.sendall((data if isinstance(data, str) else json.dumps(data)).encode()+b'\n')
                return json.loads(client.makefile('rb').readline(100000))
        good = {'operation':'start', 'binding':'_saml', 'audience':AUDIENCE}
        self.assertTrue(call(good)['ok'])
        for bad in (good | {'audience':'https://evil.invalid/sp'}, good | {'operation':'activate'}, good | {'identity':{}}, 'x'*4097,
                    '{"operation":"start","operation":"check"}'):
            self.assertFalse(call(bad)['ok'])
        self.assertTrue(call({'operation':'health','audience':AUDIENCE})['ok'])

if __name__ == '__main__': unittest.main()
