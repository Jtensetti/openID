import base64
import json
from pathlib import Path
import tempfile
import unittest
from federation import FederationServer
from federation_parties import SANDBOX_PARTIES, sandbox_purpose
from test_identity import document
from test_wallet import crypt
from wallet import Wallet


class SandboxFederationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.wallet = Wallet(root / 'wallet.sqlite', 'https://localhost:8765', clock=lambda: 1792454400)
        self.key = json.loads(crypt(op='new'))
        self.ident = self.wallet.enroll(self.key['publicKey'], document())['id']
        self.wallet.activate(self.ident, 'REVIEW-sandbox-test')
        self.bridge = FederationServer(root / 'federation.sock', self.wallet, sandbox=True)
        self.addCleanup(self.bridge.close)
        self.sp = 'https://testclient.sandbox.swedenconnect.se/testsp1'
        self.signer = 'https://testclient.sandbox.swedenconnect.se/test-signservice1'

    def start(self, audience, message=None):
        data = {'operation': 'start', 'audience': audience, 'binding': 'test-binding'}
        if message is not None:
            data['signMessage'] = message
        return self.bridge.dispatch(data)

    def approve(self, request, action='approve'):
        challenge = self.wallet.challenge({'credentialId': self.ident, 'requestId': request['id'], 'action': action})
        payload = json.loads(base64.b64decode(challenge['signingInput']))
        signature = crypt(op='sign', key=self.key['privateKey'], payload=challenge['signingInput'])
        self.wallet.execute({'challengeId': challenge['id'], 'signature': signature})
        return payload

    def consume(self, request, audience):
        return self.bridge.dispatch({'operation': 'consume', 'audience': audience, 'id': request['id'],
                                     'secret': request['secret'], 'binding': 'test-binding'})

    def test_app_consent_names_the_external_recipient_and_is_not_reusable_elsewhere(self):
        request = self.start(self.sp)
        self.assertEqual(SANDBOX_PARTIES[self.sp], request['relyingParty'])
        payload = self.approve(request)
        self.assertEqual(request['relyingParty'], payload['relyingParty'])
        self.assertEqual(sandbox_purpose(False), payload['purpose'])
        with self.assertRaises(ValueError):
            self.consume(request, self.signer)
        result = self.consume(request, self.sp)
        self.assertEqual('AUTHENTICATED', result['state'])
        with self.assertRaises(ValueError):
            self.consume(request, self.sp)
        local = self.start('https://localhost:8444/sp')
        self.approve(local)
        self.assertNotEqual(result['subject'], self.consume(local, 'https://localhost:8444/sp')['subject'])

    def test_signing_requires_separate_approval_of_the_exact_text(self):
        message = 'Jag godkänner endast detta underskriftstest.'
        request = self.start(self.signer, message)
        with self.assertRaises(ValueError):
            self.approve(request)
        payload = self.approve(request, 'sign')
        self.assertEqual(message, payload['signMessage'])
        self.assertEqual(SANDBOX_PARTIES[self.signer], payload['relyingParty'])
        self.assertEqual(sandbox_purpose(True), payload['purpose'])
        result = self.consume(request, self.signer)
        import hashlib
        self.assertEqual(hashlib.sha256(message.encode()).hexdigest(), result['signMessageSha256'])

    def test_revocation_still_blocks_an_approved_external_request(self):
        request = self.start(self.sp)
        self.approve(request)
        self.wallet.revoke(self.ident)
        with self.assertRaises(ValueError):
            self.consume(request, self.sp)

    def test_other_clients_and_unconfigured_sandbox_access_are_denied(self):
        for audience in ('https://attacker.invalid', self.sp + '/other'):
            with self.assertRaises(ValueError):
                self.start(audience)
        self.bridge.audiences = {self.bridge.audience}
        for audience in SANDBOX_PARTIES:
            with self.assertRaises(ValueError):
                self.start(audience)


if __name__ == '__main__':
    unittest.main()
