import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { CoseKey, Issuer, DeviceKey, IsoMdocDcApi, SignatureAlgorithm } from '@owf/mdoc';
import { context } from './context.mjs';
import { fixture } from './synthetic.mjs';
import { AGE_DOCTYPE, createRequest, keyPair, present, verifyCredential, verifyResponse } from './mdoc.mjs';

const site = 'https://video.example';
async function flow(ageOver18 = true) {
  const f = await fixture(ageOver18);
  const r = await createRequest(site, randomBytes(32).toString('base64url'));
  const input = { credential: f.credential, holderKey: f.holder.privateKey, request: r.request,
    browserOrigin: site, approvedOrigin: site, signerPins: [f.certificate] };
  const response = await present(input);
  const verification = { credential: response, request: r.request, recipientKey: r.recipientKey,
    siteOrigin: site, signerPins: [f.certificate] };
  return { f, r, input, response, verification };
}
test('real issuer signature, device signature and HPKE; only the age claim is disclosed', async () => {
  const { f, verification, response } = await flow();
  assert.equal(await verifyResponse(verification), true);
  assert.equal(response.protocol, 'org-iso-mdoc');
  const document = await verifyCredential(f.credential, [f.certificate]);
  assert.deepEqual(document.getPrettyClaims(AGE_DOCTYPE), { age_over_18: true });
});
test('cryptographically valid false remains a denial', async () => {
  assert.equal(await verifyResponse((await flow(false)).verification), false);
});
test('the same response is rejected for another site, nonce, and ephemeral key', async () => {
  const { verification } = await flow();
  await assert.rejects(verifyResponse({ ...verification, siteOrigin: 'https://community.example' }));
  const other = await createRequest(site, randomBytes(32).toString('base64url'));
  await assert.rejects(verifyResponse({ ...verification, request: other.request }));
  await assert.rejects(verifyResponse({ ...verification, recipientKey: other.recipientKey }));
});
test('tampered ciphertext, browser verdict, extra fields, and unknown signer are rejected', async () => {
  const { verification, response } = await flow();
  const bytes = Buffer.from(response.data.response, 'base64url');
  bytes[bytes.length - 8] ^= 1;
  await assert.rejects(verifyResponse({ ...verification,
    credential: { protocol: 'org-iso-mdoc', data: { response: bytes.toString('base64url') } } }));
  await assert.rejects(verifyResponse({ ...verification, credential: { age_over_18: true } }));
  await assert.rejects(verifyResponse({ ...verification, credential: { ...response, subject: 'extra' } }));
  await assert.rejects(verifyResponse({ ...verification, signerPins: [(await fixture()).certificate] }));
});
test('holder must consent to the actual browser origin and possess the issued key', async () => {
  const { input } = await flow();
  await assert.rejects(present({ ...input, approvedOrigin: 'https://community.example' }));
  await assert.rejects(present({ ...input, browserOrigin: '' }));
  await assert.rejects(present({ ...input, holderKey: keyPair().privateKey }));
});
test('expired credential cannot be loaded', async () => {
  const f = await fixture();
  await assert.rejects(verifyCredential(f.credential, [f.certificate], new Date(Date.now() + 86400000)));
});
test('extra identity attributes, document types and retention requests are rejected', async () => {
  const { f, input } = await flow();
  const issuer = new Issuer(AGE_DOCTYPE, context);
  issuer.addIssuerNamespace(AGE_DOCTYPE, { age_over_18: true, family_name: 'Synthetic' });
  const now = new Date();
  const extra = await issuer.sign({ signingKey: CoseKey.fromJwk(f.signerKey), certificates: [f.certificate],
    algorithm: SignatureAlgorithm.ES256, digestAlgorithm: 'SHA-256',
    deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(f.holder.publicKey) },
    validityInfo: { signed: now, validFrom: now, validUntil: new Date(Date.now() + 3600000) } });
  await assert.rejects(verifyCredential(extra.encodedForOid4Vci, [f.certificate]));
  for (const namespaces of [{ [AGE_DOCTYPE]: { age_over_18: true } },
    { [AGE_DOCTYPE]: { age_over_18: false, family_name: false } }]) {
    const { request } = await IsoMdocDcApi.createRequest({
      recipientPublicKey: CoseKey.fromJwk(keyPair().publicKey),
      docRequests: [{ docType: AGE_DOCTYPE, namespaces }],
    }, context);
    await assert.rejects(present({ ...input, request }));
  }
});
