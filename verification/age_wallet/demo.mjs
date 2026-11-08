import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createRequest, issueAgeCredential, verifyResponse } from './mdoc.mjs';
import { fixture } from './synthetic.mjs';
import { OneUseAgeWallet } from './wallet.mjs';

const f = await fixture();
const wallet = new OneUseAgeWallet([f.certificate]);
await wallet.issueBatch(holderPublicKey => issueAgeCredential({ signerKey: f.signerKey,
  signerCertificate: f.certificate, holderPublicKey }), 2);
console.log('Synthetic software-wallet demo. No iPhone, EU trust list or ZKP.');
for (const siteOrigin of ['https://a.example', 'https://b.example']) {
  const session = await createRequest(siteOrigin, randomBytes(32).toString('base64url'));
  const credential = await wallet.present({ request: session.request, browserOrigin: siteOrigin, approvedOrigin: siteOrigin });
  const age_over_18 = await verifyResponse({ ...session, credential, siteOrigin, signerPins: [f.certificate] });
  assert.equal(age_over_18, true);
  console.log(JSON.stringify({ site: siteOrigin, age_over_18 }));
}
assert.equal(wallet.remaining, 0);
await assert.rejects(wallet.present({}));
wallet.close();
console.log('2 distinct device keys spent; a third presentation was rejected.');
