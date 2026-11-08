import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { createRequest, issueAgeCredential, verifyResponse } from './mdoc.mjs';
import { fixture } from './synthetic.mjs';
import { OneUseAgeWallet } from './wallet.mjs';

const origin = 'https://a.example';
const request = () => createRequest(origin, randomBytes(32).toString('base64url'));
const issuer = f => publicKey => issueAgeCredential({ signerKey: f.signerKey,
  signerCertificate: f.certificate, holderPublicKey: publicKey });

test('fresh device keys per proof; concurrent presentations spend different proofs', async () => {
  const f = await fixture();
  const wallet = new OneUseAgeWallet([f.certificate]);
  const publicKeys = [];
  await wallet.issueBatch(key => { publicKeys.push(key); return issuer(f)(key); }, 2);
  assert.notDeepEqual(publicKeys[0], publicKeys[1]);
  assert.ok(publicKeys.every(key => !key.d));
  const origins = [origin, 'https://b.example'];
  const sessions = await Promise.all(origins.map(site => createRequest(site, randomBytes(32).toString('base64url'))));
  const responses = await Promise.all(sessions.map((r, i) => wallet.present({ request: r.request,
    browserOrigin: origins[i], approvedOrigin: origins[i] })));
  assert.equal(wallet.remaining, 0);
  for (let i = 0; i < 2; i++) assert.equal(await verifyResponse({ ...sessions[i], credential: responses[i],
    siteOrigin: origins[i], signerPins: [f.certificate] }), true);
  await assert.rejects(wallet.present({ request: sessions[0].request, browserOrigin: origin, approvedOrigin: origin }));
});
test('a rejected presentation burns its proof and close cannot resurrect it', async () => {
  const f = await fixture();
  const wallet = new OneUseAgeWallet([f.certificate]);
  await wallet.issueBatch(issuer(f), 1);
  await assert.rejects(wallet.present({ request: (await request()).request,
    browserOrigin: origin, approvedOrigin: 'https://b.example' }));
  assert.equal(wallet.remaining, 0);
  wallet.close();
  await assert.rejects(wallet.issueBatch(issuer(f), 1));
});
test('issuance is atomic, bounded and rejects a certificate for another device key', async () => {
  const f = await fixture();
  const wallet = new OneUseAgeWallet([f.certificate]);
  let calls = 0;
  await assert.rejects(wallet.issueBatch(key => ++calls === 1 ? issuer(f)(key) : f.credential, 2));
  assert.equal(wallet.remaining, 0);
  await assert.rejects(wallet.issueBatch(issuer(f), 31));
  await assert.rejects(wallet.issueBatch(issuer(f), 0));
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const pending = wallet.issueBatch(async key => { await gate; return issuer(f)(key); }, 1);
  await assert.rejects(wallet.issueBatch(issuer(f), 1));
  wallet.close();
  release();
  await assert.rejects(pending);
  assert.equal(wallet.remaining, 0);
});
