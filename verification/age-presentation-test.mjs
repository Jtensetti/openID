import test from 'node:test';
import assert from 'node:assert/strict';
import { AgePresentationError, openId4VpAuthorizationUri, runDigitalPresentation } from './static/age-presentation.mjs';

// Transport-only synthetic data: these strings are not signed credentials.
const MDOC = 'org-iso-mdoc';
const SIGNED = 'openid4vp-v1-signed';
const mdocRequest = () => ({ protocol: MDOC, data: { deviceRequest: 'ZGV2aWNl', encryptionInfo: 'ZW5jcnlwdGlvbg' } });
const signedRequest = () => ({ protocol: SIGNED, data: { request: 'aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl' } });
const presentation = (requests = [mdocRequest()]) => ({ method: 'dc_api', requests });
const credential = (protocol = MDOC) => ({
  type: 'digital', protocol,
  data: { response: protocol === MDOC ? 'ZW5jcnlwdGVk' : 'aGVhZGVy..aXY.Y2lwaGVydGV4dA.dGFn' },
  id: 'must-not-be-returned',
});
function environment(get = async () => credential(), overrides = {}) {
  return {
    navigator: { credentials: { get }, userActivation: { isActive: true } },
    DigitalCredential: { userAgentAllowsProtocol: () => true },
    isSecureContext: true,
    ...overrides,
  };
}
const rejected = code => error => {
  assert.ok(error instanceof AgePresentationError);
  if (code) assert.equal(error.code, code);
  assert.equal(error.cause, undefined);
  return true;
};

test('passes only public protocol requests and returns opaque response, never an age verdict', async () => {
  let call;
  const input = presentation();
  const returned = credential();
  const result = await runDigitalPresentation(input, environment(async options => {
    call = options;
    return returned;
  }));
  assert.deepEqual(Object.keys(call).sort(), ['digital', 'mediation', 'signal']);
  assert.equal(call.mediation, 'required');
  assert.deepEqual(call.digital, { requests: input.requests });
  assert.notEqual(call.digital.requests, input.requests);
  assert.equal(call.signal.aborted, false);
  assert.deepEqual(result, { protocol: MDOC, data: returned.data });
  assert.notEqual(result.data, returned.data);
  assert.equal('age_over_18' in result, false);
  assert.equal('id' in result, false);
});

test('accepts the signed OID4VP encrypted envelope, including a direct ECDH-ES JWE', async () => {
  const result = await runDigitalPresentation(presentation([signedRequest()]), environment(async () => credential(SIGNED)));
  assert.deepEqual(result, { protocol: SIGNED, data: credential(SIGNED).data });
});

test('preserves explicitly offered protocols without an automatic fallback', async () => {
  let call;
  const input = presentation([signedRequest(), mdocRequest()]);
  const result = await runDigitalPresentation(input, environment(async options => {
    call = options;
    return credential();
  }));
  assert.deepEqual(call.digital.requests, input.requests);
  assert.equal(result.protocol, MDOC);
  let calls = 0;
  await assert.rejects(runDigitalPresentation(input, environment(() => { calls += 1; }, {
    DigitalCredential: { userAgentAllowsProtocol: protocol => protocol === MDOC },
  })), rejected('unavailable'));
  assert.equal(calls, 0);
});

test('refuses private session fields, malformed envelopes and unknown protocols before requesting a wallet', async () => {
  let calls = 0;
  const env = environment(() => { calls += 1; });
  for (const input of [
    { id: 'private', binding: 'private', presentation: presentation() },
    { ...presentation(), binding: 'private' },
    { method: 'dc_api', requests: [] },
    presentation([mdocRequest(), mdocRequest()]),
    presentation([{ protocol: 'org-iso-mdoc-zk', data: mdocRequest().data }]),
    presentation([{ protocol: 'openid4vp', data: signedRequest().data }]),
    presentation([{ protocol: MDOC, data: { age_over_18: true } }]),
    presentation([{ protocol: MDOC, data: { ...mdocRequest().data, subject: 'private' } }]),
    presentation([{ protocol: SIGNED, data: { request: 'unsigned' } }]),
    presentation([{ protocol: MDOC, data: { deviceRequest: 'a'.repeat(100000), encryptionInfo: 'YQ' } }]),
    { method: 'openid4vp', requests: [mdocRequest()] },
    null,
  ]) await assert.rejects(runDigitalPresentation(input, env), rejected('invalid_presentation'));
  assert.equal(calls, 0);
});

test('requires a secure context, DC API support, supported protocols and a user gesture', async () => {
  for (const overrides of [
    { isSecureContext: false },
    { navigator: { credentials: {}, userActivation: { isActive: true } } },
    { navigator: { credentials: { get() { assert.fail('must not call'); } }, userActivation: { isActive: false } } },
    { DigitalCredential: {} },
    { DigitalCredential: { userAgentAllowsProtocol: () => false } },
  ]) await assert.rejects(runDigitalPresentation(presentation(), environment(undefined, overrides)), rejected('unavailable'));
});

test('rejects bare age assertions, protocol errors, mismatched protocols and malformed wallet responses', async () => {
  for (const response of [
    null, true, { age_over_18: true },
    { ...credential(), data: { age_over_18: true } },
    { ...credential(), data: { response: true } },
    { ...credential(), data: { response: '' } },
    { ...credential(), data: { response: 'YWJj', age_over_18: true } },
    { ...credential(), data: { error: 'wallet details must not escape' } },
    { ...credential(), data: { response: 'a'.repeat(100000) } },
    { ...credential(), protocol: 'unknown' },
    { ...credential(), type: 'password' },
    credential(SIGNED),
  ]) await assert.rejects(runDigitalPresentation(presentation(), environment(async () => response)), rejected());
});

test('sanitizes rejected promises and synchronous browser exceptions', async () => {
  for (const get of [
    () => { throw new Error('private credential and browser details'); },
    async () => { throw { credential: 'private', message: 'secret' }; },
  ]) await assert.rejects(runDigitalPresentation(presentation(), environment(get)), error => {
    rejected('failed')(error);
    assert.equal(error.message, 'Age presentation could not be completed.');
    assert.doesNotMatch(String(error), /private|secret/);
    return true;
  });
});

test('does not request a wallet for a pre-aborted caller signal', async () => {
  const controller = new AbortController();
  controller.abort(new Error('sensitive cancellation reason'));
  await assert.rejects(runDigitalPresentation(presentation(), environment(() => assert.fail('must not call'), {
    signal: controller.signal,
  })), rejected('cancelled'));
});

test('propagates caller cancellation even when the browser ignores abort, without forwarding its reason', async () => {
  const controller = new AbortController();
  let browserSignal;
  const running = runDigitalPresentation(presentation(), environment(options => {
    browserSignal = options.signal;
    return new Promise(() => {});
  }, { signal: controller.signal }));
  controller.abort(new Error('sensitive cancellation reason'));
  await assert.rejects(running, rejected('cancelled'));
  assert.equal(browserSignal.aborted, true);
  assert.notEqual(browserSignal.reason, controller.signal.reason);
  assert.doesNotMatch(String(browserSignal.reason), /sensitive/);
});

test('has a finite timeout even when the browser ignores abort', async () => {
  let browserSignal;
  await assert.rejects(runDigitalPresentation(presentation(), environment(options => {
    browserSignal = options.signal;
    return new Promise(() => {});
  }, { timeoutMs: 5 })), rejected('timeout'));
  assert.equal(browserSignal.aborted, true);
});

test('invalid timeout and signal options fail before the wallet call', async () => {
  const never = () => assert.fail('must not call');
  for (const timeoutMs of [0, -1, Infinity, NaN, 0.5, 120001, '100']) {
    await assert.rejects(runDigitalPresentation(presentation(), environment(never, { timeoutMs })), rejected('invalid_presentation'));
  }
  await assert.rejects(runDigitalPresentation(presentation(), environment(never, { signal: {} })), rejected('invalid_presentation'));
});

test('detaches the external abort listener after success', async () => {
  const controller = new AbortController();
  let browserSignal;
  await runDigitalPresentation(presentation(), environment(async options => {
    browserSignal = options.signal;
    return credential();
  }, { signal: controller.signal }));
  controller.abort();
  assert.equal(browserSignal.aborted, false);
});

const uri = (requestUri = 'https://verifier.example/wallet/request/opaque?version=1', rest = '') =>
  `openid4vp://?client_id=x509_san_dns%3Averifier.example&request_uri=${encodeURIComponent(requestUri)}${rest}`;
const openid = authorizationRequest => ({ method: 'openid4vp', authorizationRequest });

test('returns an unchanged validated OpenID4VP URI for a later explicit click', () => {
  const value = uri();
  assert.equal(openId4VpAuthorizationUri(openid(value)), value);
  const authorize = value.replace('openid4vp://?', 'openid4vp://authorize?');
  assert.equal(openId4VpAuthorizationUri(openid(authorize)), authorize);
  assert.equal(openId4VpAuthorizationUri(openid(uri(undefined, '&request_uri_method=post'))), uri(undefined, '&request_uri_method=post'));
});

test('rejects unsafe URI schemes, authority, path, credentials, fragments and duplicate parameters', () => {
  for (const value of [
    'javascript:alert(1)', 'https://verifier.example/request',
    uri().replace('openid4vp://?', 'openid4vp://evil.example?'),
    uri().replace('openid4vp://?', 'openid4vp://user:pass@authorize?'),
    uri().replace('openid4vp://?', 'openid4vp://authorize:?'),
    uri().replace('openid4vp://?', 'openid4vp://@?'),
    uri().replace('openid4vp://?', 'openid4vp:///path?'),
    uri('http://verifier.example/request'),
    uri('https://user:pass@verifier.example/request'),
    uri('https://@verifier.example/request'),
    uri('https://verifier.example/request#fragment'),
    uri('https://verifier.example\\@evil.example/request'),
    uri('https://verifier.example/request\n'),
    uri(undefined, '#'), uri(undefined, '&request_uri=https%3A%2F%2Fevil.example'),
    uri(undefined, '&client_id=other'), uri(undefined, '&redirect_uri=https%3A%2F%2Fevil.example'),
    uri(undefined, '&request_uri_method=delete'),
    'openid4vp://?request_uri=https%3A%2F%2Fverifier.example',
  ]) assert.throws(() => openId4VpAuthorizationUri(openid(value)), rejected('invalid_presentation'));
  assert.throws(() => openId4VpAuthorizationUri({ ...openid(uri()), binding: 'private' }), rejected('invalid_presentation'));
});
