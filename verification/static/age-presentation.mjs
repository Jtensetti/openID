/**
 * Browser transport for the separate age-verification lab.
 * Accept only the public `presentation` from the RP; API keys and the private
 * session binding stay on its server. No credential is verified in this module.
 *
 * Envelope references (not copied implementation):
 * https://www.w3.org/TR/2026/WD-digital-credentials-20261105/
 * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-A
 * https://developer.apple.com/documentation/identitydocumentservices/requesting-a-mobile-document-on-the-web
 */

const PROTOCOLS = new Set(['org-iso-mdoc', 'openid4vp-v1-signed']);
const MAX_PAYLOAD = 96 * 1024;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
// Direct ECDH-ES can have an empty encrypted-key segment.
const JWE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const MESSAGES = Object.freeze({
  invalid_presentation: 'Age presentation is invalid.',
  unavailable: 'Digital credential presentation is unavailable.',
  cancelled: 'Age presentation was cancelled.',
  timeout: 'Age presentation timed out.',
  failed: 'Age presentation could not be completed.',
});

export class AgePresentationError extends Error {
  constructor(code = 'failed') {
    const safeCode = Object.hasOwn(MESSAGES, code) ? code : 'failed';
    super(MESSAGES[safeCode]);
    this.name = 'AgePresentationError';
    this.code = safeCode;
  }
}

function fail(code = 'invalid_presentation') {
  throw new AgePresentationError(code);
}

function fields(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Object.keys(value).length !== expected.length ||
      !expected.every(key => Object.hasOwn(value, key))) fail();
}

function encoded(value, pattern) {
  if (typeof value !== 'string' || value.length > MAX_PAYLOAD || !pattern.test(value)) fail();
  return value;
}

function digitalRequests(presentation) {
  fields(presentation, ['method', 'requests']);
  if (presentation.method !== 'dc_api' || !Array.isArray(presentation.requests) ||
      presentation.requests.length < 1 || presentation.requests.length > PROTOCOLS.size) fail();
  const offered = new Set();
  const requests = presentation.requests.map(item => {
    fields(item, ['protocol', 'data']);
    const { protocol, data } = item;
    if (!PROTOCOLS.has(protocol) || offered.has(protocol)) fail();
    offered.add(protocol);
    if (protocol === 'org-iso-mdoc') {
      fields(data, ['deviceRequest', 'encryptionInfo']);
      return { protocol, data: {
        deviceRequest: encoded(data.deviceRequest, BASE64URL),
        encryptionInfo: encoded(data.encryptionInfo, BASE64URL),
      } };
    }
    fields(data, ['request']);
    return { protocol, data: { request: encoded(data.request, JWS) } };
  });
  if (JSON.stringify(requests).length > MAX_PAYLOAD) fail();
  return requests;
}

function opaqueResponse(credential, requests) {
  if (!credential || credential.type !== 'digital' ||
      !requests.some(item => item.protocol === credential.protocol)) fail('failed');
  // This lab accepts encrypted response envelopes only. This syntax check does
  // not decrypt, authenticate, check nonce/origin/issuer, or establish age.
  fields(credential.data, ['response']);
  const response = encoded(credential.data.response,
    credential.protocol === 'org-iso-mdoc' ? BASE64URL : JWE);
  return { protocol: credential.protocol, data: { response } };
}

/**
 * Call directly from a user click with an already prepared presentation.
 * Returns opaque {protocol, data} for the RP server to submit to its verifier.
 * Never treat a fulfilled promise as an age approval. No fetch, storage,
 * navigation, fallback, or logging occurs here.
 *
 * `navigator`, `DigitalCredential`, and `isSecureContext` may be injected by
 * tests. timeoutMs must be 1..120000; the default is 60000. The caller should
 * choose a timeout no longer than the server transaction's remaining lifetime.
 */
export async function runDigitalPresentation(presentation, options = {}) {
  let timer;
  let externalSignal;
  let onAbort;
  try {
    const requests = digitalRequests(presentation);
    const nav = options.navigator ?? globalThis.navigator;
    const Digital = options.DigitalCredential ?? globalThis.DigitalCredential;
    const secure = options.isSecureContext ?? globalThis.isSecureContext;
    const timeoutMs = options.timeoutMs ?? 60000;
    externalSignal = options.signal;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000) fail();
    if (externalSignal !== undefined &&
        (!externalSignal || typeof externalSignal.aborted !== 'boolean' ||
         typeof externalSignal.addEventListener !== 'function' ||
         typeof externalSignal.removeEventListener !== 'function')) fail();
    if (secure !== true || typeof nav?.credentials?.get !== 'function' ||
        typeof Digital?.userAgentAllowsProtocol !== 'function' ||
        typeof globalThis.AbortController !== 'function' ||
        nav.userActivation?.isActive !== true ||
        requests.some(item => Digital.userAgentAllowsProtocol(item.protocol) !== true)) fail('unavailable');
    if (externalSignal?.aborted) fail('cancelled');

    const controller = new AbortController();
    let stopCode;
    const stopped = new Promise((_, reject) => {
      const stop = code => {
        if (stopCode) return;
        stopCode = code;
        reject(new AgePresentationError(code));
        // Never forward the caller's arbitrary AbortSignal.reason to a wallet.
        controller.abort();
      };
      onAbort = () => stop('cancelled');
      externalSignal?.addEventListener('abort', onAbort, { once: true });
      timer = setTimeout(() => stop('timeout'), timeoutMs);
    });
    // Install handlers even if get() throws synchronously. The race also bounds
    // a browser implementation that does not settle its promise after abort.
    const operation = new Promise((resolve, reject) => {
      try {
        resolve(nav.credentials.get({ digital: { requests }, mediation: 'required', signal: controller.signal }));
      } catch {
        reject(new AgePresentationError('failed'));
      }
    });
    const credential = await Promise.race([operation, stopped]);
    if (stopCode) fail(stopCode);
    return opaqueResponse(credential, requests);
  } catch (error) {
    // Rebuild even our errors: never propagate wallet/browser messages, causes,
    // credential payloads or arbitrary rejection values to UI/logging code.
    throw new AgePresentationError(error instanceof AgePresentationError ? error.code : 'failed');
  } finally {
    clearTimeout(timer);
    if (onAbort) externalSignal?.removeEventListener('abort', onAbort);
  }
}

/** Return a narrowly validated URI for an explicit link click; never navigate. */
export function openId4VpAuthorizationUri(presentation) {
  try {
    fields(presentation, ['method', 'authorizationRequest']);
    const value = presentation.authorizationRequest;
    if (presentation.method !== 'openid4vp' || typeof value !== 'string' ||
        value.length > 8192 || !/^openid4vp:\/\/(?:authorize)?\?/.test(value) ||
        /[^\x21-\x7e]|\\/.test(value) || value.includes('#')) fail();
    const uri = new URL(value);
    if (uri.protocol !== 'openid4vp:' || !['', 'authorize'].includes(uri.hostname) ||
        uri.username || uri.password || uri.port || uri.pathname || uri.hash) fail();
    const allowed = new Set(['client_id', 'request_uri', 'request_uri_method']);
    const seen = new Set();
    for (const [key] of uri.searchParams) {
      if (!allowed.has(key) || seen.has(key)) fail();
      seen.add(key);
    }
    const clientId = uri.searchParams.get('client_id');
    const requestUri = uri.searchParams.get('request_uri');
    const method = uri.searchParams.get('request_uri_method');
    if (!clientId || clientId.length > 1024 || /[^\x21-\x7e]|\\/.test(clientId) ||
        !requestUri || requestUri.length > 4096 || !requestUri.startsWith('https://') ||
        /[^\x21-\x7e]|\\/.test(requestUri) || requestUri.includes('#') ||
        (method !== null && !['get', 'post'].includes(method))) fail();
    const request = new URL(requestUri);
    if (requestUri.slice(8).split(/[/?#]/, 1)[0].includes('@') ||
        request.protocol !== 'https:' || !request.hostname || request.username ||
        request.password || request.hash) fail();
    return value;
  } catch {
    throw new AgePresentationError('invalid_presentation');
  }
}
