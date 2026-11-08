import { generateKeyPairSync } from 'node:crypto';
import { CoseKey, DeviceKey, DeviceRequest, Holder, Issuer, IssuerSigned, IsoMdocDcApi, SignatureAlgorithm } from '@owf/mdoc';
import { context } from './context.mjs';

export const AGE_DOCTYPE = 'eu.europa.ec.av.1';
export const MAX_PROOF = 96 * 1024;
const reject = () => { throw new Error('Age proof rejected'); };
export function origin(value) {
  if (typeof value !== 'string' || value.length > 255 || !/^[\x21-\x7e]+$/.test(value)) reject();
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.origin !== value || url.username || url.password || url.pathname !== '/' ||
      !/^[a-z0-9.-]+\.[a-z][a-z0-9-]*$/.test(url.hostname)) reject();
  return value;
}
export function encoded(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > MAX_PROOF || !/^[A-Za-z0-9_-]+$/.test(value)) reject();
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value) reject();
  return bytes;
}
export function fields(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== names.length || !names.every(name => Object.hasOwn(value, name))) reject();
}
export function keyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { privateKey: privateKey.export({ format: 'jwk' }), publicKey: publicKey.export({ format: 'jwk' }) };
}
export function ageClaims(issuerSigned) {
  const mso = issuerSigned.issuerAuth.mobileSecurityObject;
  const ns = issuerSigned.issuerNamespaces?.issuerNamespaces;
  if (mso.docType !== AGE_DOCTYPE || mso.status || mso.deviceKeyInfo.keyInfo || mso.deviceKeyInfo.keyAuthorizations ||
      ns?.size !== 1 || ns.get(AGE_DOCTYPE)?.length !== 1) reject();
  const claims = issuerSigned.getPrettyClaims(AGE_DOCTYPE);
  fields(claims, ['age_over_18']);
  if (typeof claims.age_over_18 !== 'boolean') reject();
  return claims.age_over_18;
}
export async function verifyCredential(credential, signerPins, now = new Date()) {
  const issuerSigned = IssuerSigned.decode(encoded(credential));
  if (!Array.isArray(signerPins) || signerPins.length < 1 || signerPins.length > 16) reject();
  await Holder.verifyIssuerSigned({ issuerSigned, now, skewSeconds: 0,
    trustedCertificates: [{ issuance: signerPins }] }, context);
  ageClaims(issuerSigned);
  return issuerSigned;
}

// Synthetic/private issuance only. Authentication and the active-passport
// decision must be supplied by a real issuer; this module exposes no HTTP route.
export async function issueAgeCredential({ signerKey, signerCertificate, holderPublicKey, now = new Date(), ageOver18 = true, validUntil }) {
  if (typeof ageOver18 !== 'boolean' || holderPublicKey.d) reject();
  const issuer = new Issuer(AGE_DOCTYPE, context);
  issuer.addIssuerNamespace(AGE_DOCTYPE, { age_over_18: ageOver18 });
  const signed = new Date(now);
  const until = validUntil === undefined ? new Date(signed.getTime() + 86400000) : new Date(validUntil);
  if (!Number.isFinite(signed.getTime()) || !Number.isFinite(until.getTime()) || until <= signed || until - signed > 86400000) reject();
  return (await issuer.sign({ signingKey: CoseKey.fromJwk(signerKey), certificates: [signerCertificate],
    algorithm: SignatureAlgorithm.ES256, digestAlgorithm: 'SHA-256',
    deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(holderPublicKey) },
    validityInfo: { signed, validFrom: signed, validUntil: until },
  })).encodedForOid4Vci;
}
export async function createRequest(siteOrigin, nonce) {
  origin(siteOrigin);
  if (encoded(nonce).length !== 32) reject();
  const keys = keyPair();
  const { request } = await IsoMdocDcApi.createRequest({ nonce: encoded(nonce),
    recipientPublicKey: CoseKey.fromJwk(keys.publicKey),
    docRequests: [{ docType: AGE_DOCTYPE, namespaces: { [AGE_DOCTYPE]: { age_over_18: false } } }],
  }, context);
  return { request, recipientKey: keys.privateKey };
}
export async function present({ credential, holderKey, request, browserOrigin, approvedOrigin, signerPins }) {
  origin(browserOrigin);
  if (approvedOrigin !== browserOrigin) reject();
  fields(request, ['deviceRequest', 'encryptionInfo']);
  encoded(request.deviceRequest); encoded(request.encryptionInfo);
  const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin: browserOrigin }, context);
  if (parsedRequest.docRequests.length !== 1) reject();
  const doc = parsedRequest.docRequests[0];
  if (doc.docType !== AGE_DOCTYPE || doc.namespaces.size !== 1 || doc.namespaces.get(AGE_DOCTYPE)?.size !== 1 ||
      doc.namespaces.get(AGE_DOCTYPE)?.get('age_over_18') !== false) reject();
  const issuerSigned = await verifyCredential(credential, signerPins);
  const key = CoseKey.fromJwk({ ...holderKey, alg: 'ES256' });
  if (!Buffer.from(issuerSigned.issuerAuth.mobileSecurityObject.deviceKeyInfo.deviceKey.publicKey)
      .equals(Buffer.from(key.publicKey))) reject();
  return { protocol: 'org-iso-mdoc', data: await IsoMdocDcApi.createResponse({ parsedRequest,
    documents: [{ issuerSigned, deviceKey: key, docRequestIndex: 0 }] }, context) };
}
export async function verifyResponse({ credential, request, recipientKey, siteOrigin, signerPins }) {
  origin(siteOrigin);
  fields(credential, ['protocol', 'data']);
  fields(credential.data, ['response']);
  if (credential.protocol !== 'org-iso-mdoc') reject();
  encoded(credential.data.response);
  if (!Array.isArray(signerPins) || signerPins.length < 1 || signerPins.length > 16) reject();
  const { deviceResponse, verificationResult } = await IsoMdocDcApi.verifyResponse({
    response: credential.data, origin: siteOrigin, encryptionInfo: request.encryptionInfo,
    recipientKey: CoseKey.fromJwk(recipientKey),
    deviceRequest: DeviceRequest.decode(encoded(request.deviceRequest)),
    trustedCertificates: [{ issuance: signerPins }], skewSeconds: 0,
  }, context);
  if (deviceResponse.documents?.length !== 1 || verificationResult.deviceRequestMatch?.success !== true ||
      deviceResponse.documents[0].deviceSigned.deviceNamespaces.deviceNamespaces.size !== 0) reject();
  return ageClaims(deviceResponse.documents[0].issuerSigned);
}
