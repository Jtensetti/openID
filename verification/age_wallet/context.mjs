import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify, X509Certificate } from 'node:crypto';
import { CoseKey, HpkeSuiteId, SignatureAlgorithm } from '@owf/mdoc';
import { CipherSuite, KEM_DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM } from 'hpke';

const suite = new CipherSuite(KEM_DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
const unsupported = () => { throw new Error('Unsupported age proof operation'); };
function es256(algorithm, key) {
  if (algorithm !== SignatureAlgorithm.ES256 || key.jwk.kty !== 'EC' || key.jwk.crv !== 'P-256') unsupported();
}

// Deliberately uses exact, operator-pinned document signer certificates. This
// is a private interop trust model, not a CA path builder or the EU trusted list.
export const context = {
  fetch: async () => { throw new Error('Network status lookup is not supported'); },
  crypto: {
    random: randomBytes,
    digest: ({ digestAlgorithm, bytes }) => {
      if (digestAlgorithm !== 'SHA-256') unsupported();
      return createHash('sha256').update(bytes).digest();
    },
    hdkf: unsupported,
    hpke: {
      suites: [HpkeSuiteId.DhkemP256HkdfSha256HkdfSha256Aes128Gcm],
      seal: async ({ recipientPublicKey, info, aad, plaintext }) => {
        const key = await suite.DeserializePublicKey(recipientPublicKey.publicKey);
        const { encapsulatedSecret, ciphertext } = await suite.Seal(key, plaintext, { info, aad });
        return { enc: encapsulatedSecret, ciphertext };
      },
      open: async ({ recipientKey, enc, info, aad, ciphertext }) => {
        const privateKey = await suite.DeserializePrivateKey(recipientKey.privateKey);
        const publicKey = await suite.DeserializePublicKey(recipientKey.publicKey);
        return suite.Open({ privateKey, publicKey }, enc, ciphertext, { info, aad });
      },
    },
  },
  cose: {
    mac0: { authenticate: unsupported, verify: unsupported },
    sign1: {
      sign: async ({ key, algorithm, toBeSigned }) => {
        es256(algorithm, key);
        return sign('sha256', toBeSigned, {
          key: createPrivateKey({ key: key.jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363',
        });
      },
      verify: async ({ key, algorithm, signature, toBeVerified }) => {
        es256(algorithm, key);
        return verify('sha256', toBeVerified, {
          key: createPublicKey({ key: key.jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363',
        }, signature);
      },
    },
  },
  x509: {
    getSubjectNameField: ({ certificate, field }) => new X509Certificate(certificate).subject
      .split('\n').filter(line => line.startsWith(field + '=')).map(line => line.slice(field.length + 1)),
    getPublicKey: async ({ certificate, algorithm }) => {
      const key = CoseKey.fromJwk(new X509Certificate(certificate).publicKey.export({ format: 'jwk' }));
      es256(algorithm, key);
      return key;
    },
    verifyCertificateChain: ({ trustedCertificates, x5chain, now = new Date() }) => {
      if (x5chain.length !== 1 || !trustedCertificates?.some(pin => Buffer.from(pin).equals(Buffer.from(x5chain[0])))) {
        throw new Error('Document signer is not pinned');
      }
      const cert = new X509Certificate(x5chain[0]);
      if (!(now >= cert.validFromDate && now <= cert.validToDate)) throw new Error('Document signer expired');
      return { chain: [x5chain[0]] };
    },
    getCertificateData: ({ certificate }) => {
      const c = new X509Certificate(certificate);
      return { issuerName: c.issuer, subjectName: c.subject, serialNumber: c.serialNumber,
        thumbprint: createHash('sha256').update(c.raw).digest('hex'),
        notBefore: c.validFromDate, notAfter: c.validToDate, pem: c.toString() };
    },
  },
};
