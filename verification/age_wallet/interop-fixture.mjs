// Private pipes between the Python integration tests and the software holder.
// Never used by worker.mjs or installed as an HTTP endpoint.
import { fixture } from './synthetic.mjs';
import { present, issueAgeCredential } from './mdoc.mjs';
import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';

try {
  let raw = '';
  for await (const chunk of process.stdin) {
    raw += chunk;
    if (raw.length > 256 * 1024) throw new Error();
  }
  const input = JSON.parse(raw);
  if (input.operation === 'fixture') {
    const f = await fixture(input.ageOver18);
    process.stdout.write(JSON.stringify({ pem: f.pem, credential: f.credential, holderKey: f.holder.privateKey }));
  } else if (input.operation === 'present') {
    if (input.holderPem) input.holderKey = createPrivateKey(input.holderPem).export({ format: 'jwk' });
    process.stdout.write(JSON.stringify(await present({ ...input, signerPins: [new X509Certificate(input.pem).raw] })));
  } else if (input.operation === 'issue') {
    const f = await fixture();
    if (!Array.isArray(input.publicKeys) || input.publicKeys.length > 30) throw new Error();
    const credentials = [];
    for (const key of input.publicKeys) {
      credentials.push(await issueAgeCredential({ signerKey: f.signerKey, signerCertificate: f.certificate,
        holderPublicKey: createPublicKey({ key: Buffer.from(key, 'base64'), format: 'der', type: 'spki' }).export({ format: 'jwk' }),
        validUntil: input.validUntil * 1000 }));
    }
    process.stdout.write(JSON.stringify({ pem: f.pem, credentials }));
  } else throw new Error();
} catch {
  process.exitCode = 1;
}
