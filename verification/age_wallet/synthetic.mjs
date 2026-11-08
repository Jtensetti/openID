// Test-only issuance: fresh software keys and a temporary self-signed signer.
import { execFileSync } from 'node:child_process';
import { createPrivateKey, X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { setTimeout } from 'node:timers/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { issueAgeCredential, keyPair } from './mdoc.mjs';

export async function fixture(ageOver18 = true, now) {
  const directory = mkdtempSync(join(tmpdir(), 'tjipp-age-test-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
      '-nodes', '-days', '2', '-subj', '/CN=Tjipp synthetic age signer/C=SE',
      '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem')], { stdio: 'ignore' });
    const pem = readFileSync(join(directory, 'cert.pem'), 'utf8');
    const certificate = new X509Certificate(pem).raw;
    const signerKey = createPrivateKey(readFileSync(join(directory, 'key.pem'))).export({ format: 'jwk' });
    // Upstream requires signed > notBefore, at whole-second precision.
    await setTimeout(1100);
    const holder = keyPair();
    const credential = await issueAgeCredential({ signerKey, signerCertificate: certificate,
      holderPublicKey: holder.publicKey, now, ageOver18 });
    return { pem, certificate, signerKey, holder, credential };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
