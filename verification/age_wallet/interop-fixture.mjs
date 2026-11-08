// Private pipes between the Python integration tests and the software holder.
// Never used by worker.mjs or installed as an HTTP endpoint.
import { fixture } from './synthetic.mjs';
import { present } from './mdoc.mjs';

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
    const { X509Certificate } = await import('node:crypto');
    process.stdout.write(JSON.stringify(await present({ ...input, signerPins: [new X509Certificate(input.pem).raw] })));
  } else throw new Error();
} catch {
  process.exitCode = 1;
}
