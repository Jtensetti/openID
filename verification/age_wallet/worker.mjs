import { createRequest, verifyResponse, fields } from './mdoc.mjs';

try {
  let size = 0;
  const chunks = [];
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 256 * 1024) throw new Error();
    chunks.push(chunk);
  }
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  let result;
  if (input.operation === 'begin') {
    fields(input, ['operation', 'origin', 'nonce']);
    result = await createRequest(input.origin, input.nonce);
  } else {
    fields(input, ['operation', 'credential', 'request', 'recipientKey', 'siteOrigin', 'signerPins']);
    if (input.operation !== 'verify') throw new Error();
    result = { age_over_18: await verifyResponse({ ...input,
      signerPins: input.signerPins.map(pin => Buffer.from(pin, 'base64')) }) };
  }
  process.stdout.write(JSON.stringify(result));
} catch {
  // Never emit a credential, private key, origin, or a dependency error.
  process.exitCode = 1;
}
