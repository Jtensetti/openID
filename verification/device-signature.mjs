import {createPublicKey, verify} from 'node:crypto';
import {pathToFileURL} from 'node:url';

export function evaluate(value) {
  const bytes = Buffer.from(value.publicKey, 'base64');
  const key = createPublicKey({key: bytes, format: 'der', type: 'spki'});
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails.namedCurve !== 'prime256v1' ||
      !key.export({format: 'der', type: 'spki'}).equals(bytes)) throw Error('key');
  if (value.operation === 'validate') {
    return {valid: true};
  } else if (value.operation === 'verify' && verify('sha256', Buffer.from(value.payload, 'base64'),
      key, Buffer.from(value.signature, 'base64'))) {
    return {valid: true};
  } else throw Error('signature');
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  let input = '';
  for await (const chunk of process.stdin) {
    input += chunk;
    if (input.length > 32768) process.exit(2);
  }
  try { process.stdout.write(JSON.stringify(evaluate(JSON.parse(input)))); }
  catch { process.stdout.write('{"valid":false}'); process.exitCode = 2; }
}
