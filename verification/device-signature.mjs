import {createPublicKey, verify} from 'node:crypto';
let input = '';
for await (const chunk of process.stdin) {
  input += chunk;
  if (input.length > 32768) process.exit(2);
}
try {
  const value = JSON.parse(input);
  const bytes = Buffer.from(value.publicKey, 'base64');
  const key = createPublicKey({key: bytes, format: 'der', type: 'spki'});
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails.namedCurve !== 'prime256v1' ||
      !key.export({format: 'der', type: 'spki'}).equals(bytes)) throw Error('key');
  if (value.operation === 'validate') {
    process.stdout.write('{"valid":true}');
  } else if (value.operation === 'verify' && verify('sha256', Buffer.from(value.payload, 'base64'),
      key, Buffer.from(value.signature, 'base64'))) {
    process.stdout.write('{"valid":true}');
  } else throw Error('signature');
} catch (_) { process.stdout.write('{"valid":false}'); process.exitCode = 2; }
