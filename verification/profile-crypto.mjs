import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import {pathToFileURL} from 'node:url';

export function evaluate(request) {
  const { operation, key: encodedKey, aad, value } = request;
  const key = Buffer.from(encodedKey, 'base64');
  if (key.length !== 32 || typeof aad !== 'string' || aad.length > 300) throw Error();
  let output;
  if (operation === 'seal') {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(Buffer.from(aad));
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    output = { version: 1, nonce: nonce.toString('base64'), data: encrypted.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
  } else if (operation === 'open') {
    if (value.version !== 1) throw Error();
    const nonce = Buffer.from(value.nonce, 'base64'), tag = Buffer.from(value.tag, 'base64');
    if (nonce.length !== 12 || tag.length !== 16) throw Error();
    const cipher = createDecipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(Buffer.from(aad)); cipher.setAuthTag(tag);
    output = JSON.parse(Buffer.concat([cipher.update(Buffer.from(value.data, 'base64')), cipher.final()]).toString('utf8'));
  } else throw Error();
  return {value: output};
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  let input = '';
  try {
    for await (const chunk of process.stdin) {
      input += chunk;
      if (input.length > 100000) throw Error();
    }
    process.stdout.write(JSON.stringify(evaluate(JSON.parse(input))));
  } catch { process.exitCode = 1; }
}
