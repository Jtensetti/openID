import {createInterface} from 'node:readline';
import {evaluate as signature} from './device-signature.mjs';
import {evaluate as profile} from './profile-crypto.mjs';
const evaluate = {signature, profile}[process.argv[2]];
if (!evaluate) process.exit(2);
const lines = createInterface({input: process.stdin, crlfDelay: Infinity});
for await (const line of lines) {
  if (line.length > 100000) process.exit(2);
  let result;
  try { result = {ok: true, result: evaluate(JSON.parse(line))}; }
  catch { result = {ok: false}; }
  process.stdout.write(JSON.stringify(result)+'\n');
}
