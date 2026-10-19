import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import cbor from 'cbor';
// Fresh test-only keys and signatures. No Apple production credentials are used.
const team='ABCDEFGHIJ',bundle='se.openid.PassportCapture';
const keys=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const publicKey=keys.publicKey.export({type:'spki',format:'pem'});
const payload=Buffer.from('{"nonce":"one-time-test-challenge","frames":["test-frame"]}');
const hash=data=>createHash('sha256').update(data).digest();
const authData=Buffer.alloc(37);hash(Buffer.from(team+'.'+bundle)).copy(authData);authData.writeUInt32BE(1,33);
const signature=sign('sha256',hash(Buffer.concat([authData,hash(payload)])),keys.privateKey);
const assertion=cbor.encode({signature,authenticatorData:authData}).toString('base64');
function run(changes={}){
 return spawnSync(process.execPath,['attest.mjs'],{cwd:import.meta.dirname,input:JSON.stringify({operation:'assertion',teamIdentifier:team,bundleIdentifier:bundle,publicKey,payload:payload.toString('base64'),assertion,signCount:0,...changes}),encoding:'utf8'});
}
test('real signature verifies against exact payload and app',()=>{const result=run();assert.equal(result.status,0);assert.equal(JSON.parse(result.stdout).signCount,1);});
test('modified captured bytes rejected',()=>assert.equal(run({payload:Buffer.from('changed frame').toString('base64')}).status,2));
test('different app rejected',()=>assert.equal(run({bundleIdentifier:'se.attacker.app'}).status,2));
test('replayed counter rejected',()=>assert.equal(run({signCount:1}).status,2));
test('different key rejected',()=>{const other=generateKeyPairSync('ec',{namedCurve:'prime256v1'});assert.equal(run({publicKey:other.publicKey.export({type:'spki',format:'pem'})}).status,2);});
test('trailing CBOR rejected',()=>assert.equal(run({assertion:Buffer.concat([Buffer.from(assertion,'base64'),cbor.encode({})]).toString('base64')}).status,2));
