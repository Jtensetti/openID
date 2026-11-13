import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import cbor from 'cbor';
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

function extended({extensions={apple_validation_category_01:5,apple_bundle_version_01:'117'},flags=0x80,tail=Buffer.alloc(0),counter=1}={}) {
 const head=Buffer.from(authData);head[32]=flags;head.writeUInt32BE(counter,33);
 const data=Buffer.concat([head,cbor.encode(extensions),tail]);
 const signature=sign('sha256',hash(Buffer.concat([data,hash(payload)])),keys.privateKey);
 return cbor.encode({signature,authenticatorData:data}).toString('base64');
}
test('signed Apple authenticator extensions accepted',()=>assert.equal(run({assertion:extended()}).status,0));
test('documented short extension names accepted',()=>assert.equal(run({assertion:extended({extensions:{validationCategory:5,bundleVersion:'117'}})}).status,0));
test('modified payload still rejected with extensions',()=>assert.equal(run({assertion:extended(),payload:Buffer.from('changed').toString('base64')}).status,2));
test('replayed extended assertion rejected',()=>assert.equal(run({assertion:extended(),signCount:1}).status,2));
test('extended assertion for different app rejected',()=>assert.equal(run({assertion:extended(),bundleIdentifier:'se.attacker.app'}).status,2));
test('development and invalid categories rejected in production',()=>{for(const n of [0,1,3,6,7,8,9,10])assert.equal(run({assertion:extended({extensions:{apple_validation_category_01:n,apple_bundle_version_01:'117'}})}).status,2);});
test('older or malformed version rejected',()=>{for(const v of ['116','117junk','00117',117])assert.equal(run({assertion:extended({extensions:{apple_validation_category_01:5,apple_bundle_version_01:v}})}).status,2);});
test('unflagged or trailing extension data rejected',()=>{assert.equal(run({assertion:extended({flags:0})}).status,2);assert.equal(run({assertion:extended({tail:cbor.encode({})})}).status,2);});
test('missing and unknown extensions rejected',()=>{for(const e of [{},{apple_validation_category_01:5},{apple_validation_category_01:5,other:'117'}])assert.equal(run({assertion:extended({extensions:e})}).status,2);});
test('Apple assertion flags C0 accepted with signed extensions',()=>assert.equal(run({assertion:extended({flags:0xc0})}).status,0));

test('iOS 27 shape with little-endian category and C0 flags verifies',()=>{
 const category=Buffer.alloc(4);category.writeUInt32LE(5);
 const assertion=extended({flags:0xc0,extensions:{apple_validation_category_01:category,apple_bundle_version_01:'117'}});
 assert.equal(cbor.decodeFirstSync(Buffer.from(assertion,'base64')).authenticatorData.length,101);
 assert.equal(run({assertion}).status,0);
 assert.equal(run({assertion,payload:Buffer.from('changed').toString('base64')}).status,2);
 assert.equal(run({assertion,signCount:1}).status,2);
});
test('binary development category and wrong byte order rejected',()=>{
 for(const category of [Buffer.from([3,0,0,0]),Buffer.from([0,0,0,5]),Buffer.from([5,0,0])])
 assert.equal(run({assertion:extended({flags:0xc0,extensions:{apple_validation_category_01:category,apple_bundle_version_01:'117'}})}).status,2);
});
test('reserved assertion flags rejected',()=>assert.equal(run({assertion:extended({flags:0xe0})}).status,2));
