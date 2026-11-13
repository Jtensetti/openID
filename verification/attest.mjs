import {verifyAttestation,verifyAssertion} from 'node-app-attest';
import cbor from 'cbor';
import {X509Certificate} from 'node:crypto';
// App Attest assertions may include signed authenticator extensions on current OS releases.
// The complete authenticatorData is still passed to verifyAssertion; never strip it before verification.
function assertionAuthenticator(data, request) {
  if (!Buffer.isBuffer(data) || data.length < 37 || data.length > 1024 || (data[32] & ~0xc5))
    throw Error('authenticator data');
  // Apple assertions retain AT (0x40) even without attested-credential bytes.
  // ED still determines whether the signed CBOR extension dictionary is present.
  const extended = (data[32] & 0x80) !== 0;
  if (!extended) {
    if (data.length !== 37) throw Error('unflagged extensions');
    return;
  }
  const extensions = cbor.decodeFirstSync(data.subarray(37), {preferMap: true, preventDuplicateKeys: true, max_depth: 4});
  if (!(extensions instanceof Map) || extensions.size !== 2) throw Error('assertion extensions');
  const longNames = extensions.has('apple_validation_category_01');
  const categoryName = longNames ? 'apple_validation_category_01' : 'validationCategory';
  const versionName = longNames ? 'apple_bundle_version_01' : 'bundleVersion';
  if (!extensions.has(categoryName) || !extensions.has(versionName)) throw Error('assertion extension fields');
  // Apple encodes this UInt32 as four little-endian bytes on current devices.
  let category = extensions.get(categoryName);
  if (Buffer.isBuffer(category) && category.length === 4) category = category.readUInt32LE();
  const allowed = request.allowDevelopmentEnvironment === true ? [2,3,4,5] : [2,4,5];
  if (!Number.isInteger(category) || !allowed.includes(category)) throw Error('assertion validation category');
  const version = extensions.get(versionName);
  // This production service accepts the currently distributed build and later builds.
  if (typeof version !== 'string' || !/^[1-9][0-9]{0,8}$/.test(version) || Number(version) < 117)
    throw Error('assertion bundle version');
}
let input='';
for await (const chunk of process.stdin) {
  input+=chunk;
  if(input.length>15000000)process.exit(2);
}
try {
  const request=JSON.parse(input);
  const common={bundleIdentifier:request.bundleIdentifier,teamIdentifier:request.teamIdentifier};
  let result;
  if(request.operation==='attestation') {
    const objects=cbor.decodeAllSync(Buffer.from(request.attestation,'base64'));
    if(objects.length!==1 || objects[0].attStmt?.x5c?.length!==2)throw Error('certificate count');
    // node-app-attest verifies signatures/root binding but omits certificate dates.
    const certificates=objects[0].attStmt.x5c.map(bytes=>new X509Certificate(bytes));
    if(certificates.filter(cert=>cert.ca).length!==1)throw Error('CA constraints');
    for(const cert of certificates) {
      if(Date.now()<Date.parse(cert.validFrom)||Date.now()>Date.parse(cert.validTo))throw Error('certificate validity');
    }
    result=verifyAttestation({...common,attestation:Buffer.from(request.attestation,'base64'),
      challenge:request.challenge,keyId:request.keyId,allowDevelopmentEnvironment:request.allowDevelopmentEnvironment===true});
    result={keyId:result.keyId,publicKey:result.publicKey};
  } else if(request.operation==='assertion') {
    const objects=cbor.decodeAllSync(Buffer.from(request.assertion,'base64'));
    if(objects.length!==1)throw Error('authenticator data');
    assertionAuthenticator(objects[0].authenticatorData, request);
    result=verifyAssertion({...common,assertion:Buffer.from(request.assertion,'base64'),
      payload:Buffer.from(request.payload,'base64'),publicKey:request.publicKey,signCount:request.signCount});
    if(!Number.isSafeInteger(result.signCount)||result.signCount<=request.signCount)throw Error('counter');
    result={signCount:result.signCount};
  } else throw Error('operation');
  process.stdout.write(JSON.stringify(result));
}catch(_){process.stdout.write('{"error":"ATTESTATION_REJECTED"}');process.exitCode=2;}
