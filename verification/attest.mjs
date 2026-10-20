import {verifyAttestation,verifyAssertion} from 'node-app-attest';
import cbor from 'cbor';
import {X509Certificate} from 'node:crypto';
// A private subprocess interface. The caller supplies operator configuration, never HTTP fields.
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
    // Enforce current validity using Node's X.509 parser, without a trust/network override.
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
    if(objects.length!==1 || objects[0].authenticatorData?.length!==37)throw Error('authenticator data');
    result=verifyAssertion({...common,assertion:Buffer.from(request.assertion,'base64'),
      payload:Buffer.from(request.payload,'base64'),publicKey:request.publicKey,signCount:request.signCount});
    if(!Number.isSafeInteger(result.signCount)||result.signCount<=request.signCount)throw Error('counter');
    result={signCount:result.signCount};
  } else throw Error('operation');
  process.stdout.write(JSON.stringify(result));
}catch(_){process.stdout.write('{"error":"ATTESTATION_REJECTED"}');process.exitCode=2;}
