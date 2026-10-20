// Disposable software test key: verifies CryptoKit DER/SPKI interoperability with the server.
// Never used by the app or for identity proofing. Private material is never printed.
import Foundation
import CryptoKit
let key = P256.Signing.PrivateKey()
let payload = Data("openID interop test: åäö / request-bound approval".utf8)
let signature = try key.signature(for: payload)
let object = ["operation":"verify", "publicKey":key.publicKey.derRepresentation.base64EncodedString(),
              "payload":payload.base64EncodedString(), "signature":signature.derRepresentation.base64EncodedString()]
FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: object))
