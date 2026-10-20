// CryptoKit DER/SPKI interoperability test with a temporary software key.
import Foundation
import CryptoKit
let key = P256.Signing.PrivateKey()
let payload = Data("openID interop test: åäö / request-bound approval".utf8)
let signature = try key.signature(for: payload)
let object = ["operation":"verify", "publicKey":key.publicKey.derRepresentation.base64EncodedString(),
              "payload":payload.base64EncodedString(), "signature":signature.derRepresentation.base64EncodedString()]
FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: object))
