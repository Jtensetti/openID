import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// A separate namespace: age proofs must never use the long-lived identity key.
protocol AgeKeyStorage {
    func insert(_ data: Data, account: String) throws
    func read(account: String) throws -> Data
    func remove(account: String) throws
}

struct AgeKeychainStorage: AgeKeyStorage {
    let accessGroup: String?
    init(accessGroup: String? = nil) { self.accessGroup = accessGroup }

    private func query(_ account: String) -> [String: Any] {
        var value: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "se.openid.age-keys.v1", kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false]
        if let accessGroup { value[kSecAttrAccessGroup as String] = accessGroup }
        return value
    }
    func insert(_ data: Data, account: String) throws {
        var value = query(account)
        value[kSecValueData as String] = data
        value[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        // SecItemAdd is the cross-process exclusion primitive. Never update an
        // existing claim: a duplicate or any Keychain failure rejects signing.
        guard SecItemAdd(value as CFDictionary, nil) == errSecSuccess else { throw WalletError.keyUnavailable }
    }
    func read(account: String) throws -> Data {
        var value = query(account)
        value[kSecReturnData as String] = true
        value[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(value as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { throw WalletError.keyUnavailable }
        return data
    }
    func remove(account: String) throws {
        let result = SecItemDelete(query(account) as CFDictionary)
        guard result == errSecSuccess || result == errSecItemNotFound else { throw WalletError.keyUnavailable }
    }
}

protocol AgeKeyCryptography {
    func create(context: LAContext) throws -> (wrapped: Data, publicKey: Data)
    func sign(_ data: Data, wrapped: Data, publicKey: Data, context: LAContext) throws -> Data
}

struct AgeSecureEnclave: AgeKeyCryptography {
    func create(context: LAContext) throws -> (wrapped: Data, publicKey: Data) {
        guard SecureEnclave.isAvailable,
              let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                   [.privateKeyUsage, .userPresence], nil) else { throw WalletError.keyUnavailable }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: context)
        return (key.dataRepresentation, key.publicKey.derRepresentation)
    }
    func sign(_ data: Data, wrapped: Data, publicKey: Data, context: LAContext) throws -> Data {
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: wrapped, authenticationContext: context)
        guard key.publicKey.derRepresentation == publicKey else { throw WalletError.keyUnavailable }
        // COSE ES256 uses fixed-width r || s, unlike the identity API's DER signature.
        return try key.signature(for: data).rawRepresentation
    }
}

struct AgeProofKey: Codable, Equatable {
    let id: String
    let publicKey: Data
    let expiresAt: TimeInterval
}

final class AgeProofKeys {
    private struct Record: Codable {
        let key: AgeProofKey
        let wrapped: Data
    }
    private let storage: any AgeKeyStorage
    private let crypto: any AgeKeyCryptography
    private let clock: () -> TimeInterval

    init(storage: any AgeKeyStorage = AgeKeychainStorage(),
         crypto: any AgeKeyCryptography = AgeSecureEnclave(),
         clock: @escaping () -> TimeInterval = { Date().timeIntervalSince1970 }) {
        self.storage = storage; self.crypto = crypto; self.clock = clock
    }

    func create(context: LAContext) throws -> AgeProofKey {
        let generated = try crypto.create(context: context)
        let key = AgeProofKey(id: UUID().uuidString, publicKey: generated.publicKey, expiresAt: clock() + 600)
        try storage.insert(JSONEncoder().encode(Record(key: key, wrapped: generated.wrapped)), account: key.id)
        return key
    }

    private func record(_ key: AgeProofKey) throws -> Record {
        guard UUID(uuidString: key.id) != nil, key.expiresAt.isFinite, key.expiresAt > clock(),
              key.expiresAt <= clock() + 600 else { throw WalletError.rejected }
        let value = try JSONDecoder().decode(Record.self, from: storage.read(account: key.id))
        guard value.key == key else { throw WalletError.rejected }
        return value
    }

    /// Call only after validating the issuer and the complete mdoc request and
    /// showing its OS-provided HTTPS origin. This is key storage, not an mdoc parser.
    func consumeSignature(for key: AgeProofKey, deviceAuthentication: Data, context: LAContext) throws -> Data {
        guard !deviceAuthentication.isEmpty, deviceAuthentication.count <= 96 * 1024 else { throw WalletError.rejected }
        let value = try record(key)
        try storage.insert(Data([1]), account: "spent." + key.id)
        // Burn before any authentication/signing. Crashes, user cancellation and
        // simultaneous app/extension requests must never make the key available again.
        try storage.remove(account: key.id)
        let signature = try crypto.sign(deviceAuthentication, wrapped: value.wrapped, publicKey: key.publicKey, context: context)
        guard key.expiresAt > clock() else { throw WalletError.rejected }
        return signature
    }

    func signIssuance(_ challenge: AgeIssuanceChallenge, for key: AgeProofKey, origin: String,
                      credentialID: String, batch: [AgeProofKey], context: LAContext) throws -> Data {
        guard batch.contains(key) else { throw WalletError.rejected }
        let data = try challenge.validatedBytes(origin: origin, credentialID: credentialID, keys: batch, now: clock())
        let value = try record(key)
        // This key gets only one issuance attempt, even if a response is lost.
        try storage.insert(Data([1]), account: "issuance." + key.id)
        let raw = try crypto.sign(data, wrapped: value.wrapped, publicKey: key.publicKey, context: context)
        guard key.expiresAt > clock() else { throw WalletError.rejected }
        return try P256.Signing.ECDSASignature(rawRepresentation: raw).derRepresentation
    }
}

struct AgeIssuanceChallenge: Decodable {
    let id: String
    let signingInput: String

    func validatedBytes(origin: String, credentialID: String, keys: [AgeProofKey], now: TimeInterval) throws -> Data {
        guard (1...30).contains(keys.count), Set(keys.map(\.publicKey)).count == keys.count,
              keys.allSatisfy({ $0.expiresAt > now }),
              let data = Data(base64Encoded: signingInput), data.count <= 8192,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(["version", "action", "origin", "credentialId", "challengeId", "expiresAt", "publicKeys"]),
              // Decode typed values too: JSON true must not count as version 1.
              let envelope = try? JSONDecoder().decode(Envelope.self, from: data),
              envelope.version == 1, envelope.action == "issue-age-18", envelope.origin == origin,
              envelope.credentialId == credentialID, envelope.challengeId == id,
              id.range(of: "^[a-f0-9]{64}\\z", options: .regularExpression) != nil,
              envelope.expiresAt > now, envelope.expiresAt <= now + 60,
              envelope.publicKeys == keys.map({ $0.publicKey.base64EncodedString() }) else { throw WalletError.rejected }
        return data
    }
    private struct Envelope: Decodable {
        let version: Int
        let action: String
        let origin: String
        let credentialId: String
        let challengeId: String
        let expiresAt: TimeInterval
        let publicKeys: [String]
    }
}
