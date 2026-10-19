import Foundation
import Security
import CryptoKit
import LocalAuthentication

struct SecureVault {
    private let service = "se.openid.wallet.v1"
    private func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: account, kSecAttrSynchronizable as String: false]
    }
    func read<T: Decodable>(_ account: String, as type: T.Type) throws -> T? {
        var q = query(account); q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let bytes = result as? Data else { throw WalletError.keyUnavailable }
        return try JSONDecoder().decode(type, from: bytes)
    }
    func save<T: Encodable>(_ value: T, account: String) throws {
        let data = try JSONEncoder().encode(value)
        var update: [String: Any] = [kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly]
        let status = SecItemUpdate(query(account) as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            update.merge(query(account), uniquingKeysWith: { _, new in new })
            guard SecItemAdd(update as CFDictionary, nil) == errSecSuccess else { throw WalletError.keyUnavailable }
        } else if status != errSecSuccess { throw WalletError.keyUnavailable }
    }
    func remove(_ account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw WalletError.keyUnavailable }
    }
    func createCredential(context: LAContext) throws -> LocalCredential {
        guard SecureEnclave.isAvailable,
              let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                    [.privateKeyUsage, .userPresence], nil) else { throw WalletError.keyUnavailable }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: context)
        let publicKey = key.publicKey.derRepresentation
        let id = SHA256.hash(data: publicKey).map { String(format: "%02x", $0) }.joined()
        let credential = LocalCredential(id: id, wrappedKey: key.dataRepresentation, publicKey: publicKey)
        // This is a device-bound opaque key blob, not an exported raw private key.
        try save(credential, account: "credential")
        return credential
    }
    func sign(_ bytes: Data, credential: LocalCredential, context: LAContext) throws -> Data {
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: credential.wrappedKey, authenticationContext: context)
        guard key.publicKey.derRepresentation == credential.publicKey else { throw WalletError.keyUnavailable }
        return try key.signature(for: bytes).derRepresentation
    }
}
