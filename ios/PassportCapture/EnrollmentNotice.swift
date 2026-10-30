import Foundation
import CryptoKit

struct EnrollmentText: Codable, Equatable {
    let version: String
    let controller: String
    let contact: String
    let locale: String
    let notBefore: Int64
    let notAfter: Int64
    let terms: String
    let privacy: String
    let biometrics: String
    let withdrawal: String
}

/// Display the exact server bytes whose digest is bound into the App Attest assertion.
struct EnrollmentNotice: Codable, Equatable {
    let digest: String
    let noticeJSON: String

    func text(at now: Date? = nil) throws -> EnrollmentText {
        guard digest.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              noticeJSON.count <= 87384, let bytes = Data(base64Encoded: noticeJSON),
              !bytes.isEmpty, bytes.count <= 65536,
              SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == digest else { throw WalletError.rejected }
        let value = try JSONDecoder().decode(EnrollmentText.self, from: bytes)
        guard value.locale == "sv-SE", value.version.range(of: "^[A-Za-z0-9][A-Za-z0-9_.-]{7,95}$", options: .regularExpression) != nil,
              value.notBefore >= 0, value.notBefore < value.notAfter, value.notAfter <= 253402300799,
              [value.controller, value.contact].allSatisfy({ Self.visible($0, limit: 1024) }),
              [value.terms, value.privacy, value.biometrics, value.withdrawal].allSatisfy({ Self.visible($0, limit: 16384) }) else { throw WalletError.rejected }
        if let now {
            guard Double(value.notBefore) <= now.timeIntervalSince1970,
                  now.timeIntervalSince1970 < Double(value.notAfter) else { throw WalletError.rejected }
        }
        return value
    }

    private static func visible(_ value: String, limit: Int) -> Bool {
        !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && value.utf8.count <= limit &&
        !value.unicodeScalars.contains { scalar in
            let n = scalar.value
            return (n < 32 && n != 10 && n != 9) || (127...159).contains(n) ||
                [0x2028,0x2029,0x202a,0x202b,0x202c,0x202d,0x202e,0x2066,0x2067,0x2068,0x2069,0xfeff].contains(n)
        }
    }

    func acceptance(terms: Bool, biometrics: Bool, at now: Date = Date()) throws -> [String: Any] {
        _ = try text(at: now)
        guard terms && biometrics else { throw WalletError.rejected }
        return ["policyDigest": digest, "termsAccepted": true, "biometricsAccepted": true]
    }
}

struct EnrollmentReceipt: Codable, Identifiable, Equatable {
    enum State: String, Codable { case submitted, recorded, withdrawn }
    let id: String
    let credentialId: String
    let origin: String
    let notice: EnrollmentNotice
    var state: State

    func withdrawalPayload() throws -> Data {
        guard id.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else { throw WalletError.rejected }
        return try JSONSerialization.data(withJSONObject: ["action":"withdraw-enrollment-consent", "origin":origin, "receipt":id], options: [.sortedKeys])
    }
}

struct EnrollmentReceiptStore {
    private let vault = SecureVault()
    func read(for credentialId: String) throws -> [EnrollmentReceipt] {
        let values = try vault.read("enrollment-" + credentialId, as: [EnrollmentReceipt].self) ?? []
        guard values.count <= 32, values.allSatisfy({ $0.credentialId == credentialId }) else { throw WalletError.rejected }
        return values
    }
    func save(_ receipt: EnrollmentReceipt) throws {
        var values = try read(for: receipt.credentialId)
        if let index = values.firstIndex(where: { $0.id == receipt.id }) { values[index] = receipt }
        else {
            guard values.count < 32 else { throw WalletError.rejected }
            values.append(receipt)
        }
        try vault.save(values, account: "enrollment-" + receipt.credentialId)
    }
}
