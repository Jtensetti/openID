import CryptoKit
import Foundation
import LocalAuthentication
import XCTest
@testable import PassportCapture

private final class AgeMemoryStorage: AgeKeyStorage {
    private let lock = NSLock()
    private var values: [String: Data] = [:]
    var rejectRemove = false
    func insert(_ data: Data, account: String) throws {
        lock.lock(); defer { lock.unlock() }
        guard values[account] == nil else { throw WalletError.keyUnavailable }
        values[account] = data
    }
    func read(account: String) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        guard let data = values[account] else { throw WalletError.keyUnavailable }
        return data
    }
    func remove(account: String) throws {
        lock.lock(); defer { lock.unlock() }
        guard !rejectRemove else { throw WalletError.keyUnavailable }
        values.removeValue(forKey: account)
    }
}

/// Real CryptoKit signatures with software keys; not Secure Enclave evidence.
private final class AgeSoftwareKeys: AgeKeyCryptography {
    var rejectSign = false
    func create(context: LAContext) throws -> (wrapped: Data, publicKey: Data) {
        let key = P256.Signing.PrivateKey()
        return (key.rawRepresentation, key.publicKey.derRepresentation)
    }
    func sign(_ data: Data, wrapped: Data, publicKey: Data, context: LAContext) throws -> Data {
        guard !rejectSign else { throw WalletError.cancelled }
        let key = try P256.Signing.PrivateKey(rawRepresentation: wrapped)
        guard key.publicKey.derRepresentation == publicKey else { throw WalletError.keyUnavailable }
        return try key.signature(for: data).rawRepresentation
    }
}

final class AgeProofKeysTests: XCTestCase {
    private let bytes = Data("synthetic-device-authentication".utf8)

    func testFreshKeyAndCOSESignatureConsumedAcrossInstances() throws {
        let storage = AgeMemoryStorage(), crypto = AgeSoftwareKeys()
        let first = AgeProofKeys(storage: storage, crypto: crypto, clock: { 1000 })
        let second = AgeProofKeys(storage: storage, crypto: crypto, clock: { 1000 })
        let key = try first.create(context: LAContext())
        XCTAssertNotEqual(key.publicKey, try first.create(context: LAContext()).publicKey)
        let signature = try second.consumeSignature(for: key, deviceAuthentication: bytes, context: LAContext())
        XCTAssertEqual(64, signature.count)
        XCTAssertTrue(try P256.Signing.PublicKey(derRepresentation: key.publicKey)
            .isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: signature), for: bytes))
        XCTAssertThrowsError(try first.consumeSignature(for: key, deviceAuthentication: bytes, context: LAContext()))
    }

    func testCancellationAndStorageFailureBurnBeforeSigning() throws {
        for deletionFailure in [false, true] {
            let storage = AgeMemoryStorage(), crypto = AgeSoftwareKeys()
            let vault = AgeProofKeys(storage: storage, crypto: crypto, clock: { 1000 })
            let key = try vault.create(context: LAContext())
            storage.rejectRemove = deletionFailure; crypto.rejectSign = !deletionFailure
            XCTAssertThrowsError(try vault.consumeSignature(for: key, deviceAuthentication: bytes, context: LAContext()))
            storage.rejectRemove = false; crypto.rejectSign = false
            XCTAssertThrowsError(try vault.consumeSignature(for: key, deviceAuthentication: bytes, context: LAContext()))
        }
    }

    func testParallelConsumersSignOnce() throws {
        let storage = AgeMemoryStorage(), crypto = AgeSoftwareKeys()
        let vaults = (0..<4).map { _ in AgeProofKeys(storage: storage, crypto: crypto, clock: { 1000 }) }
        let key = try vaults[0].create(context: LAContext())
        let lock = NSLock()
        var successes = 0
        DispatchQueue.concurrentPerform(iterations: 16) { index in
            if (try? vaults[index % 4].consumeSignature(for: key, deviceAuthentication: self.bytes, context: LAContext())) != nil {
                lock.lock(); successes += 1; lock.unlock()
            }
        }
        XCTAssertEqual(1, successes)
    }

    func testExpiryAndKeySubstitution() throws {
        var now: TimeInterval = 1000
        let vault = AgeProofKeys(storage: AgeMemoryStorage(), crypto: AgeSoftwareKeys(), clock: { now })
        let key = try vault.create(context: LAContext())
        let changed = AgeProofKey(id: key.id, publicKey: Data([1]), expiresAt: key.expiresAt)
        XCTAssertThrowsError(try vault.consumeSignature(for: changed, deviceAuthentication: bytes, context: LAContext()))
        now = 1600
        XCTAssertThrowsError(try vault.consumeSignature(for: key, deviceAuthentication: bytes, context: LAContext()))
    }

    private func challenge(_ keys: [AgeProofKey], changes: [String: Any] = [:]) throws -> AgeIssuanceChallenge {
        var value: [String: Any] = ["version": 1, "action": "issue-age-18", "origin": "https://issuer.example",
            "credentialId": String(repeating: "a", count: 64), "challengeId": String(repeating: "b", count: 64),
            "expiresAt": 1060, "publicKeys": keys.map({ $0.publicKey.base64EncodedString() })]
        value.merge(changes, uniquingKeysWith: { _, new in new })
        return AgeIssuanceChallenge(id: String(repeating: "b", count: 64),
            signingInput: try JSONSerialization.data(withJSONObject: value).base64EncodedString())
    }

    func testIssuanceBindsWholeBatchAndSignsOnlyOnce() throws {
        let vault = AgeProofKeys(storage: AgeMemoryStorage(), crypto: AgeSoftwareKeys(), clock: { 1000 })
        let keys = try (0..<2).map { _ in try vault.create(context: LAContext()) }
        let request = try challenge(keys)
        let signature = try vault.signIssuance(request, for: keys[0], origin: "https://issuer.example",
            credentialID: String(repeating: "a", count: 64), batch: keys, context: LAContext())
        XCTAssertTrue(try P256.Signing.PublicKey(derRepresentation: keys[0].publicKey).isValidSignature(
            P256.Signing.ECDSASignature(derRepresentation: signature), for: Data(base64Encoded: request.signingInput)!))
        XCTAssertThrowsError(try vault.signIssuance(request, for: keys[0], origin: "https://issuer.example",
            credentialID: String(repeating: "a", count: 64), batch: keys, context: LAContext()))
    }

    func testChangedConsentNeverReachesKeyOperation() throws {
        let vault = AgeProofKeys(storage: AgeMemoryStorage(), crypto: AgeSoftwareKeys(), clock: { 1000 })
        let keys = [try vault.create(context: LAContext())]
        let mutations: [[String: Any]] = [["origin": "https://other.example"], ["credentialId": "other"],
            ["action": "approve"], ["challengeId": "other"], ["expiresAt": 1000], ["expiresAt": 1061],
            ["publicKeys": []], ["version": true], ["birthDate": "900101"]]
        for change in mutations {
            XCTAssertThrowsError(try vault.signIssuance(challenge(keys, changes: change), for: keys[0],
                origin: "https://issuer.example", credentialID: String(repeating: "a", count: 64), batch: keys, context: LAContext()))
        }
        XCTAssertNoThrow(try vault.signIssuance(challenge(keys), for: keys[0], origin: "https://issuer.example",
            credentialID: String(repeating: "a", count: 64), batch: keys, context: LAContext()))
    }
}
