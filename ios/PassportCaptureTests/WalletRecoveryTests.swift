import XCTest
import LocalAuthentication
@testable import PassportCapture

@MainActor final class WalletRecoveryTests: XCTestCase {
    private let credential = LocalCredential(id: String(repeating: "a", count: 64), wrappedKey: Data([1]), publicKey: Data([2]))
    private let proofAccount = "revocation-" + String(repeating: "a", count: 64)
    private let receiptAccount = "enrollment-" + String(repeating: "a", count: 64)

    private func prepared(state: CredentialState? = nil, confirmed: Bool = false) throws -> (WalletModel, RecoveryVault) {
        let vault = RecoveryVault()
        try vault.save(credential, account: "credential")
        try vault.save("synthetic-revocation-proof", account: proofAccount)
        try vault.save("synthetic-enrollment-receipt", account: receiptAccount)
        let model = WalletModel(vault: vault)
        model.configureRecoveryPreview(credential: credential, state: state,
            statusError: state == nil ? URLError(.timedOut) : nil, confirmedRevocation: confirmed)
        return (model, vault)
    }

    func testStatusFailureAndRelaunchDoNotTrapAnUnfinishedRegistration() throws {
        let (model, vault) = try prepared()
        XCTAssertNotNil(model.statusMessage)
        XCTAssertTrue(model.canResumeRegistration)
        model.beginRegistration()
        XCTAssertTrue(model.registrationPresented)
        XCTAssertEqual(model.credential?.id, credential.id)
        XCTAssertEqual(vault.created, 0, "Retry must keep the original key")
        XCTAssertNil(model.statusMessage)
        model.lock()
        model.configureRecoveryPreview(credential: try vault.read("credential", as: LocalCredential.self), statusError: URLError(.notConnectedToInternet))
        model.beginRegistration()
        XCTAssertTrue(model.registrationPresented)
        XCTAssertEqual(model.credential?.id, credential.id)
        XCTAssertEqual(vault.created, 0)
    }

    func testOnlyConfirmedRevocationAllowsKeyRemoval() throws {
        for state in [nil, .pending, .active, .expired] as [CredentialState?] {
            let (model, vault) = try prepared(state: state)
            XCTAssertFalse(model.canForgetCredential)
            XCTAssertThrowsError(try model.forgetRevokedCredential())
            XCTAssertNotNil(vault.data["credential"])
            XCTAssertNotNil(vault.data[proofAccount])
            XCTAssertTrue(vault.removed.isEmpty)
            if state != nil {
                model.beginRegistration()
                XCTAssertFalse(model.registrationPresented)
                XCTAssertEqual(vault.created, 0)
            }
        }
    }

    func testFailedKeyDeletionPreservesKeyAndRevocationProof() throws {
        let (model, vault) = try prepared(state: .revoked)
        vault.failRemoval = "credential"
        XCTAssertThrowsError(try model.forgetRevokedCredential())
        XCTAssertEqual(model.credential?.id, credential.id)
        XCTAssertNotNil(vault.data[proofAccount])
        XCTAssertNotNil(vault.data["credential"])
        XCTAssertNotNil(vault.data[receiptAccount])
        XCTAssertTrue(model.canForgetCredential)
        XCTAssertFalse(model.canResumeRegistration)
    }

    func testRevokedKeyRemovalAllowsNewKeyEvenIfOldProofCleanupFails() throws {
        let (model, vault) = try prepared(state: .revoked)
        vault.failRemoval = proofAccount
        model.selectedTab = 3
        try model.forgetRevokedCredential()
        XCTAssertNil(model.credential)
        XCTAssertNil(vault.data["credential"])
        XCTAssertNil(vault.data[receiptAccount])
        XCTAssertNil(model.snapshot)
        XCTAssertNil(model.statusMessage)
        XCTAssertEqual(model.selectedTab, 0)
        XCTAssertTrue(model.canResumeRegistration)
        model.beginRegistration()
        XCTAssertEqual(vault.created, 1)
        XCTAssertNotEqual(model.credential?.id, credential.id)
        XCTAssertTrue(model.registrationPresented)
    }

    func testSeparateRevocationConfirmationCanBeFollowedByRemovalWithoutStatusServer() throws {
        let (model, vault) = try prepared(confirmed: true)
        XCTAssertTrue(model.canForgetCredential)
        XCTAssertFalse(model.canRevoke)
        XCTAssertFalse(model.canResumeRegistration)
        model.beginRegistration()
        XCTAssertFalse(model.registrationPresented)
        // No signed snapshot request may replace a confirmed permanent revocation.
        model.refresh()
        XCTAssertFalse(model.busy)
        try model.forgetRevokedCredential()
        XCTAssertNil(model.confirmedRevocationID)
        XCTAssertEqual(vault.removed, ["credential", proofAccount, receiptAccount])
        model.beginRegistration()
        XCTAssertTrue(model.registrationPresented)
        XCTAssertEqual(vault.created, 1)
    }

    func testLockedAppCannotRemoveOrResume() throws {
        let (model, vault) = try prepared(state: .revoked)
        model.lock()
        XCTAssertFalse(model.canResumeRegistration)
        XCTAssertThrowsError(try model.forgetRevokedCredential())
        model.beginRegistration()
        XCTAssertFalse(model.registrationPresented)
        XCTAssertNotNil(vault.data["credential"])
    }
}

private final class RecoveryVault: CredentialVault {
    var data: [String: Data] = [:]
    var removed: [String] = []
    var failRemoval: String?
    var created = 0
    func read<T: Decodable>(_ account: String, as type: T.Type) throws -> T? {
        try data[account].map { try JSONDecoder().decode(type, from: $0) }
    }
    func save<T: Encodable>(_ value: T, account: String) throws { data[account] = try JSONEncoder().encode(value) }
    func remove(_ account: String) throws {
        if failRemoval == account { throw WalletError.keyUnavailable }
        removed.append(account); data.removeValue(forKey: account)
    }
    func createCredential(context: LAContext) throws -> LocalCredential {
        created += 1
        let credential = LocalCredential(id: String(repeating: "b", count: 64), wrappedKey: Data([3]), publicKey: Data([4]))
        try save(credential, account: "credential")
        return credential
    }
    func sign(_ bytes: Data, credential: LocalCredential, context: LAContext) throws -> Data { throw WalletError.keyUnavailable }
}
