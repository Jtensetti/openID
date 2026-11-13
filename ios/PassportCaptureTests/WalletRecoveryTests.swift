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

    func testCancellingStatusReadKeepsTheKeyAndReleasesRegistration() async throws {
        let (model, vault) = try prepared()
        model.refresh()
        XCTAssertTrue(model.isRefreshingStatus)
        XCTAssertTrue(model.canOfferRegistration)
        XCTAssertFalse(model.canResumeRegistration)
        model.cancelStatusRefresh()
        await Task.yield()
        XCTAssertFalse(model.busy)
        XCTAssertTrue(model.canResumeRegistration)
        XCTAssertNil(model.snapshot)
        XCTAssertNotNil(model.statusMessage)
        XCTAssertEqual(model.credential?.id, credential.id)
        XCTAssertTrue(vault.removed.isEmpty)
        XCTAssertEqual(vault.created, 0)
        model.beginRegistration()
        XCTAssertTrue(model.registrationPresented)
        XCTAssertFalse(model.verification.termsAccepted)
        XCTAssertFalse(model.verification.biometricsAccepted)
    }
    func testStatusCancellationPreservesKnownCredentialState() throws {
        for state in [CredentialState.active, .pending, .expired, .revoked] {
            let (model, vault) = try prepared(state: state)
            model.refresh(); model.cancelStatusRefresh()
            XCTAssertEqual(model.credentialState, state)
            XCTAssertFalse(model.canResumeRegistration)
            XCTAssertEqual(model.canForgetCredential, state == .revoked)
            XCTAssertTrue(vault.removed.isEmpty)
            model.lock()
        }
    }
    func testStatusCancelCannotAbandonSignedDecisionsOrRevocation() throws {
        let request = WalletRequest(id: String(repeating: "b", count: 64), relyingParty: "Synthetic",
            purpose: "Test", code: "012345", expiresAt: Date().timeIntervalSince1970 + 120,
            signMessage: "Synthetic text", verification: nil)
        let actions: [(WalletModel) -> Void] = [
            { $0.decide(request, approve: true) }, { $0.decide(request, approve: false) },
            { $0.revoke() }, { $0.setSecurityCode(current: nil, new: "628401") }
        ]
        for action in actions {
            let (model, vault) = try prepared(state: .active)
            action(model)
            XCTAssertTrue(model.busy)
            XCTAssertFalse(model.isRefreshingStatus)
            model.cancelStatusRefresh()
            XCTAssertTrue(model.busy)
            XCTAssertFalse(model.canResumeRegistration)
            XCTAssertTrue(vault.removed.isEmpty)
            model.lock()
        }
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

    func testNewEnvironmentDoesNotReuseLegacyConfigurationOrKeychainNamespace() throws {
        XCTAssertEqual(WalletEnvironment.original.keychainService, "se.openid.wallet.v1")
        XCTAssertNotEqual(WalletEnvironment.original.keychainService, WalletEnvironment.folkidentitet.keychainService)
        XCTAssertNil(try WalletEnvironment.folkidentitet.initialConfiguration(saved: nil))
        XCTAssertEqual(try WalletEnvironment.original.initialConfiguration(saved: nil), .beta)
        XCTAssertThrowsError(try WalletEnvironment.folkidentitet.initialConfiguration(saved: .beta))
        let new = try ServerConfiguration(origin: WalletEnvironment.folkidentitet.suggestedOrigin,
                                          pairing: String(repeating: "x", count: 43))
        XCTAssertEqual(try WalletEnvironment.folkidentitet.initialConfiguration(saved: new), new)
        XCTAssertThrowsError(try ServerConfiguration(origin: WalletEnvironment.folkidentitet.suggestedOrigin, pairing: ""))
    }

    func testEnvironmentSwitchPreservesOldKeyAndClearsUnlockedState() throws {
        let old = RecoveryVault(), new = RecoveryVault()
        try old.save(credential, account: "credential")
        try old.save(ServerConfiguration.beta, account: "configuration")
        try old.save("revocation-proof", account: proofAccount)
        try old.save("consent-receipt", account: receiptAccount)
        let original = old.data
        var selections: [WalletEnvironment] = []
        let model = WalletModel(vault: old, environmentVault: { $0 == .original ? old : new },
                                saveEnvironment: { selections.append($0) })
        model.configureRecoveryPreview(credential: credential, state: .active)
        try model.switchEnvironment(to: .folkidentitet)
        XCTAssertEqual(model.environment, .folkidentitet)
        XCTAssertFalse(model.unlocked)
        XCTAssertNil(model.credential); XCTAssertNil(model.configuration); XCTAssertNil(model.snapshot)
        XCTAssertNil(model.revocationProof); XCTAssertFalse(model.canOfferRegistration)
        XCTAssertEqual(old.data, original); XCTAssertTrue(old.removed.isEmpty)
        XCTAssertTrue(new.data.isEmpty); XCTAssertEqual(new.created, 0)
        try model.switchEnvironment(to: .original)
        XCTAssertEqual(old.data, original)
        XCTAssertEqual(selections, [.folkidentitet, .original])
    }

    func testEnvironmentSwitchCanCancelOnlyStatusRead() throws {
        let old = RecoveryVault(), new = RecoveryVault()
        try old.save(credential, account: "credential")
        let model = WalletModel(vault: old, environmentVault: { $0 == .original ? old : new })
        model.configureRecoveryPreview(credential: credential, state: nil)
        model.refresh()
        XCTAssertTrue(model.isRefreshingStatus)
        try model.switchEnvironment(to: .folkidentitet)
        XCTAssertFalse(model.busy); XCTAssertNil(model.credential)
        XCTAssertNotNil(old.data["credential"]); XCTAssertTrue(old.removed.isEmpty)
    }

    func testEnvironmentSwitchRejectsSignedWriteAndPreservesOriginalStorage() throws {
        let request = WalletRequest(id: String(repeating: "b", count: 64), relyingParty: "Synthetic",
            purpose: "Test", code: "012345", expiresAt: Date().timeIntervalSince1970 + 120,
            signMessage: "Synthetic text", verification: nil)
        let actions: [(WalletModel) -> Void] = [
            { $0.decide(request, approve: true) }, { $0.decide(request, approve: false) },
            { $0.revoke() }, { $0.setSecurityCode(current: nil, new: "628401") }
        ]
        for action in actions {
            let old = RecoveryVault(), new = RecoveryVault()
            try old.save(credential, account: "credential")
            let model = WalletModel(vault: old, environmentVault: { $0 == .original ? old : new })
            model.configureRecoveryPreview(credential: credential, state: .active)
            action(model)
            XCTAssertTrue(model.busy); XCTAssertFalse(model.canSwitchEnvironment)
            XCTAssertThrowsError(try model.switchEnvironment(to: .folkidentitet))
            XCTAssertEqual(model.environment, .original)
            XCTAssertEqual(model.credential?.id, credential.id)
            XCTAssertTrue(old.removed.isEmpty); XCTAssertTrue(new.data.isEmpty)
            model.lock()
        }
    }

    func testNewEnvironmentRejectsAnUnrelatedServerWithoutSavingIt() throws {
        let vault = RecoveryVault()
        let model = WalletModel(vault: vault, environment: .folkidentitet)
        model.configureRecoveryPreview(credential: credential, state: .pending)
        XCTAssertThrowsError(try model.saveConfiguration(origin: ServerConfiguration.betaOrigin, pairing: ""))
        XCTAssertTrue(vault.data.isEmpty)
    }

    func testConsentReceiptsUseTheSameSeparateStorageAsTheirCredentials() throws {
        let old = RecoveryVault(), new = RecoveryVault()
        let notice = EnrollmentNotice(digest: String(repeating: "0", count: 64), noticeJSON: "e30=")
        let original = EnrollmentReceipt(id: String(repeating: "c", count: 64), credentialId: credential.id,
            origin: ServerConfiguration.betaOrigin, notice: notice, state: .submitted)
        let replacement = EnrollmentReceipt(id: String(repeating: "d", count: 64), credentialId: credential.id,
            origin: WalletEnvironment.folkidentitet.suggestedOrigin, notice: notice, state: .submitted)
        let oldStore = EnrollmentReceiptStore(vault: old), newStore = EnrollmentReceiptStore(vault: new)
        try oldStore.save(original)
        XCTAssertTrue(try newStore.read(for: credential.id).isEmpty)
        try newStore.save(replacement)
        XCTAssertEqual(try oldStore.read(for: credential.id).map(\.id), [original.id])
        XCTAssertEqual(try newStore.read(for: credential.id).map(\.id), [replacement.id])
    }

    func testActivePassportCaptureBlocksEnvironmentSwitch() throws {
        let old = RecoveryVault(), new = RecoveryVault()
        let model = WalletModel(vault: old, environmentVault: { $0 == .original ? old : new })
        model.verification.busy = true
        XCTAssertFalse(model.canSwitchEnvironment)
        XCTAssertThrowsError(try model.switchEnvironment(to: .folkidentitet))
        XCTAssertEqual(model.environment, .original)
        XCTAssertTrue(new.data.isEmpty)
        model.verification.busy = false
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
