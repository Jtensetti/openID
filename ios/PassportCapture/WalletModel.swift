import SwiftUI
import LocalAuthentication

@MainActor final class WalletModel: ObservableObject {
    @Published private(set) var configuration: ServerConfiguration?
    @Published private(set) var credential: LocalCredential?
    @Published private(set) var snapshot: WalletSnapshot?
    @Published private(set) var revocationProof: RevocationProof?
    @Published private(set) var unlocked = false
    @Published private(set) var busy = false
    @Published var error: String?
    @Published private(set) var statusMessage: String?
    @Published private(set) var decisionMessage: String?
    @Published var selectedTab = 0
    @Published var focusedRequest: WalletRequest?
    /// Shown beside the code field; a wrong code keeps the request open so the holder can try again.
    @Published private(set) var securityCodeMessage: String?
    @Published var registrationPresented = false
    @Published var settingsPresented = false
    private let vault = SecureVault()
    private var context: LAContext?
    private var operationContext: LAContext?
    private var task: Task<Void, Never>?
    private var activeAction: String?
    private var generation = UUID()
    private var pendingLink: String?
    let verification = VerificationFlow()

    var canRevoke: Bool {
        guard unlocked, credential != nil else { return false }
        if !busy { return true }
        return configuration?.isPublicBeta == true && revocationProof != nil
            && Self.canInterruptForRevocation(activeAction)
    }
    static func canInterruptForRevocation(_ action: String?) -> Bool {
        action == "snapshot" || action == "inspect"
    }

    func unlock() {
        guard !busy else { return }
        busy = true; error = nil; statusMessage = nil; decisionMessage = nil
        let epoch = generation
        task = Task {
            defer {
                if generation == epoch {
                    busy = false
                    if unlocked, credential != nil { refresh() }
                }
            }
            do {
                let auth = LAContext(); context = auth
                guard try await auth.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Öppna ditt openID") else { throw WalletError.cancelled }
                try Task.checkCancellation(); guard generation == epoch else { return }
                let saved = try vault.read("configuration", as: ServerConfiguration.self)
                let selected = ServerConfiguration.initial(saved: saved)
                configuration = try ServerConfiguration(origin: selected.origin, pairing: selected.pairing)
                if saved == nil { try vault.save(selected, account: "configuration") }
                credential = try vault.read("credential", as: LocalCredential.self)
                if selected.isPublicBeta, let credential,
                   let proof = try vault.read("revocation-" + credential.id, as: RevocationProof.self) {
                    try proof.validate(for: credential.id)
                    revocationProof = proof
                }
                unlocked = true
            } catch {
                if generation == epoch, !Self.wasCancelled(error) {
                    self.error = "Kunde inte låsa upp. Försök igen med Face ID, Touch ID eller din enhetskod."
                }
            }
        }
    }
    func lock() {
        generation = UUID(); task?.cancel(); context?.invalidate(); context = nil
        operationContext?.invalidate(); operationContext = nil
        verification.cancel(); snapshot = nil; credential = nil; configuration = nil; revocationProof = nil
        focusedRequest = nil; registrationPresented = false; settingsPresented = false
        unlocked = false; busy = false; activeAction = nil; error = nil; statusMessage = nil; decisionMessage = nil
        securityCodeMessage = nil; pendingLink = nil
    }
    func saveConfiguration(origin: String, pairing: String) throws {
        guard unlocked, !busy, !verification.busy else { throw WalletError.rejected }
        let value = try ServerConfiguration(origin: origin, pairing: pairing)
        // Only the pairing code may change after enrollment.
        if credential != nil, configuration?.origin != value.origin { throw WalletError.rejected }
        try vault.save(value, account: "configuration"); configuration = value; snapshot = nil
    }
    func beginRegistration() {
        guard unlocked, let configuration, !busy else { error = "Lås upp och anslut till din server först."; return }
        guard snapshot == nil else { error = "Det finns redan en registrering. Hantera den innan du börjar om."; return }
        do {
            guard let context else { throw WalletError.keyUnavailable }
            if credential == nil { credential = try vault.createCredential(context: context) }
            guard let credential else { throw WalletError.keyUnavailable }
            verification.prepare(configuration: configuration, credential: credential)
            registrationPresented = true
        } catch { self.error = error.localizedDescription }
    }
    func refresh() {
        if let id = pendingLink { perform("inspect", inspectID: id) }
        else { perform("snapshot") }
    }
    func decide(_ request: WalletRequest, approve: Bool, securityCode: String? = nil) {
        // The code travels only with an approval the service asked to protect with it; rejecting never needs it.
        let code = approve && request.needsSecurityCode ? securityCode : nil
        if approve && request.needsSecurityCode && !(code.map(SecurityCode.valid) ?? false) {
            securityCodeMessage = "Skriv din säkerhetskod med sex siffror."; return
        }
        perform(approve ? (request.isSigning ? "sign" : "approve") : "reject", request: request, extra: code.map { ["pin": $0] } ?? [:])
    }
    /// Choose a code, or change it: the current code is then required and counted like any other attempt.
    func setSecurityCode(current: String?, new: String) {
        guard SecurityCode.valid(new), current.map(SecurityCode.valid) ?? true else { securityCodeMessage = "Koden ska vara sex siffror."; return }
        guard !SecurityCode.weak(new) else { securityCodeMessage = WalletError.securityCode("PIN_WEAK", nil).localizedDescription; return }
        var extra = ["newPin": new]
        if let current { extra["pin"] = current }
        perform("set-pin", extra: extra)
    }
    func clearSecurityCodeMessage() { securityCodeMessage = nil }
    func withdrawEnrollmentConsent(_ receiptID: String) {
        guard unlocked, !busy, !verification.busy, let configuration, let credential else { return }
        busy = true; activeAction = "withdraw-consent"; error = nil; statusMessage = nil
        let epoch = generation
        task = Task {
            defer { if generation == epoch { busy = false; activeAction = nil } }
            do {
                guard var receipt = try EnrollmentReceiptStore().read(for: credential.id).first(where: { $0.id == receiptID }),
                      receipt.origin == configuration.origin else { throw WalletError.rejected }
                let auth = LAContext(); operationContext = auth
                defer { auth.invalidate(); if generation == epoch { operationContext = nil } }
                guard try await auth.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Återkalla ditt biometriska samtycke") else { throw WalletError.cancelled }
                try Task.checkCancellation(); guard generation == epoch else { return }
                let payload = try receipt.withdrawalPayload()
                let signature = try vault.sign(payload, credential: credential, context: auth)
                let result = try await WalletAPI(configuration: configuration).postObject("/native/withdraw", body:
                    ["publicKey":credential.publicKey.base64EncodedString(), "payload":payload.base64EncodedString(), "signature":signature.base64EncodedString()])
                try Task.checkCancellation(); guard generation == epoch else { return }
                guard result["withdrawn"] as? Bool == true, result["receipt"] as? String == receipt.id else { throw WalletError.rejected }
                receipt.state = .withdrawn; try EnrollmentReceiptStore().save(receipt)
                statusMessage = "Återkallelsen är bekräftad."
            } catch {
                if generation == epoch, !Self.wasCancelled(error) {
                    self.error = "Återkallelsen kunde inte bekräftas. Försök igen när servern är tillgänglig. Om felet kvarstår, kontakta den ansvarige i kvittot."
                }
            }
        }
    }
    func revoke() {
        guard configuration?.isPublicBeta == true, let proof = revocationProof else { perform("revoke"); return }
        guard canRevoke, let credential else { return }
        // Only a read-only status request may be cancelled. A pending approval
        // must finish; cancelling its local Task cannot undo a server decision.
        if busy {
            generation = UUID(); task?.cancel(); pendingLink = nil
            focusedRequest = nil
        }
        busy = true; activeAction = "revoke"; error = nil; statusMessage = nil
        let epoch = generation
        task = Task {
            defer { if generation == epoch { busy = false; activeAction = nil } }
            do {
                try proof.validate(for: credential.id)
                let auth = LAContext(); operationContext = auth
                defer { auth.invalidate(); if generation == epoch { operationContext = nil } }
                guard try await auth.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Spärra ditt ID permanent") else { throw WalletError.cancelled }
                try Task.checkCancellation(); guard generation == epoch else { return }
                var request = URLRequest(url: RevocationProof.endpoint)
                request.httpMethod = "POST"; request.timeoutInterval = 20
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
                request.setValue("application/json", forHTTPHeaderField: "Accept")
                request.httpBody = try JSONSerialization.data(withJSONObject: ["credential": credential.id, "token": proof.token, "confirm": true])
                let (_, status) = try await WalletHTTP().send(request, limit: 4096)
                try Task.checkCancellation(); guard generation == epoch else { return }
                guard status == 200 else { throw WalletError.unavailable }
                snapshot = nil; focusedRequest = nil
                statusMessage = "Ditt ID är spärrat permanent. Registrera ett nytt ID om du vill använda openID igen."
            } catch {
                if generation == epoch, !Self.wasCancelled(error) {
                    self.error = "Spärren kunde inte bekräftas. Kontrollera internetanslutningen och försök igen. Att radera appen spärrar inte ditt ID."
                }
            }
        }
    }
    private func perform(_ action: String, request: WalletRequest? = nil, inspectID: String? = nil, extra: [String: String] = [:]) {
        guard unlocked, !busy, let configuration, let credential else { return }
        if let request, request.expired {
            focusedRequest = nil
            error = "QR-koden har gått ut. Starta en ny inloggning på testsidan och skanna den nya koden."
            return
        }
        busy = true; activeAction = action; error = nil; statusMessage = nil; decisionMessage = nil; securityCodeMessage = nil
        let epoch = generation
        task = Task {
            defer {
                if generation == epoch {
                    busy = false; activeAction = nil
                    if pendingLink != nil { refresh() }
                }
            }
            do {
                let api = WalletAPI(configuration: configuration)
                let challenge = try await api.post("/wallet/challenge", body: ["credentialId": credential.id,
                    "action": action, "requestId": (request?.id ?? inspectID) as Any? ?? NSNull()], as: DeviceChallenge.self)
                let bytes = try challenge.validatedBytes(configuration: configuration, credentialID: credential.id, action: action, request: request, inspectID: inspectID)
                try Task.checkCancellation(); guard generation == epoch else { return }
                let auth: LAContext
                if ["snapshot", "inspect"].contains(action), let current = context { auth = current }
                else {
                    auth = LAContext()
                    operationContext = auth
                    guard try await auth.evaluatePolicy(.deviceOwnerAuthentication, localizedReason:
                        action == "revoke" ? "Spärra ditt ID permanent" : action == "set-pin" ? "Spara säkerhetskoden för openID"
                        : action == "sign" ? "Skriv under för \(request?.relyingParty ?? "openID")" : "Bekräfta ditt val för \(request?.relyingParty ?? "openID")") else { throw WalletError.cancelled }
                }
                defer { if !["snapshot", "inspect"].contains(action) { auth.invalidate() } }
                try Task.checkCancellation(); guard generation == epoch else { return }
                let signature = try vault.sign(bytes, credential: credential, context: auth)
                var body: [String: Any] = ["challengeId": challenge.id, "signature": signature.base64EncodedString()]
                for (key, value) in extra { body[key] = value }
                let result = try await api.post("/wallet/execute", body: body, as: WalletSnapshot.self)
                try result.validate(for: credential.id)
                try Task.checkCancellation(); guard generation == epoch else { return }
                if configuration.isPublicBeta, let code = result.revocationCode {
                    let proof = RevocationProof(origin: configuration.origin, code: code)
                    try proof.validate(for: credential.id)
                    try vault.save(proof, account: "revocation-" + credential.id)
                    revocationProof = proof
                }
                // Choosing a code from inside an open request returns to that request.
                snapshot = result; if action != "set-pin" { focusedRequest = nil }
                if action == "approve" { decisionMessage = "Ditt godkännande har skickats. Gå tillbaka till testsidan för att se om inloggningen är klar." }
                if action == "sign" { decisionMessage = "Din underskrift har skickats. Gå tillbaka till tjänsten för att se att dokumentet är underskrivet." }
                if action == "set-pin" { statusMessage = "Din säkerhetskod är sparad. Tjänster kan nu kräva den för stora åtaganden." }
                if action == "reject" { decisionMessage = request?.isSigning == true ? "Du avböjde underskriften. Ingenting har skrivits under." : "Du nekade legitimeringen. Vill du försöka igen, starta en ny inloggning på testsidan." }
                if let link = inspectID {
                    focusedRequest = result.requests.first { $0.id == link }
                    if pendingLink == link { pendingLink = nil }
                    if focusedRequest == nil { self.error = "Begäran är inte längre tillgänglig. Starta en ny inloggning på testsidan och skanna den nya QR-koden." }
                }
            } catch {
                if generation == epoch, let walletError = error as? WalletError, case .securityCode(let code, _) = walletError {
                    // The server counted the attempt and returned how many remain; the request stays open for a retry.
                    securityCodeMessage = error.localizedDescription
                    if code == "PIN_LOCKED" { focusedRequest = nil; self.error = error.localizedDescription; refreshAfterBusy(epoch: epoch) }
                    return
                }
                if generation == epoch {
                    if pendingLink == inspectID { pendingLink = nil }
                    if Self.wasCancelled(error) { return }
                    snapshot = nil; focusedRequest = nil
                    let message = Self.failureMessage(action: action, error: error)
                    if action == "snapshot" { statusMessage = message }
                    else { self.error = message }
                }
            }
        }
    }
    /// A locked code changes the holder's status; fetch it once the failed operation has finished.
    private func refreshAfterBusy(epoch: UUID) {
        Task { [weak self] in
            while self?.generation == epoch && self?.busy == true { try? await Task.sleep(nanoseconds: 50_000_000) }
            guard self?.generation == epoch else { return }
            self?.perform("snapshot")
        }
    }
    static func wasCancelled(_ error: Error) -> Bool {
        if error is CancellationError { return true }
        if let value = error as? LAError { return [.userCancel, .systemCancel, .appCancel].contains(value.code) }
        if let value = error as? WalletError, case .cancelled = value { return true }
        return false
    }
    static func failureMessage(action: String, error: Error) -> String {
        if action == "snapshot" {
            return "Kunde inte hämta aktuell status. Kontrollera internetanslutningen och serverns öppettid. Tryck sedan på Hämta status. En sparad spärrkod kan användas även när testservern är stängd."
        }
        if action == "inspect", let value = error as? WalletError, case .rejected = value {
            return "Begäran kunde inte öppnas. Den kan ha gått ut eller avslutats, eller ditt ID kan vara inaktivt. Hämta status under Mitt ID. Om ditt ID är aktivt, starta en ny inloggning på testsidan."
        }
        if let value = error as? WalletError, case .securityCode = value { return value.localizedDescription }
        if ["approve", "sign", "reject", "revoke", "set-pin"].contains(action) {
            return "Vi kunde inte bekräfta att ditt val registrerades. Hämta status under Mitt ID och kontrollera Aktivitet innan du försöker igen."
        }
        return "Kunde inte nå tjänsten. Kontrollera internetanslutningen och försök sedan igen."
    }
    func open(_ url: URL) {
        guard let id = RequestLink.identifier(url) else { error = "Länken är inte en giltig openID-begäran."; return }
        pendingLink = id; selectedTab = 1
        if unlocked { refresh() }
    }
    func forgetRevokedCredential() throws {
        guard unlocked, !busy, snapshot?.state == .revoked || snapshot?.state == .expired else { throw WalletError.rejected }
        if let credential {
            try vault.remove("revocation-" + credential.id)
            try vault.remove("enrollment-" + credential.id)
        }
        try vault.remove("credential"); credential = nil; snapshot = nil; revocationProof = nil
    }
}
