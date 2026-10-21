import SwiftUI
import LocalAuthentication

@MainActor final class WalletModel: ObservableObject {
    @Published private(set) var configuration: ServerConfiguration?
    @Published private(set) var credential: LocalCredential?
    @Published private(set) var snapshot: WalletSnapshot?
    @Published private(set) var unlocked = false
    @Published private(set) var busy = false
    @Published var error: String?
    @Published private(set) var statusMessage: String?
    @Published private(set) var decisionMessage: String?
    @Published var selectedTab = 0
    @Published var focusedRequest: WalletRequest?
    @Published var registrationPresented = false
    @Published var settingsPresented = false
    private let vault = SecureVault()
    private var context: LAContext?
    private var operationContext: LAContext?
    private var task: Task<Void, Never>?
    private var generation = UUID()
    private var pendingLink: String?
    let verification = VerificationFlow()

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
                if let saved = try vault.read("configuration", as: ServerConfiguration.self) {
                    configuration = try ServerConfiguration(origin: saved.origin, pairing: saved.pairing)
                }
                credential = try vault.read("credential", as: LocalCredential.self)
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
        verification.cancel(); snapshot = nil; credential = nil; configuration = nil
        focusedRequest = nil; registrationPresented = false; settingsPresented = false
        unlocked = false; busy = false; error = nil; statusMessage = nil; decisionMessage = nil
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
    func decide(_ request: WalletRequest, approve: Bool) { perform(approve ? "approve" : "reject", request: request) }
    func revoke() { perform("revoke") }
    private func perform(_ action: String, request: WalletRequest? = nil, inspectID: String? = nil) {
        guard unlocked, !busy, let configuration, let credential else { return }
        if let request, request.expired {
            focusedRequest = nil
            error = "QR-koden har gått ut. Starta en ny inloggning på testsidan och skanna den nya koden."
            return
        }
        busy = true; error = nil; statusMessage = nil; decisionMessage = nil
        let epoch = generation
        task = Task {
            defer {
                if generation == epoch {
                    busy = false
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
                        action == "revoke" ? "Spärra ditt ID permanent" : "Bekräfta ditt val för \(request?.relyingParty ?? "openID")") else { throw WalletError.cancelled }
                }
                defer { if !["snapshot", "inspect"].contains(action) { auth.invalidate() } }
                try Task.checkCancellation(); guard generation == epoch else { return }
                let signature = try vault.sign(bytes, credential: credential, context: auth)
                let result = try await api.post("/wallet/execute", body: ["challengeId": challenge.id,
                    "signature": signature.base64EncodedString()], as: WalletSnapshot.self)
                try result.validate(for: credential.id)
                try Task.checkCancellation(); guard generation == epoch else { return }
                snapshot = result; focusedRequest = nil
                if action == "approve" { decisionMessage = "Ditt godkännande har skickats. Gå tillbaka till testsidan för att se om inloggningen är klar." }
                if action == "reject" { decisionMessage = "Du nekade legitimeringen. Vill du försöka igen, starta en ny inloggning på testsidan." }
                if let link = inspectID {
                    focusedRequest = result.requests.first { $0.id == link }
                    if pendingLink == link { pendingLink = nil }
                    if focusedRequest == nil { self.error = "Begäran är inte längre tillgänglig. Starta en ny inloggning på testsidan och skanna den nya QR-koden." }
                }
            } catch {
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
    static func wasCancelled(_ error: Error) -> Bool {
        if error is CancellationError { return true }
        if let value = error as? LAError { return [.userCancel, .systemCancel, .appCancel].contains(value.code) }
        if let value = error as? WalletError, case .cancelled = value { return true }
        return false
    }
    static func failureMessage(action: String, error: Error) -> String {
        if action == "snapshot" {
            return "Kunde inte hämta aktuell status. Kontrollera internet och att WireGuard är anslutet. Tryck sedan på Hämta status."
        }
        if action == "inspect", let value = error as? WalletError, case .rejected = value {
            return "Begäran kunde inte öppnas. Den kan ha gått ut eller avslutats, eller ditt ID kan vara inaktivt. Hämta status under Mitt ID. Om ditt ID är aktivt, starta en ny inloggning på testsidan."
        }
        if ["approve", "reject", "revoke"].contains(action) {
            return "Vi kunde inte bekräfta att ditt val registrerades. Hämta status under Mitt ID och kontrollera Aktivitet innan du försöker igen."
        }
        return "Kunde inte nå tjänsten. Kontrollera internet och WireGuard och försök sedan igen."
    }
    func open(_ url: URL) {
        guard let id = RequestLink.identifier(url) else { error = "Länken är inte en giltig openID-begäran."; return }
        pendingLink = id; selectedTab = 1
        if unlocked { refresh() }
    }
    func forgetRevokedCredential() throws {
        guard unlocked, !busy, snapshot?.state == .revoked || snapshot?.state == .expired else { throw WalletError.rejected }
        try vault.remove("credential"); credential = nil; snapshot = nil
    }
}
