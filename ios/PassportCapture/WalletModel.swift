import SwiftUI
import LocalAuthentication

@MainActor final class WalletModel: ObservableObject {
    @Published private(set) var configuration: ServerConfiguration?
    @Published private(set) var credential: LocalCredential?
    @Published private(set) var snapshot: WalletSnapshot?
    @Published private(set) var unlocked = false
    @Published private(set) var busy = false
    @Published var error: String?
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

    init() {
        // Keychain access is deferred until explicit local authentication.
    }
    func unlock() {
        guard !busy else { return }
        busy = true; error = nil
        let epoch = generation
        task = Task {
            defer { if generation == epoch { busy = false } }
            do {
                let auth = LAContext(); context = auth
                guard try await auth.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Öppna ditt openID") else { throw WalletError.cancelled }
                try Task.checkCancellation(); guard generation == epoch else { return }
                if let saved = try vault.read("configuration", as: ServerConfiguration.self) {
                    configuration = try ServerConfiguration(origin: saved.origin, pairing: saved.pairing)
                }
                credential = try vault.read("credential", as: LocalCredential.self)
                unlocked = true
            } catch { if generation == epoch { self.error = "Kunde inte låsa upp. Försök igen med Face ID, Touch ID eller din enhetskod." } }
        }
    }
    // An empty first-launch home is safe to show; no account is read or action performed.
    func lock() {
        generation = UUID(); task?.cancel(); context?.invalidate(); context = nil
        operationContext?.invalidate(); operationContext = nil
        verification.cancel(); snapshot = nil; credential = nil; configuration = nil
        focusedRequest = nil; registrationPresented = false; settingsPresented = false
        unlocked = false; busy = false; error = nil
    }
    func saveConfiguration(origin: String, pairing: String) throws {
        guard unlocked, !busy, !verification.busy else { throw WalletError.rejected }
        let value = try ServerConfiguration(origin: origin, pairing: pairing)
        // Existing credentials stay bound to their server; updating its per-process pairing code is allowed.
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
    func refresh() { perform("snapshot") }
    func decide(_ request: WalletRequest, approve: Bool) { perform(approve ? "approve" : "reject", request: request) }
    func revoke() { perform("revoke") }
    private func perform(_ action: String, request: WalletRequest? = nil) {
        guard unlocked, !busy, let configuration, let credential else { return }
        busy = true; error = nil
        let epoch = generation
        task = Task {
            defer { if generation == epoch { busy = false } }
            do {
                let api = WalletAPI(configuration: configuration)
                let challenge = try await api.post("/wallet/challenge", body: ["credentialId": credential.id,
                    "action": action, "requestId": request?.id as Any? ?? NSNull()], as: DeviceChallenge.self)
                let bytes = try challenge.validatedBytes(configuration: configuration, credentialID: credential.id, action: action, request: request)
                try Task.checkCancellation(); guard generation == epoch else { return }
                let auth: LAContext
                if action == "snapshot", let current = context { auth = current }
                else {
                    auth = LAContext()
                    operationContext = auth
                    guard try await auth.evaluatePolicy(.deviceOwnerAuthentication, localizedReason:
                        action == "revoke" ? "Spärra ditt ID permanent" : "Bekräfta ditt val för \(request?.relyingParty ?? "openID")") else { throw WalletError.cancelled }
                }
                defer { if action != "snapshot" { auth.invalidate() } }
                try Task.checkCancellation(); guard generation == epoch else { return }
                let signature = try vault.sign(bytes, credential: credential, context: auth)
                let result = try await api.post("/wallet/execute", body: ["challengeId": challenge.id,
                    "signature": signature.base64EncodedString()], as: WalletSnapshot.self)
                try result.validate(for: credential.id)
                try Task.checkCancellation(); guard generation == epoch else { return }
                snapshot = result; focusedRequest = nil
                if let link = pendingLink {
                    focusedRequest = result.requests.first { $0.id == link }
                    pendingLink = nil
                    if focusedRequest == nil { self.error = "Begäran finns inte eller har gått ut." }
                }
            } catch {
                if generation == epoch {
                    snapshot = nil; focusedRequest = nil
                    self.error = "Status kunde inte hämtas eller åtgärden slutföras. Ingen inloggning bekräftas lokalt. Kontrollera servern och uppdatera."
                }
            }
        }
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
