import Foundation
import CryptoKit
import DeviceCheck
import NFCPassportReader

@MainActor final class VerificationFlow: ObservableObject {
    private var configuration: ServerConfiguration?
    private var credential: LocalCredential?
    @Published var phase = 0
    @Published var completed = false
    @Published var failed = false
    @Published var stepTitle = "Passuppgifter"
    @Published var passportRead = false
    @Published private(set) var notice: EnrollmentNotice?
    @Published private(set) var noticeText: EnrollmentText?
    @Published private(set) var loadingNotice = false
    @Published var termsAccepted = false
    @Published var biometricsAccepted = false
    private var noticeGeneration = UUID()
    var canStart: Bool { (try? PassportAccessKey.encode(documentNumber: documentNumber, birth: birth, expiry: expiry)) != nil }

    func retry() { failed = false; phase = 0; passportRead = false; status = ""; stepTitle = "Passuppgifter"; termsAccepted = false; biometricsAccepted = false }
    @Published var documentNumber = ""
    @Published var birth = ""
    @Published var expiry = ""
    @Published var status = ""
    @Published var busy = false
    @Published var cameraVisible = false
    @Published private(set) var readyForCamera = false
    private var cameraStart: CheckedContinuation<Void, Error>?
    let camera = CaptureCamera()
    private var task: Task<Void, Never>?
    private var reader: PassportReader?
    private let chipRelay = PassportChipRelay()

    func prepare(configuration: ServerConfiguration, credential: LocalCredential) {
        self.configuration = configuration; self.credential = credential
        noticeGeneration = UUID(); notice = nil; noticeText = nil; loadingNotice = false; termsAccepted = false; biometricsAccepted = false
        phase = 0; completed = false; failed = false; passportRead = false; stepTitle = "Passuppgifter"; status = ""
    }

    func loadNotice() async {
        guard !busy, !loadingNotice, let configuration else { return }
        let epoch = noticeGeneration
        loadingNotice = true; notice = nil; noticeText = nil; termsAccepted = false; biometricsAccepted = false
        defer { if noticeGeneration == epoch { loadingNotice = false } }
        do {
            let value = try await WalletAPI(configuration: configuration).post("/native/notice", body: [:], as: EnrollmentNotice.self)
            try Task.checkCancellation()
            let text = try value.text(at: Date())
            guard noticeGeneration == epoch else { return }
            notice = value; noticeText = text; status = ""
        } catch {
            guard noticeGeneration == epoch else { return }
            status = (error as? WalletError)?.localizedDescription ?? "Informationen inför registrering kunde inte hämtas. Försök igen innan du lämnar passuppgifter."
        }
    }

    #if DEBUG && targetEnvironment(simulator)
    func setPreviewNotice(_ value: EnrollmentNotice) throws {
        noticeText = try value.text(at: Date()); notice = value
    }
    #endif

    func start() {
        guard !busy else { return }
        guard let notice, let acceptance = try? notice.acceptance(terms: termsAccepted, biometrics: biometricsAccepted) else {
            status = "Läs den aktuella informationen och gör båda valen innan du fortsätter."; return
        }
        busy = true; failed = false; passportRead = false
        task = Task {
            defer { busy = false; cameraVisible = false; readyForCamera = false; camera.stop(); reader = nil; clearDocument(); failed = !completed && !Task.isCancelled }
            do {
                guard let configuration, let credential else { throw FlowError.rejected }
                let api = WalletAPI(configuration: configuration)
                var activeChip: [String: Any]?
                defer {
                    if let activeChip { Task { _ = try? await api.postObject("/native/cancel", body: activeChip) } }
                }
                phase = 1
                let key = try PassportAccessKey.encode(documentNumber: documentNumber, birth: birth, expiry: expiry)
                let service = DCAppAttestService.shared
                guard service.isSupported else { throw FlowError.rejected }
                stepTitle = "Ansluter säkert"
                status = "Kontrollerar anslutningen och appen."
                let start = try await api.postObject("/native/start", body: [:])
                try Task.checkCancellation()
                guard let id = start["id"] as? String, let challenge = start["challenge"] as? String else { throw FlowError.rejected }
                let keyID = try await service.generateKey()
                try Task.checkCancellation()
                let attestation = try await service.attestKey(keyID, clientDataHash: Data(SHA256.hash(data: Data(challenge.utf8))))
                try Task.checkCancellation()
                let registered = try await api.postObject("/native/attest", body: ["id": id, "keyId": keyID, "attestation": attestation.base64EncodedString()])
                guard let initialNonce = registered["nonce"] as? String else { throw FlowError.rejected }
                let receiptID = (UUID().uuidString + UUID().uuidString).replacingOccurrences(of: "-", with: "").lowercased()
                let choice: [String: Any] = ["id": id, "nonce": initialNonce, "receipt": receiptID,
                    "devicePublicKey": credential.publicKey.base64EncodedString(), "acceptance": acceptance]
                let choiceBytes = try JSONSerialization.data(withJSONObject: choice, options: [.sortedKeys])
                let choiceAssertion = try await service.generateAssertion(keyID, clientDataHash: Data(SHA256.hash(data: choiceBytes)))
                try Task.checkCancellation()
                // Persist the reference BEFORE transmission so an uncertain reply
                // does not lose the holder's ability to request withdrawal.
                var receipt = EnrollmentReceipt(id: receiptID, credentialId: credential.id,
                    origin: configuration.origin, notice: notice, state: .submitted)
                try EnrollmentReceiptStore().save(receipt)
                let accepted = try await api.postObject("/native/consent", body: ["id":id,
                    "payload":choiceBytes.base64EncodedString(), "assertion":choiceAssertion.base64EncodedString()])
                guard accepted["id"] as? String == id, accepted["receipt"] as? String == receiptID,
                      let nonce = accepted["nonce"] as? String else { throw FlowError.rejected }
                receipt.state = .recorded; try EnrollmentReceiptStore().save(receipt)
                try Task.checkCancellation()
                stepTitle = "Läser passets chip"
                status = "Lägg passet plant och håll telefonens överkant stilla mot passet tills läsningen är klar."
                let passportReader = PassportReader(); reader = passportReader
                let passport = try await passportReader.readPassport(mrzKey: key, tags: [.DG1, .DG2, .DG14, .SOD], skipCA: true, skipPACE: false, customDisplayMessage: { message in
                    switch message {
                    case .requestPresentPassport: return "Håll telefonens överkant mot passet."
                    case .authenticatingWithPassport: return "Passet hittat. Håll telefonen stilla medan chipet öppnas."
                    case .readingDataGroupProgress(_, let progress): return "Läser passet: \(progress) % av aktuell del. Håll kvar telefonen."
                    case .successfulRead: return "Passet är läst. Nästa steg är serverns säkerhetskontroll."
                    case .error: return "Kontakten med passet misslyckades. Håll telefonen stilla och försök igen."
                    case .activeAuthentication: return "Kontrollerar chipet. Håll kvar telefonen."
                    }
                })
                try Task.checkCancellation()
                passportRead = true
                clearDocument()
                guard let sod = passport.dataGroupsRead[.SOD]?.data,
                      let dg1 = passport.dataGroupsRead[.DG1]?.data,
                      let dg2 = passport.dataGroupsRead[.DG2]?.data,
                      let dg14 = passport.dataGroupsRead[.DG14]?.data else { throw FlowError.rejected }
                let document: [String: Any] = ["id": id, "nonce": nonce, "sod": Data(sod).base64EncodedString(),
                    "dg1": Data(dg1).base64EncodedString(), "dg2": Data(dg2).base64EncodedString(),
                    "dg14": Data(dg14).base64EncodedString(), "devicePublicKey": credential.publicKey.base64EncodedString()]
                let documentBytes = try JSONSerialization.data(withJSONObject: document, options: [.sortedKeys])
                let documentAssertion = try await service.generateAssertion(keyID, clientDataHash: Data(SHA256.hash(data: documentBytes)))
                try Task.checkCancellation()
                stepTitle = "Kontrollerar passets äkthet"
                status = "Passet är läst. Servern kontrollerar signaturen och uppgifterna innan nästa chipläsning."
                let chipStart = try await api.postObject("/native/chip/start", body: ["id": id,
                    "payload": documentBytes.base64EncodedString(), "assertion": documentAssertion.base64EncodedString()])
                guard let chipToken = chipStart["chipToken"] as? String else { throw FlowError.rejected }
                activeChip = ["id": id, "chipToken": chipToken]
                try Task.checkCancellation()
                stepTitle = "Säkerhetskontroll av chipet"
                status = "Första läsningen är klar. Håll telefonen mot samma pass igen. Behåll kontakten tills säkerhetskontrollen är klar."
                let chipResult = try await chipRelay.authenticate(api: api, initial: chipStart)
                try Task.checkCancellation()
                guard let captureNonce = chipResult["nonce"] as? String,
                      let poses = CapturePose.sequence(server: chipResult["poses"] as? [String]) else { throw FlowError.rejected }
                status = ""
                phase = 2
                stepTitle = "Ansiktskontroll"
                status = "Passets båda chipkontroller är klara. Lägg undan passet och håll telefonen framför ansiktet."
                try await waitForCameraStart()
                status = ""
                cameraVisible = true
                let frames = try await camera.capture(sequence: poses)
                cameraVisible = false
                try Task.checkCancellation()
                let payload: [String: Any] = ["id": id, "nonce": captureNonce,
                    "frames": frames.map { $0.base64EncodedString() }]
                let bytes = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
                let assertion = try await service.generateAssertion(keyID, clientDataHash: Data(SHA256.hash(data: bytes)))
                try Task.checkCancellation()
                stepTitle = "Kontrollerar dina uppgifter"
                status = "Bilderna är tagna. Vänta medan servern slutför kontrollen."
                let result = try await api.postObject("/native/finish", body: ["id": id,"payload":bytes.base64EncodedString(),"assertion":assertion.base64EncodedString()])
                activeChip = nil
                try Task.checkCancellation()
                if result["checksPassed"] as? Bool == false, let remaining = result["attemptsRemaining"] as? Int, (0...5).contains(remaining) {
                    // Only a count, never scores: the server does not reveal how close a failed attempt was.
                    stepTitle = "Ansiktskontrollen godkändes inte"
                    status = remaining > 0
                        ? "Bilderna kunde inte bekräfta att det är du som syns i passet. Följ vridningarna i den ordning appen visar, i jämnt ljus och utan glasögon eller mössa. Du har \(remaining) försök kvar just nu."
                        : WalletError.attemptLimit.localizedDescription
                    return
                }
                let state = try CredentialState.registrationResult(result, credentialID: credential.id, publicBeta: configuration.isPublicBeta)
                phase = 3; completed = true; stepTitle = "Kontrollen är klar"
                status = state == .active
                    ? "Ditt test-ID är aktiverat. Det spärras när betan avslutas den 1 december 2026 kl. 00.00 svensk tid."
                    : "Registreringen väntar på aktivering."
            } catch is CancellationError { status = "Registreringen avbröts." }
            catch WalletError.cameraImageRejected(let frame) { status = WalletError.cameraImageRejected(frame).localizedDescription }
            catch WalletError.attemptLimit { status = WalletError.attemptLimit.localizedDescription }
            catch WalletError.registrationPaused { status = WalletError.registrationPaused.localizedDescription }
            catch WalletError.overloaded { status = WalletError.overloaded.localizedDescription }
            catch is URLError { status = "Anslutningen bröts. Gå till Mitt ID och uppdatera status innan du försöker igen." }
            catch let error as CaptureCamera.CaptureError { status = error.localizedDescription }
            catch {
                status = passportRead && phase == 1
                    ? "Passet lästes, men säkerhetskontrollen kunde inte slutföras. Stopp vid: \(stepTitle). Registreringen är inte klar. Ange detta steg när du rapporterar felet."
                    : "Kontrollen kunde inte slutföras vid: \(stepTitle). Registreringen är inte klar. Du kan börja om."
            }
        }
    }
    func cancel() { task?.cancel(); noticeGeneration = UUID(); notice = nil; noticeText = nil; loadingNotice = false; termsAccepted = false; biometricsAccepted = false; let pending = cameraStart; cameraStart = nil; readyForCamera = false; pending?.resume(throwing: CancellationError()); chipRelay.cancel(); camera.stop(); clearDocument(); configuration = nil; credential = nil }
    func startCamera() {
        let pending = cameraStart; cameraStart = nil; readyForCamera = false
        pending?.resume()
    }
    private func waitForCameraStart() async throws {
        try await withTaskCancellationHandler(operation: {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                cameraStart = continuation; readyForCamera = true
            }
            try Task.checkCancellation()
        }, onCancel: { Task { @MainActor in
            let pending = self.cameraStart; self.cameraStart = nil; self.readyForCamera = false
            pending?.resume(throwing: CancellationError())
        } })
    }
    private func clearDocument() { documentNumber = ""; birth = ""; expiry = "" }
    enum FlowError: Error { case rejected }
}
