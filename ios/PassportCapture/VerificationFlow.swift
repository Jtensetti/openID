import Foundation
import CryptoKit
import DeviceCheck
import NFCPassportReader

@MainActor final class VerificationFlow: ObservableObject {
    private var configuration: ServerConfiguration?
    private var credential: LocalCredential?
    @Published var phase = 0
    @Published var completed = false
    @Published var documentNumber = ""
    @Published var birth = ""
    @Published var expiry = ""
    @Published var status = ""
    @Published var busy = false
    @Published var cameraVisible = false
    let camera = CaptureCamera()
    private var task: Task<Void, Never>?
    private var reader: PassportReader?

    func prepare(configuration: ServerConfiguration, credential: LocalCredential) {
        self.configuration = configuration; self.credential = credential
        phase = 0; completed = false; status = ""
    }

    func start() {
        guard !busy else { return }
        busy = true
        task = Task {
            defer { busy = false; cameraVisible = false; camera.stop(); reader = nil; clearDocument() }
            do {
                guard let configuration, let credential else { throw FlowError.rejected }
                let api = WalletAPI(configuration: configuration)
                phase = 1
                let key = try PassportAccessKey.encode(documentNumber: documentNumber, birth: birth, expiry: expiry)
                let service = DCAppAttestService.shared
                guard service.isSupported else { throw FlowError.rejected }
                status = "Ansluter…"
                let start = try await api.postObject("/native/start", body: [:])
                guard let id = start["id"] as? String, let challenge = start["challenge"] as? String else { throw FlowError.rejected }
                let keyID = try await service.generateKey()
                let attestation = try await service.attestKey(keyID, clientDataHash: Data(SHA256.hash(data: Data(challenge.utf8))))
                let registered = try await api.postObject("/native/attest", body: ["id": id, "keyId": keyID, "attestation": attestation.base64EncodedString()])
                guard let nonce = registered["nonce"] as? String else { throw FlowError.rejected }
                try Task.checkCancellation()
                status = "Håll telefonen mot passet tills läsningen är klar."
                let passportReader = PassportReader(); reader = passportReader
                let passport = try await passportReader.readPassport(mrzKey: key, tags: [.DG1, .DG2, .DG14, .SOD], skipCA: false, skipPACE: false)
                clearDocument()
                try Task.checkCancellation()
                guard passport.chipAuthenticationStatus == .success,
                      let sod = passport.dataGroupsRead[.SOD]?.data,
                      let dg1 = passport.dataGroupsRead[.DG1]?.data,
                      let dg2 = passport.dataGroupsRead[.DG2]?.data else { throw FlowError.rejected }
                status = "Håll telefonen stilla. Tre bilder tas automatiskt."
                phase = 2
                cameraVisible = true
                let frames = try await camera.capture()
                cameraVisible = false
                try Task.checkCancellation()
                let payload: [String: Any] = ["id": id, "nonce": nonce, "sod": Data(sod).base64EncodedString(),
                    "dg1": Data(dg1).base64EncodedString(), "dg2": Data(dg2).base64EncodedString(),
                    "chipAuthentication": true, "frames": frames.map { $0.base64EncodedString() },
                    "devicePublicKey": credential.publicKey.base64EncodedString()]
                let bytes = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
                let assertion = try await service.generateAssertion(keyID, clientDataHash: Data(SHA256.hash(data: bytes)))
                try Task.checkCancellation()
                status = "Kontrollerar pass och kamerabilder…"
                let result = try await api.postObject("/native/finish", body: ["id": id,"payload":bytes.base64EncodedString(),"assertion":assertion.base64EncodedString()])
                try Task.checkCancellation()
                guard result["checksPassed"] as? Bool == true,
                      let registeredCredential = result["credential"] as? [String: Any],
                      registeredCredential["id"] as? String == credential.id,
                      registeredCredential["state"] as? String == "PENDING_REVIEW" else { throw FlowError.rejected }
                phase = 3; completed = true
                status = "Registreringen väntar på aktivering."
            } catch is CancellationError { status = "Avbrutet." }
            catch { status = "Verifieringen kunde inte slutföras. Kontrollera anslutning, passuppgifter och kamerabehörighet och börja om." }
        }
    }
    func cancel() { task?.cancel(); camera.stop(); clearDocument(); configuration = nil; credential = nil }
    private func clearDocument() { documentNumber = ""; birth = ""; expiry = "" }
    enum FlowError: Error { case rejected }
}
