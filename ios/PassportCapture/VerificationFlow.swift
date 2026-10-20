import Foundation
import CryptoKit
import DeviceCheck
import NFCPassportReader

@MainActor final class VerificationFlow: ObservableObject {
    @Published var server = ""
    @Published var pairing = ""
    @Published var documentNumber = ""
    @Published var birth = ""
    @Published var expiry = ""
    @Published var status = "Ange serveradress och kopplingskod från verifieringsservern."
    @Published var busy = false
    @Published var cameraVisible = false
    let camera = CaptureCamera()
    private var task: Task<Void, Never>?
    private var reader: PassportReader?

    func start() {
        guard !busy else { return }
        busy = true
        task = Task {
            defer { busy = false; cameraVisible = false; camera.stop(); reader = nil; clearDocument() }
            do {
                let origin = try validatedOrigin()
                let key = try mrzKey()
                let service = DCAppAttestService.shared
                guard service.isSupported else { throw FlowError.rejected }
                status = "Binder appen till verifieringssessionen…"
                let start = try await post("/native/start", [:], origin)
                guard let id = start["id"] as? String, let challenge = start["challenge"] as? String else { throw FlowError.rejected }
                let keyID = try await service.generateKey()
                let attestation = try await service.attestKey(keyID, clientDataHash: Data(SHA256.hash(data: Data(challenge.utf8))))
                let registered = try await post("/native/attest", ["id": id, "keyId": keyID, "attestation": attestation.base64EncodedString()], origin)
                guard let nonce = registered["nonce"] as? String else { throw FlowError.rejected }
                try Task.checkCancellation()
                status = "Håll iPhone mot passet. Läser chipet och utför chipautentisering…"
                let passportReader = PassportReader(); reader = passportReader
                let passport = try await passportReader.readPassport(mrzKey: key, tags: [.DG1, .DG2, .DG14, .SOD], skipCA: false, skipPACE: false)
                clearDocument()
                try Task.checkCancellation()
                guard passport.chipAuthenticationStatus == .success,
                      let sod = passport.dataGroupsRead[.SOD]?.data,
                      let dg1 = passport.dataGroupsRead[.DG1]?.data,
                      let dg2 = passport.dataGroupsRead[.DG2]?.data else { throw FlowError.rejected }
                status = "Titta mot kameran. Tre bilder tas för ansiktsjämförelse och liveness."
                cameraVisible = true
                let frames = try await camera.capture()
                cameraVisible = false
                try Task.checkCancellation()
                let payload: [String: Any] = ["id": id, "nonce": nonce, "sod": Data(sod).base64EncodedString(),
                    "dg1": Data(dg1).base64EncodedString(), "dg2": Data(dg2).base64EncodedString(),
                    "chipAuthentication": true, "frames": frames.map { $0.base64EncodedString() }]
                let bytes = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
                let assertion = try await service.generateAssertion(keyID, clientDataHash: Data(SHA256.hash(data: bytes)))
                try Task.checkCancellation()
                status = "Verifierar passets signaturkedja, ansiktslikhet och liveness…"
                let result = try await post("/native/finish", ["id": id,"payload":bytes.base64EncodedString(),"assertion":assertion.base64EncodedString()], origin)
                status = (result["checksPassed"] as? Bool == true)
                    ? "De tekniska kontrollerna passerade. Resultatet använder utvärderingsgränser; ingen e-legitimation har utfärdats."
                    : "Kontrollerna passerade inte. Ingen e-legitimation har utfärdats."
            } catch is CancellationError { status = "Avbrutet. Underlaget används inte vidare." }
            catch { status = "Verifieringen kunde inte slutföras. Kontrollera anslutning, passuppgifter och kamerabehörighet och börja om." }
        }
    }
    func cancel() { task?.cancel(); camera.stop(); clearDocument(); pairing = "" }
    private func clearDocument() { documentNumber = ""; birth = ""; expiry = "" }
    private func validatedOrigin() throws -> URL {
        guard let url = URL(string: server), url.scheme == "https", url.host != nil, url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil, url.path.isEmpty, pairing.count >= 32 else { throw FlowError.rejected }
        return url
    }
    private func post(_ path: String, _ body: [String: Any], _ origin: URL) async throws -> [String: Any] {
        var request = URLRequest(url: URL(string: path, relativeTo: origin)!)
        request.httpMethod = "POST"; request.timeoutInterval = 60
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(origin.absoluteString, forHTTPHeaderField: "Origin")
        request.setValue(pairing, forHTTPHeaderField: "X-CSRF-Token")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil; configuration.httpCookieStorage = nil
        let session = URLSession(configuration: configuration, delegate: NoRedirect(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        // Default platform TLS validation. No trust-all/self-signed bypass.
        let (data,response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw FlowError.rejected }
        return object
    }
    private func mrzKey() throws -> String {
        let number = documentNumber.uppercased()
        guard number.range(of: "^[A-Z0-9<]{1,9}$", options: .regularExpression) != nil,
              birth.range(of: "^[0-9]{6}$", options: .regularExpression) != nil,
              expiry.range(of: "^[0-9]{6}$", options: .regularExpression) != nil else { throw FlowError.rejected }
        // ICAO MRZ check digits are format checks, not cryptographic authentication.
        // Adapted from AndyQ/NFCPassportReader's MIT-licensed PassportUtils.
        func checked(_ value: String) -> String {
            let alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            let values = value.enumerated().map { index, character in (alphabet.firstIndex(of: character) ?? 0) * [7,3,1][index % 3] }
            return value + String(values.reduce(0,+) % 10)
        }
        return checked(number + String(repeating: "<", count: 9-number.count)) + checked(birth) + checked(expiry)
    }
    enum FlowError: Error { case rejected }
}

private final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
