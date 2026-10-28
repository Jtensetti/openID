import Foundation

final class WalletAPI {
    let configuration: ServerConfiguration
    private let transport = WalletHTTP()

    init(configuration: ServerConfiguration) {
        self.configuration = configuration
    }
    func post<T: Decodable>(_ path: String, body: [String: Any], as type: T.Type) async throws -> T {
        let data = try await postData(path, body: body)
        return try JSONDecoder().decode(type, from: data)
    }
    func postObject(_ path: String, body: [String: Any]) async throws -> [String: Any] {
        let data = try await postData(path, body: body)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw WalletError.rejected }
        return object
    }
    private func postData(_ path: String, body: [String: Any]) async throws -> Data {
        guard ["/native/notice", "/native/start", "/native/attest", "/native/consent", "/native/withdraw", "/native/chip/start", "/native/chip/step", "/native/cancel", "/native/finish", "/wallet/challenge", "/wallet/execute"].contains(path) else { throw WalletError.rejected }
        var request = URLRequest(url: URL(string: path, relativeTo: configuration.url)!)
        request.httpMethod = "POST"; request.timeoutInterval = 60
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(configuration.origin, forHTTPHeaderField: "Origin")
        if !configuration.pairing.isEmpty { request.setValue(configuration.pairing, forHTTPHeaderField: "X-CSRF-Token") }
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        guard request.httpBody!.count <= 14_000_000 else { throw WalletError.rejected }
        let (data, status) = try await transport.send(request, limit: 262144)
        if status == 503 {
            if path.hasPrefix("/native/"),
               let error = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               error["error"] as? String == "REGISTRATION_PAUSED" { throw WalletError.registrationPaused }
            throw WalletError.overloaded
        }
        if status == 422, path == "/native/finish",
           let error = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           error["error"] as? String == "CAMERA_IMAGE_REJECTED",
           let frame = error["frame"] as? Int, (1...3).contains(frame) {
            throw WalletError.cameraImageRejected(frame)
        }
        if status == 403, path == "/wallet/execute",
           let error = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let code = error["error"] as? String, ["PIN_REQUIRED", "PIN_INCORRECT", "PIN_LOCKED", "PIN_WEAK"].contains(code) {
            let remaining = error["attemptsRemaining"] as? Int
            throw WalletError.securityCode(code, remaining.flatMap { (0...SecurityCode.attempts).contains($0) ? $0 : nil })
        }
        if status == 403, path == "/native/finish",
           let error = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           error["error"] as? String == "ATTEMPT_LIMIT" {
            throw WalletError.attemptLimit
        }
        guard status == 200 else { throw WalletError.rejected }
        return data
    }
}
