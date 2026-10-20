import Foundation

struct WalletAPI {
    let configuration: ServerConfiguration
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
        guard ["/native/start", "/native/attest", "/native/chip/start", "/native/chip/step", "/native/cancel", "/native/finish", "/wallet/challenge", "/wallet/execute"].contains(path) else { throw WalletError.rejected }
        var request = URLRequest(url: URL(string: path, relativeTo: configuration.url)!)
        request.httpMethod = "POST"; request.timeoutInterval = 60
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(configuration.origin, forHTTPHeaderField: "Origin")
        request.setValue(configuration.pairing, forHTTPHeaderField: "X-CSRF-Token")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        guard request.httpBody!.count <= 14_000_000 else { throw WalletError.rejected }
        let options = URLSessionConfiguration.ephemeral
        options.urlCache = nil; options.httpCookieStorage = nil
        let session = URLSession(configuration: options, delegate: NoRedirect(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        // Check size while streaming; data(for:) would buffer the entire response.
        let (stream, response) = try await session.bytes(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw WalletError.rejected }
        var data = Data()
        for try await byte in stream {
            guard data.count < 262144 else { throw WalletError.rejected }
            data.append(byte)
        }
        try Task.checkCancellation()
        return data
    }
}
private final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
