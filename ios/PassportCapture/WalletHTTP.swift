import Foundation

/// Shared by registration, signed wallet operations and the independent revocation service.
final class WalletHTTP {
    private let session: URLSession

    init(configuration: URLSessionConfiguration = .ephemeral) {
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 60
        configuration.timeoutIntervalForResource = 90
        session = URLSession(configuration: configuration, delegate: NoRedirect(), delegateQueue: nil)
    }

    deinit { session.invalidateAndCancel() }

    func send(_ request: URLRequest, limit: Int) async throws -> (Data, Int) {
        guard let url = request.url, url.scheme == "https", request.httpMethod == "POST", limit > 0 else {
            throw WalletError.rejected
        }
        try Task.checkCancellation()
        let (stream, response) = try await session.bytes(for: request)
        // Cancel the transfer on every exit, including rejected headers and oversized chunked responses.
        defer { stream.task.cancel() }
        guard let http = response as? HTTPURLResponse, http.url == url,
              !(300...399).contains(http.statusCode) else { throw WalletError.rejected }
        if http.statusCode == 429 { throw WalletError.overloaded }
        guard http.mimeType?.lowercased() == "application/json",
              http.expectedContentLength <= Int64(limit) else { throw WalletError.rejected }
        var data = Data()
        for try await byte in stream {
            try Task.checkCancellation()
            guard data.count < limit else { throw WalletError.rejected }
            data.append(byte)
        }
        try Task.checkCancellation()
        return (data, http.statusCode)
    }
}

final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
