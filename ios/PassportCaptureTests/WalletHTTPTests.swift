import XCTest
@testable import PassportCapture

final class WalletHTTPTests: XCTestCase {
    private func transport() -> WalletHTTP {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [SyntheticHTTP.self]
        return WalletHTTP(configuration: configuration)
    }
    private func request(_ path: String) -> URLRequest {
        var request = URLRequest(url: URL(string: "https://synthetic.invalid/" + path)!)
        request.httpMethod = "POST"
        return request
    }
    func testBoundedJSONAndHTTPFailuresReachTheCaller() async throws {
        let (data, status) = try await transport().send(request("ok"), limit: 2)
        XCTAssertEqual(data, Data("{}".utf8))
        XCTAssertEqual(status, 200)
        let (_, denied) = try await transport().send(request("denied"), limit: 4096)
        XCTAssertEqual(denied, 403)
    }
    func testOversizedDeclaredAndChunkedResponsesAreRejected() async {
        for path in ["large-declared", "large-stream"] {
            do {
                _ = try await transport().send(request(path), limit: 4096)
                XCTFail("Accepted oversized response: \(path)")
            } catch WalletError.rejected {} catch { XCTFail("Unexpected error: \(error)") }
        }
    }
    func testRedirectsWrongEndpointAndNonJSONCannotConfirmAnOperation() async {
        for path in ["redirect", "other-url", "html"] {
            do {
                _ = try await transport().send(request(path), limit: 4096)
                XCTFail("Accepted untrusted response: \(path)")
            } catch WalletError.rejected {} catch { XCTFail("Unexpected error: \(error)") }
        }
    }
    func testRedirectDelegateNeverForwardsTheBody() {
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let original = request("ok")
        let response = HTTPURLResponse(url: original.url!, statusCode: 307, httpVersion: nil,
                                       headerFields: ["Location": "https://other.invalid/"])!
        NoRedirect().urlSession(session, task: session.dataTask(with: original), willPerformHTTPRedirection: response,
                                newRequest: URLRequest(url: URL(string: "https://other.invalid/")!)) { next in
            XCTAssertNil(next)
        }
    }
    func testRateLimitDoesNotRequireAPotentiallyLargeResponseBody() async {
        do {
            _ = try await transport().send(request("busy"), limit: 4096)
            XCTFail("Rate limit accepted")
        } catch WalletError.overloaded {} catch { XCTFail("Unexpected error: \(error)") }
    }
    func testCancelledOperationCannotStartANewRequest() async {
        let operation = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await transport().send(request("ok"), limit: 4096)
        }
        do { _ = try await operation.value; XCTFail("Cancelled operation accepted") }
        catch is CancellationError {} catch { XCTFail("Unexpected error: \(error)") }
    }
    func testInsecureRequestIsRejectedBeforeTransport() async {
        var insecure = request("ok")
        insecure.url = URL(string: "http://synthetic.invalid/ok")!
        do { _ = try await transport().send(insecure, limit: 4096); XCTFail("HTTP accepted") }
        catch WalletError.rejected {} catch { XCTFail("Unexpected error: \(error)") }
    }
    @MainActor func testLockClearsSecurityCodeFeedbackAndDisplayedState() {
        let model = WalletModel()
        model.setSecurityCode(current: nil, new: "bad")
        XCTAssertNotNil(model.securityCodeMessage)
        model.lock()
        XCTAssertNil(model.securityCodeMessage)
        XCTAssertNil(model.snapshot)
        XCTAssertNil(model.focusedRequest)
        XCTAssertNil(model.revocationProof)
        XCTAssertFalse(model.unlocked)
    }
}

/// Synthetic URL loading only: no TLS, DNS, credentials or live revocation is exercised.
private final class SyntheticHTTP: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "synthetic.invalid" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let path = request.url!.lastPathComponent
        let status = path == "busy" ? 429 : path == "redirect" ? 307 : path == "denied" ? 403 : 200
        var headers = ["Content-Type": path == "html" ? "text/html" : "application/json; charset=utf-8"]
        if path == "large-declared" { headers["Content-Length"] = "9999999" }
        if path == "redirect" { headers["Location"] = "https://other.invalid/" }
        let url = path == "other-url" ? URL(string: "https://other.invalid/")! : request.url!
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!, cacheStoragePolicy: .notAllowed)
        if path == "large-stream" {
            client?.urlProtocol(self, didLoad: Data(repeating: 32, count: 4096))
            client?.urlProtocol(self, didLoad: Data([32]))
        } else { client?.urlProtocol(self, didLoad: Data("{}".utf8)) }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
