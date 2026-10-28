import XCTest
import CryptoKit
@testable import PassportCapture

final class EnrollmentNoticeTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 2_000_000_000)
    private func fixture(_ changes: [String: Any] = [:]) throws -> EnrollmentNotice {
        let value: [String: Any] = ["version":"SYNTHETIC_TERMS_001", "locale":"sv-SE", "notBefore":1_999_999_940, "notAfter":2_000_000_600,
            "controller":"Syntetisk utfärdare", "contact":"privacy@example.invalid", "terms":"Testvillkor / svenska åäö.",
            "privacy":"Endast testdata.", "biometrics":"Syntetiskt uttryckligt val.", "withdrawal":"Syntetisk återkallelseinformation."]
        let bytes = try JSONSerialization.data(withJSONObject: value.merging(changes) { _, new in new }, options: [.sortedKeys])
        return EnrollmentNotice(digest: SHA256.hash(data: bytes).map { String(format:"%02x", $0) }.joined(), noticeJSON:bytes.base64EncodedString())
    }
    func testSeparateChoicesAndExactBytesAreRequired() throws {
        let notice = try fixture()
        XCTAssertEqual("Testvillkor / svenska åäö.",try notice.text(at: now).terms)
        let choice = try notice.acceptance(terms:true,biometrics:true,at:now)
        XCTAssertEqual(notice.digest, choice["policyDigest"] as? String)
        XCTAssertNil(choice["privacyAccepted"])
        for values in [(false,false),(true,false),(false,true)] {
            XCTAssertThrowsError(try notice.acceptance(terms:values.0,biometrics:values.1,at:now))
        }
        let changed = try fixture(["terms":"Andra villkor"])
        XCTAssertThrowsError(try EnrollmentNotice(digest:notice.digest,noticeJSON:changed.noticeJSON).text(at:now))
    }
    func testExpiredNoticeCanBeReadAsEvidenceButCannotAuthorizeNewCollection() throws {
        let notice = try fixture(["notAfter":1_999_999_999])
        XCTAssertNoThrow(try notice.text())
        XCTAssertThrowsError(try notice.acceptance(terms:true,biometrics:true,at:now))
        XCTAssertThrowsError(try fixture(["notBefore":2_000_000_001]).text(at:now))
    }
    func testIncompleteHiddenOversizedOrUnrecognizedNoticesFailClosed() throws {
        for fields: [String: Any] in [["terms":""],["privacy":String(repeating:"a",count:16385)],
            ["biometrics":"Synligt\u{202e}dolt"],["controller":""],["locale":"en-US"],["notAfter":true],["notBefore":-1]] {
            XCTAssertThrowsError(try fixture(fields).text(at:now))
        }
        XCTAssertThrowsError(try EnrollmentNotice(digest:String(repeating:"0",count:64),noticeJSON:"invalid").text(at:now))
    }
    func testWithdrawalPayloadCannotBeAnAuthenticationOrIssuanceRequest() throws {
        let receipt = EnrollmentReceipt(id:String(repeating:"a",count:64),credentialId:String(repeating:"b",count:64),
            origin:"https://localhost:8765",notice:try fixture(),state:.submitted)
        let value = try XCTUnwrap(JSONSerialization.jsonObject(with:receipt.withdrawalPayload()) as? [String:String])
        XCTAssertEqual(["action":"withdraw-enrollment-consent","origin":receipt.origin,"receipt":receipt.id],value)
    }
}
