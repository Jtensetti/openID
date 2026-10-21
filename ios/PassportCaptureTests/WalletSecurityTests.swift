import XCTest
@testable import PassportCapture

final class WalletSecurityTests: XCTestCase {
    @MainActor func testRefreshFailureDoesNotClaimAnActionWasSent() {
        let message = WalletModel.failureMessage(action: "snapshot", error: URLError(.notConnectedToInternet))
        XCTAssertTrue(message.contains("Hämta status"))
        XCTAssertFalse(message.contains("ditt val"))
        XCTAssertTrue(WalletModel.failureMessage(action: "approve", error: URLError(.timedOut)).contains("innan du försöker igen"))
    }
    @MainActor func testCancelledAuthenticationIsNotAnErrorAlert() {
        XCTAssertTrue(WalletModel.wasCancelled(CancellationError()))
        XCTAssertTrue(WalletModel.wasCancelled(WalletError.cancelled))
        XCTAssertFalse(WalletModel.wasCancelled(URLError(.timedOut)))
    }
    let ident = String(repeating: "a", count: 64)
    let requestID = String(repeating: "b", count: 64)
    let now: TimeInterval = 1000
    var config: ServerConfiguration { try! ServerConfiguration(origin: "https://192.168.1.20:8765", pairing: String(repeating: "x", count: 43)) }
    var request: WalletRequest { WalletRequest(id: requestID, relyingParty: "openID lokal testtjänst", purpose: "Logga in", code: "123456", expiresAt: 1100) }
    func envelope(_ changes: [String: Any] = [:]) -> DeviceChallenge {
        var data: [String: Any] = ["version":1,"origin":config.origin,"credentialId":ident,"action":"approve",
            "requestId":requestID,"challengeId":"challenge","expiresAt":1060,
            "relyingParty":request.relyingParty,"purpose":request.purpose,"code":request.code]
        data.merge(changes, uniquingKeysWith: { _, value in value })
        let encoded = try! JSONSerialization.data(withJSONObject: data)
        return DeviceChallenge(id: "challenge", signingInput: encoded.base64EncodedString())
    }
    func testExactDisplayedApprovalCanBeSigned() throws {
        let challenge = envelope()
        XCTAssertEqual(try challenge.validatedBytes(configuration: config, credentialID: ident, action: "approve", request: request, now: now), Data(base64Encoded: challenge.signingInput))
    }
    func testChangedRelyingPartyPurposeAndCodeCannotBeSigned() {
        for field in ["relyingParty", "purpose", "code"] {
            XCTAssertThrowsError(try envelope([field:"attacker"]).validatedBytes(configuration: config, credentialID: ident, action: "approve", request: request, now: now))
        }
    }
    func testWrongOriginCredentialActionSessionAndRequestCannotBeSigned() {
        for field in ["origin", "credentialId", "action", "challengeId", "requestId"] {
            XCTAssertThrowsError(try envelope([field:"other"]).validatedBytes(configuration: config, credentialID: ident, action: "approve", request: request, now: now))
        }
    }
    func testExpiredAndExcessivelyLongChallengeCannotBeSigned() {
        for expiry in [999, 1000, 1091] {
            XCTAssertThrowsError(try envelope(["expiresAt":expiry]).validatedBytes(configuration: config, credentialID: ident, action: "approve", request: request, now: now))
        }
    }
    func testExpiredDisplayedRequestCannotBeSigned() {
        let expired = WalletRequest(id: requestID, relyingParty: request.relyingParty, purpose: request.purpose, code: request.code, expiresAt: 1000)
        XCTAssertThrowsError(try envelope().validatedBytes(configuration: config, credentialID: ident, action: "approve", request: expired, now: now))
    }
    func testSnapshotCannotSmuggleApproval() {
        XCTAssertThrowsError(try envelope().validatedBytes(configuration: config, credentialID: ident, action: "snapshot", request: nil, now: now))
    }
    func testInspectCanReadRequestButCannotSignApproval() throws {
        let challenge = envelope(["action":"inspect", "relyingParty":NSNull(), "purpose":NSNull(), "code":NSNull()])
        XCTAssertNoThrow(try challenge.validatedBytes(configuration:config,credentialID:ident,action:"inspect",request:nil,inspectID:requestID,now:now))
        XCTAssertThrowsError(try challenge.validatedBytes(configuration:config,credentialID:ident,action:"approve",request:request,now:now))
        XCTAssertThrowsError(try challenge.validatedBytes(configuration:config,credentialID:ident,action:"inspect",request:nil,inspectID:String(repeating:"c",count:64),now:now))
        XCTAssertThrowsError(try envelope().validatedBytes(configuration:config,credentialID:ident,action:"inspect",request:nil,inspectID:requestID,now:now))
    }
    func testIdentityProfilePreservesMrzAndRejectsOversizedOrMalformedPortrait() throws {
        let image = Data([0xff,0xd8,0xff,0xd9]).base64EncodedString()
        let identity = PassportIdentity(displayName:"ALICE SYNTHETIC",birthDateMrz:"900101",portraitJpeg:image)
        XCTAssertNoThrow(try identity.validate())
        XCTAssertEqual(identity.birthDateMrz,"900101")
        for invalid in [PassportIdentity(displayName:"<script>",birthDateMrz:"900101",portraitJpeg:image),
                        PassportIdentity(displayName:"ALICE",birthDateMrz:"19900101",portraitJpeg:image),
                        PassportIdentity(displayName:"ALICE",birthDateMrz:"900101",portraitJpeg:Data(repeating:0,count:24001).base64EncodedString())] {
            XCTAssertThrowsError(try invalid.validate())
        }
        var snapshot = WalletSnapshot(credentialId:ident,state:.revoked,createdAt:1,expiresAt:2000,requests:[],events:[],environment:"PRIVATE_PILOT",legalIdentityIssued:false)
        snapshot.identity = identity
        XCTAssertThrowsError(try snapshot.validate(for:ident))
    }
    func testPassportNumberDecodesWithoutChangingLegacyProfiles() throws {
        let image = Data([0xff,0xd8,0xff,0xd9]).base64EncodedString()
        var payload: [String: Any] = ["displayName":"ALICE SYNTHETIC", "birthDateMrz":"570413", "portraitJpeg":image]
        func decode() throws -> PassportIdentity {
            try JSONDecoder().decode(PassportIdentity.self, from: JSONSerialization.data(withJSONObject: payload))
        }
        XCTAssertNil(try decode().passportPersonalNumber)
        payload["passportPersonalNumber"] = NSNull()
        XCTAssertNil(try decode().passportPersonalNumber)
        for number in ["195704133106", "5704133106"] {
            payload["passportPersonalNumber"] = number
            let value = try decode()
            XCTAssertEqual(value.passportPersonalNumber, number)
            XCTAssertNoThrow(try value.validate())
        }
        for number in ["19570413-3106", "570413310", "195704133106\n", "ABCDEFGHIJKL"] {
            payload["passportPersonalNumber"] = number
            XCTAssertThrowsError(try decode().validate())
        }
        payload["passportPersonalNumber"] = 123
        XCTAssertThrowsError(try decode())
    }
    func testMalformedPayloadAndVersionCannotBeSigned() {
        for raw in ["!", Data("{}".utf8).base64EncodedString(), Data(repeating: 0, count: 5000).base64EncodedString()] {
            XCTAssertThrowsError(try DeviceChallenge(id:"challenge",signingInput:raw).validatedBytes(configuration:config,credentialID:ident,action:"approve",request:request,now:now))
        }
        XCTAssertThrowsError(try envelope(["version":2]).validatedBytes(configuration:config,credentialID:ident,action:"approve",request:request,now:now))
    }
    func testHTTPSOriginNormalization() throws {
        XCTAssertEqual(try ServerConfiguration(origin: "https://example.test/", pairing: config.pairing).origin, "https://example.test")
    }
    func testUnsafeServerAddressesAreRejected() {
        for address in ["http://example.test", "https://user:password@example.test", "https://example.test/path", "https://example.test?token=abc", "https://example.test#fragment", "https://example.test:0", "file:///etc/passwd", "https://example.test/%2f"] {
            XCTAssertThrowsError(try ServerConfiguration(origin: address, pairing: config.pairing), address)
        }
    }
    func testInvalidPairingCodesAreRejected() {
        for code in ["", "short", String(repeating:"x", count:129), String(repeating:"x", count:40)+"\n"] {
            XCTAssertThrowsError(try ServerConfiguration(origin:config.origin,pairing:code))
        }
    }
    func testOnlyOpaqueSameAppRequestLinksAreAccepted() {
        XCTAssertEqual(RequestLink.identifier(URL(string:"openid://request/"+requestID)!),requestID)
        for value in ["https://evil.test/"+requestID,"openid://user@request/"+requestID,"openid://request/"+requestID+"?callback=https://evil.test","openid://request/short","openid://request:123/"+requestID,"openid://request/"+requestID+"#fragment"] {
            XCTAssertNil(RequestLink.identifier(URL(string:value)!))
        }
    }
    func testSnapshotFromOtherCredentialOrEnvironmentRejected() {
        let empty = WalletSnapshot(credentialId:"other",state:.active,createdAt:1,expiresAt:2000,requests:[],events:[],environment:"PRIVATE_PILOT",legalIdentityIssued:false)
        XCTAssertThrowsError(try empty.validate(for:ident))
        let production = WalletSnapshot(credentialId:ident,state:.active,createdAt:1,expiresAt:2000,requests:[],events:[],environment:"PRODUCTION",legalIdentityIssued:true)
        XCTAssertThrowsError(try production.validate(for:ident))
    }
    func testRevokedSnapshotMustNotOfferApproval() {
        let revoked = WalletSnapshot(credentialId:ident,state:.revoked,createdAt:1,expiresAt:2000,requests:[request],events:[],environment:"PRIVATE_PILOT",legalIdentityIssued:false)
        XCTAssertThrowsError(try revoked.validate(for:ident))
    }
}
