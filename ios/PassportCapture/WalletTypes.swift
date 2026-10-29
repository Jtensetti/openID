import Foundation

enum WalletError: LocalizedError {
    case configuration, rejected, unavailable, overloaded, cancelled, keyUnavailable, attemptLimit, registrationPaused
    case cameraImageRejected(Int)
    /// Server decision about the security code: PIN_REQUIRED, PIN_INCORRECT, PIN_LOCKED or PIN_WEAK.
    case securityCode(String, Int?)
    var errorDescription: String? {
        switch self {
        case .securityCode(let code, let remaining):
            switch code {
            case "PIN_INCORRECT":
                let left = remaining ?? 0
                return "Fel säkerhetskod. Du har \(left) försök kvar innan koden spärras."
            case "PIN_LOCKED": return "Säkerhetskoden är spärrad efter för många fel. Det går inte att låsa upp den i appen: registrera ditt ID på nytt med passet. Inloggning med Face ID fungerar fortfarande."
            case "PIN_WEAK": return "Koden är för lätt att gissa. Undvik samma siffra, följder som 123456, upprepningar och ditt födelsedatum."
            default: return "Tjänsten kräver en säkerhetskod. Välj en säkerhetskod under Inställningar och försök igen."
            }
        case .attemptLimit: return "Försöksgränsen för ansiktskontroll är nådd för det här passet. Du kan försöka igen när den rullande 24-timmarsgränsen har passerat."
        case .registrationPaused: return "Ny registrering är tillfälligt pausad av säkerhetsskäl. Försök igen senare."
        case .cameraImageRejected(let frame): return "Servern kunde inte hitta ett enda tydligt ansikte i bild \(frame) av 3. Registreringen är inte klar. Försök igen med jämnt ljus och bara dig själv i bilden."
        case .configuration: return "Ange en HTTPS-adress och en giltig kopplingskod från din server."
        case .rejected: return "Begäran kunde inte godkännas. Uppdatera status och försök igen."
        case .unavailable: return "Servern svarar inte. Kontrollera anslutningen och serverns certifikat."
        case .overloaded: return "Servern är tillfälligt upptagen. Vänta en stund och uppdatera ditt ID innan du försöker igen."
        case .cancelled: return "Åtgärden avbröts."
        case .keyUnavailable: return "Telefonens skyddade nyckel kunde inte öppnas. Enhetskod och Secure Enclave krävs."
        }
    }
}

struct ServerConfiguration: Codable, Equatable {
    static let betaOrigin = "https://api.openid.tensetti.io"
    static var beta: ServerConfiguration { try! ServerConfiguration(origin: betaOrigin, pairing: "") }
    let origin: String
    let pairing: String
    var isPublicBeta: Bool { origin == Self.betaOrigin }
    static func initial(saved: ServerConfiguration?) -> ServerConfiguration {
        // Keep enrolled devices bound to their saved server. Never migrate a private identity.
        saved ?? beta
    }
    init(origin: String, pairing: String) throws {
        let value = origin.trimmingCharacters(in: .whitespacesAndNewlines)
        guard var parts = URLComponents(string: value), parts.scheme == "https",
              let host = parts.host, !host.isEmpty, parts.user == nil, parts.password == nil,
              parts.query == nil, parts.fragment == nil, parts.percentEncodedPath == "" || parts.percentEncodedPath == "/",
              parts.port == nil || (1...65535).contains(parts.port!),
              (pairing.range(of: "^[A-Za-z0-9_-]{32,128}\\z", options: .regularExpression) != nil || (value == Self.betaOrigin && pairing.isEmpty)) else { throw WalletError.configuration }
        parts.path = ""
        guard let url = parts.url else { throw WalletError.configuration }
        self.origin = url.absoluteString; self.pairing = pairing
    }
    var url: URL { URL(string: origin)! }
}

enum CredentialState: String, Codable {
    case pending = "PENDING_REVIEW", active = "ACTIVE", revoked = "REVOKED", expired = "EXPIRED"
    static func registrationResult(_ result: [String: Any], credentialID: String, publicBeta: Bool) throws -> CredentialState {
        guard result["checksPassed"] as? Bool == true, result["issuanceEnabled"] as? Bool == false,
              let credential = result["credential"] as? [String: Any],
              credential["id"] as? String == credentialID,
              let rawState = credential["state"] as? String, let state = CredentialState(rawValue: rawState),
              state == .pending || (state == .active && publicBeta && result["testBetaEndsAt"] as? Int == 1796079600)
        else { throw WalletError.rejected }
        return state
    }
    var guidance: String {
        switch self {
        case .pending: return "Registreringen är klar och väntar på aktivering. Du behöver inte läsa passet igen. Hämta status under Mitt ID efter att ditt ID aktiverats."
        case .active: return "Ditt test-ID är aktivt. Starta en inloggning på testsidan och skanna QR-koden."
        case .revoked: return "Ditt ID är spärrat och kan inte användas. Gå till Inställningar för att ta bort den spärrade nyckeln och registrera ett nytt ID."
        case .expired: return "Ditt ID har gått ut. Gå till Inställningar för att ta bort den gamla nyckeln och registrera ett nytt ID."
        }
    }
    var title: String {
        switch self { case .pending: return "Inväntar aktivering"; case .active: return "Aktivt"; case .revoked: return "Spärrat"; case .expired: return "Utgånget" }
    }
}
struct LocalCredential: Codable {
    let id: String
    let wrappedKey: Data
    let publicKey: Data
}
struct WalletRequest: Codable, Identifiable, Equatable {
    let id: String
    let relyingParty: String
    let purpose: String
    let code: String
    let expiresAt: TimeInterval
    /// Exact plain text the holder signs. Present only for a signature; approved with the separate "sign" action.
    var signMessage: String? = nil
    /// "pin" when the service requires the security code as well as Face ID (like BankID's PIN requirement).
    var verification: String? = nil
    var needsSecurityCode: Bool { verification == "pin" }
    var expired: Bool { expiresAt <= Date().timeIntervalSince1970 }
    var isSigning: Bool { signMessage != nil }
    /// Same rules as the server: bounded plain text, no control or bidirectional override characters.
    static func validSignMessage(_ text: String) -> Bool {
        let forbidden: Set<UInt32> = [0x2028, 0x2029, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0xfeff]
        return !text.isEmpty && text.unicodeScalars.count <= 400 && text == text.trimmingCharacters(in: .whitespacesAndNewlines)
            && text.filter({ $0 == "\n" }).count <= 12
            && !text.unicodeScalars.contains { ($0.value < 32 && $0.value != 10) || (127..<160).contains($0.value) || forbidden.contains($0.value) }
    }
}
struct WalletEvent: Codable, Identifiable {
    let id: String
    let kind: String
    let time: TimeInterval
    var title: String {
        switch kind {
        case "CAPTURE_VERIFIED": return "Pass- och personkontroll slutförd"
        case "ACTIVATED": return "ID aktiverat"
        case "TEST_BETA_VALIDITY_CHANGED": return "Test-ID giltigt till betans slut"
        case "REQUESTED": return "Ny begäran om legitimering"
        case "APPROVED": return "Begäran godkänd"
        case "SIGNED": return "Underskrift godkänd"
        case "SECURITY_CODE_SET": return "Säkerhetskod vald"
        case "SECURITY_CODE_FAILED": return "Fel säkerhetskod angiven"
        case "SECURITY_CODE_LOCKED": return "Säkerhetskoden spärrad"
        case "REJECTED": return "Begäran nekad"
        case "AUTHENTICATED": return "Inloggning genomförd"
        case "REVOKED": return "ID spärrat permanent"
        default: return "Status ändrad"
        }
    }
}
struct WalletSnapshot: Decodable {
    let credentialId: String
    let state: CredentialState
    let createdAt: TimeInterval
    let expiresAt: TimeInterval?
    let requests: [WalletRequest]
    let events: [WalletEvent]
    let environment: String
    let legalIdentityIssued: Bool
    var identity: PassportIdentity? = nil
    var revocationCode: String? = nil
    var securityCode: SecurityCodeStatus? = nil
    func validate(for id: String) throws {
        guard credentialId == id, environment == "PRIVATE_PILOT", !legalIdentityIssued,
              requests.count <= 5, events.count <= 50,
              state == .active || requests.isEmpty,
              (state == .active || state == .pending) || identity == nil else { throw WalletError.rejected }
        try identity?.validate()
        if let code = revocationCode { try RevocationProof(origin: ServerConfiguration.betaOrigin, code: code).validate(for: id) }
        for request in requests {
            guard request.id.range(of: "^[a-f0-9]{64}\\z", options: .regularExpression) != nil,
                  !request.relyingParty.isEmpty, request.relyingParty.count <= 100,
                  !request.purpose.isEmpty, request.purpose.count <= 200,
                  request.code.range(of: "^[0-9]{6}\\z", options: .regularExpression) != nil,
                  request.signMessage.map({ WalletRequest.validSignMessage($0) && request.purpose.hasPrefix("Skriv under") }) ?? true,
                  request.verification == nil || request.verification == "pin" else { throw WalletError.rejected }
        }
        if let code = securityCode, !(0...SecurityCode.attempts).contains(code.attemptsRemaining) || (code.locked && code.attemptsRemaining != 0) { throw WalletError.rejected }
    }
}

struct RevocationProof: Codable {
    let origin: String
    let code: String
    static let endpoint = URL(string: "https://o86p8fy3h6.execute-api.eu-north-1.amazonaws.com/revoke")!
    func validate(for credentialID: String) throws {
        guard origin == ServerConfiguration.betaOrigin,
              code.hasPrefix(credentialID + "."),
              code.range(of: "^[a-f0-9]{64}\\.[A-Za-z0-9_-]{43}\\z", options: .regularExpression) != nil else { throw WalletError.rejected }
    }
    var token: String { String(code.suffix(43)) }
}
struct PassportIdentity: Decodable {
    let displayName: String
    let birthDateMrz: String
    let portraitJpeg: String
    var passportPersonalNumber: String? = nil
    func validate() throws {
        if let number = passportPersonalNumber {
            guard number.range(of: "^(?:[0-9]{10}|[0-9]{12})\\z", options: .regularExpression) != nil else { throw WalletError.rejected }
        }
        guard displayName.range(of: "^[A-Z ]{1,89}\\z", options: .regularExpression) != nil,
              birthDateMrz.range(of: "^[0-9]{6}\\z", options: .regularExpression) != nil,
              let image = Data(base64Encoded: portraitJpeg), image.count <= 24000,
              image.starts(with: [0xff, 0xd8]), image.suffix(2) == Data([0xff, 0xd9]) else { throw WalletError.rejected }
    }
}
struct DeviceChallenge: Decodable {
    let id: String
    let signingInput: String
    // Sign only the request details shown to the user.
    func validatedBytes(configuration: ServerConfiguration, credentialID: String, action: String,
                        request: WalletRequest?, inspectID: String? = nil, now: TimeInterval = Date().timeIntervalSince1970) throws -> Data {
        guard let bytes = Data(base64Encoded: signingInput), bytes.count <= 4096 else { throw WalletError.rejected }
        let value = try JSONDecoder().decode(SigningEnvelope.self, from: bytes)
        guard value.version == 1, value.origin == configuration.origin, value.credentialId == credentialID,
              value.action == action, value.challengeId == id, value.requestId == (request?.id ?? inspectID),
              value.expiresAt > now, value.expiresAt <= now + 90,
              value.relyingParty == request?.relyingParty, value.purpose == request?.purpose,
              value.code == request?.code, value.signMessage == request?.signMessage,
              value.verification == request?.verification,
              ["snapshot", "inspect", "approve", "sign", "reject", "revoke", "set-pin"].contains(action),
              (action == "inspect") == (inspectID != nil),
              inspectID == nil || inspectID!.range(of: "^[a-f0-9]{64}\\z", options: .regularExpression) != nil,
              (action == "approve" || action == "sign" || action == "reject") == (request != nil),
              // A signature is never approved as a login, and a login never as a signature.
              action != "approve" || request?.signMessage == nil, action != "sign" || request?.signMessage != nil,
              request == nil || request!.expiresAt > now else { throw WalletError.rejected }
        return bytes
    }
}
private struct SigningEnvelope: Decodable {
    let version: Int
    let origin: String
    let credentialId: String
    let action: String
    let requestId: String?
    let challengeId: String
    let expiresAt: TimeInterval
    let relyingParty: String?
    let purpose: String?
    let code: String?
    let signMessage: String?
    let verification: String?
}
struct SecurityCodeStatus: Decodable, Equatable {
    let set: Bool
    let locked: Bool
    let attemptsRemaining: Int
}
enum SecurityCode {
    static let attempts = 5
    /// Exactly six ASCII digits; the server decides, this only avoids a pointless round trip.
    static func valid(_ code: String) -> Bool {
        code.count == 6 && code.unicodeScalars.allSatisfy { (48...57).contains($0.value) }
    }
    /// Same simple rules as the server, which also refuses the passport birth date.
    static func weak(_ code: String) -> Bool {
        guard valid(code) else { return true }
        let digits = code.unicodeScalars.map { Int($0.value) - 48 }
        let steps = Set((0..<5).map { digits[$0 + 1] - digits[$0] })
        if Set(digits).count <= 2 || steps == [1] || steps == [-1] { return true }
        let chars = Array(code)
        return chars[0..<3] == chars[3..<6] || (chars[0..<2] == chars[2..<4] && chars[2..<4] == chars[4..<6])
    }
}
enum RequestLink {
    static func identifier(_ url: URL) -> String? {
        guard url.scheme == "openid", url.host == "request", url.user == nil, url.password == nil,
              url.port == nil, url.query == nil, url.fragment == nil else { return nil }
        let id = String(url.path.dropFirst())
        return id.range(of: "^[a-f0-9]{64}\\z", options: .regularExpression) != nil ? id : nil
    }
}
