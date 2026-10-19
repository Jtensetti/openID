import Foundation

enum WalletError: LocalizedError {
    case configuration, rejected, unavailable, cancelled, keyUnavailable
    var errorDescription: String? {
        switch self {
        case .configuration: return "Ange en HTTPS-adress och en giltig kopplingskod från din server."
        case .rejected: return "Begäran kunde inte godkännas. Uppdatera status och försök igen."
        case .unavailable: return "Servern svarar inte. Kontrollera anslutningen och serverns certifikat."
        case .cancelled: return "Åtgärden avbröts."
        case .keyUnavailable: return "Telefonens skyddade nyckel kunde inte öppnas. Enhetskod och Secure Enclave krävs."
        }
    }
}

struct ServerConfiguration: Codable, Equatable {
    let origin: String
    let pairing: String
    init(origin: String, pairing: String) throws {
        let value = origin.trimmingCharacters(in: .whitespacesAndNewlines)
        guard var parts = URLComponents(string: value), parts.scheme == "https",
              let host = parts.host, !host.isEmpty, parts.user == nil, parts.password == nil,
              parts.query == nil, parts.fragment == nil, parts.percentEncodedPath == "" || parts.percentEncodedPath == "/",
              parts.port == nil || (1...65535).contains(parts.port!),
              pairing.range(of: "^[A-Za-z0-9_-]{32,128}\\z", options: .regularExpression) != nil else { throw WalletError.configuration }
        parts.path = ""
        guard let url = parts.url else { throw WalletError.configuration }
        self.origin = url.absoluteString; self.pairing = pairing
    }
    var url: URL { URL(string: origin)! }
}

enum CredentialState: String, Codable {
    case pending = "PENDING_REVIEW", active = "ACTIVE", revoked = "REVOKED", expired = "EXPIRED"
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
    var expired: Bool { expiresAt <= Date().timeIntervalSince1970 }
}
struct WalletEvent: Codable, Identifiable {
    let id: String
    let kind: String
    let time: TimeInterval
    var title: String {
        switch kind {
        case "CAPTURE_VERIFIED": return "Pass- och personkontroll slutförd"
        case "ACTIVATED": return "ID aktiverat"
        case "REQUESTED": return "Ny begäran om legitimering"
        case "APPROVED": return "Begäran godkänd"
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
    func validate(for id: String) throws {
        guard credentialId == id, environment == "PRIVATE_PILOT", !legalIdentityIssued,
              requests.count <= 5, events.count <= 50,
              state == .active || requests.isEmpty else { throw WalletError.rejected }
    }
}
struct DeviceChallenge: Decodable {
    let id: String
    let signingInput: String
    // Sign only the request details shown to the user.
    func validatedBytes(configuration: ServerConfiguration, credentialID: String, action: String,
                        request: WalletRequest?, now: TimeInterval = Date().timeIntervalSince1970) throws -> Data {
        guard let bytes = Data(base64Encoded: signingInput), bytes.count <= 4096 else { throw WalletError.rejected }
        let value = try JSONDecoder().decode(SigningEnvelope.self, from: bytes)
        guard value.version == 1, value.origin == configuration.origin, value.credentialId == credentialID,
              value.action == action, value.challengeId == id, value.requestId == request?.id,
              value.expiresAt > now, value.expiresAt <= now + 90,
              value.relyingParty == request?.relyingParty, value.purpose == request?.purpose,
              value.code == request?.code, ["snapshot", "approve", "reject", "revoke"].contains(action),
              (action == "approve" || action == "reject") == (request != nil),
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
}
enum RequestLink {
    static func identifier(_ url: URL) -> String? {
        guard url.scheme == "openid", url.host == "request", url.user == nil, url.password == nil,
              url.port == nil, url.query == nil, url.fragment == nil else { return nil }
        let id = String(url.path.dropFirst())
        return id.range(of: "^[a-f0-9]{64}\\z", options: .regularExpression) != nil ? id : nil
    }
}
