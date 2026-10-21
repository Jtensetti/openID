import Foundation

enum PassportAccessKey {
    enum Field: Hashable {
        case number, birth, expiry
        var instruction: String {
            switch self {
            case .number: return "Fyll i passnumret: högst nio bokstäver eller siffror, utan mellanslag."
            case .birth: return "Skriv födelsedatum med sex siffror: år, månad, dag. Exempel: 900516 för 16 maj 1990."
            case .expiry: return "Skriv passets sista giltighetsdag med sex siffror: år, månad, dag. Exempel: 300516 för 16 maj 2030."
            }
        }
    }
    static func invalidField(documentNumber: String, birth: String, expiry: String) -> Field? {
        if documentNumber.uppercased().range(of: "^[A-Z0-9<]{1,9}\\z", options: .regularExpression) == nil { return .number }
        if birth.range(of: "^[0-9]{6}\\z", options: .regularExpression) == nil { return .birth }
        if expiry.range(of: "^[0-9]{6}\\z", options: .regularExpression) == nil { return .expiry }
        return nil
    }
    static func encode(documentNumber: String, birth: String, expiry: String) throws -> String {
        let number = documentNumber.uppercased()
        guard invalidField(documentNumber: number, birth: birth, expiry: expiry) == nil else { throw WalletError.rejected }
        // ICAO MRZ check digits are format checks, not cryptographic authentication.
        // Adapted from AndyQ/NFCPassportReader's MIT-licensed PassportUtils.
        func checked(_ value: String) -> String {
            let alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            let values = value.enumerated().map { index, character in
                (alphabet.firstIndex(of: character) ?? 0) * [7, 3, 1][index % 3]
            }
            return value + String(values.reduce(0, +) % 10)
        }
        return checked(number + String(repeating: "<", count: 9 - number.count)) + checked(birth) + checked(expiry)
    }
}
