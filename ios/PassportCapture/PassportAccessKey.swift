import Foundation

enum PassportAccessKey {
    static func encode(documentNumber: String, birth: String, expiry: String) throws -> String {
        let number = documentNumber.uppercased()
        guard number.range(of: "^[A-Z0-9<]{1,9}\\z", options: .regularExpression) != nil,
              birth.range(of: "^[0-9]{6}\\z", options: .regularExpression) != nil,
              expiry.range(of: "^[0-9]{6}\\z", options: .regularExpression) != nil else { throw WalletError.rejected }
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
