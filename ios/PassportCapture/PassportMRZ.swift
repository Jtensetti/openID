import Foundation

/// Camera text is an input aid only. Authenticity is checked from the signed chip data.
struct PassportMRZ: Equatable {
    let documentNumber: String
    let birth: String
    let expiry: String

    static func parse(_ text: String) -> PassportMRZ? {
        let lines = text.uppercased().components(separatedBy: .newlines).map {
            $0.filter { !$0.isWhitespace }
        }
        let candidates = lines.filter { $0.count == 44 && $0.range(of: "^[A-Z0-9<]+$", options: .regularExpression) != nil }
        var results = Set<String>()
        var found: PassportMRZ?
        for line in candidates {
            let chars = Array(line)
            func part(_ range: Range<Int>) -> String { String(chars[range]) }
            let number = part(0..<9), birth = part(13..<19), expiry = part(21..<27)
            guard part(10..<13).range(of: "^[A-Z<]{3}$", options: .regularExpression) != nil,
                  ["M", "F", "<"].contains(String(chars[20])),
                  validDate(birth), validDate(expiry),
                  check(number, chars[9]), check(birth, chars[19]), check(expiry, chars[27]),
                  check(part(0..<10) + part(13..<20) + part(21..<43), chars[43]),
                  !number.replacingOccurrences(of: "<", with: "").isEmpty else { continue }
            // Extended document numbers need a different MRZ profile; keep manual input available.
            let trimmed = String(number.prefix { $0 != "<" })
            guard number == trimmed + String(repeating: "<", count: 9 - trimmed.count) else { continue }
            results.insert(line)
            found = PassportMRZ(documentNumber: trimmed, birth: birth, expiry: expiry)
        }
        return results.count == 1 ? found : nil
    }

    private static func validDate(_ value: String) -> Bool {
        guard value.range(of: "^[0-9]{6}$", options: .regularExpression) != nil else { return false }
        let a = Array(value)
        let y = 2000 + Int(String(a[0..<2]))!, m = Int(String(a[2..<4]))!, d = Int(String(a[4..<6]))!
        let calendar = Calendar(identifier: .gregorian)
        let components = DateComponents(year: y, month: m, day: d)
        guard let date = calendar.date(from: components) else { return false }
        return calendar.dateComponents([.year, .month, .day], from: date) == components
    }

    private static func check(_ value: String, _ digit: Character) -> Bool {
        let alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        let sum = value.enumerated().reduce(0) { total, item in
            total + (alphabet.firstIndex(of: item.element) ?? 0) * [7, 3, 1][item.offset % 3]
        }
        return String(sum % 10) == String(digit)
    }
}
