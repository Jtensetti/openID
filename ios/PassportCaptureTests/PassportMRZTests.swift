import XCTest
@testable import PassportCapture

final class PassportMRZTests: XCTestCase {
    private func line(number: String = "TEST12345", birth: String = "900215", expiry: String = "300215") -> String {
        func digit(_ value: String) -> String {
            let alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            return String(value.enumerated().reduce(0) { $0 + (alphabet.firstIndex(of: $1.element) ?? 0) * [7, 3, 1][$1.offset % 3] } % 10)
        }
        let first = number + digit(number)
        let born = birth + digit(birth)
        let end = expiry + digit(expiry) + String(repeating: "<", count: 14) + "0"
        return first + "UTO" + born + "<" + end + digit(first + born + end)
    }
    func testReadsSyntheticTD3Line() {
        let result = PassportMRZ.parse("P<UTOEXAMPLE<<TEST<<<<<<<<<<<<<<<<<<<<<<<<<<<\n" + line())
        XCTAssertEqual(result, PassportMRZ(documentNumber: "TEST12345", birth: "900215", expiry: "300215"))
    }
    func testRejectsChangedCheckDigit() {
        var value = Array(line()); value[9] = value[9] == "0" ? "1" : "0"
        XCTAssertNil(PassportMRZ.parse(String(value)))
    }
    func testRejectsInvalidCalendarDateEvenWithValidChecksum() {
        XCTAssertNil(PassportMRZ.parse(line(birth: "900230")))
    }
    func testRejectsAmbiguousPassports() {
        XCTAssertNil(PassportMRZ.parse(line() + "\n" + line(number: "TEST54321")))
    }
    func testRejectsPartialTextAndOCRSubstitutions() {
        XCTAssertNil(PassportMRZ.parse(String(line().dropLast())))
        XCTAssertNil(PassportMRZ.parse(line().replacingOccurrences(of: "900215", with: "9OO215")))
    }
    func testAllowsWhitespaceAndDuplicateRecognition() {
        XCTAssertNotNil(PassportMRZ.parse("  " + line() + "  \n" + line()))
    }
}
