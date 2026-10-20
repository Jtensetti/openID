import XCTest
@testable import PassportCapture

final class PassportAccessKeyTests: XCTestCase {
    func testICAOSampleAccessKey() throws {
        XCTAssertEqual(try PassportAccessKey.encode(documentNumber: "L898902C3", birth: "740812", expiry: "120415"),
                       "L898902C3674081221204159")
    }
    func testPastedNewlineCannotReachPaddingOrNFC() {
        for suffix in ["\n", "\r", "\r\n", "\u{2028}"] {
            XCTAssertThrowsError(try PassportAccessKey.encode(documentNumber: "L898902C3" + suffix, birth: "740812", expiry: "120415"))
            XCTAssertThrowsError(try PassportAccessKey.encode(documentNumber: "L898902C3", birth: "740812" + suffix, expiry: "120415"))
            XCTAssertThrowsError(try PassportAccessKey.encode(documentNumber: "L898902C3", birth: "740812", expiry: "120415" + suffix))
        }
    }
    func testInvalidDocumentNumbersAndDatesAreRejected() {
        for number in ["", "1234567890", "L8989 2C3", "Å898902C3", "<script>"] {
            XCTAssertThrowsError(try PassportAccessKey.encode(documentNumber: number, birth: "740812", expiry: "120415"))
        }
        for date in ["74081", "7408120", "74O812", "７４０８１２"] {
            XCTAssertThrowsError(try PassportAccessKey.encode(documentNumber: "L898902C3", birth: date, expiry: "120415"))
        }
    }
}
