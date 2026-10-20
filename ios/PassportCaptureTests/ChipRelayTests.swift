import XCTest
@testable import PassportCapture

final class ChipRelayTests: XCTestCase {
    private func message(_ bytes: [UInt8], sequence: Any = 0) -> [String: Any] {
        ["type": "command", "sequence": sequence, "command": Data(bytes).base64EncodedString()]
    }
    func testReadOnlyProtocolCommands() throws {
        for instruction: UInt8 in [0xA4, 0xB0, 0x22, 0x86, 0xC0] {
            XCTAssertEqual(try ChipRelayCommand(message([0, instruction, 0, 0]), expectedSequence: 0).bytes[1], instruction)
        }
        _ = try ChipRelayCommand(message([0, 0xA4, 2, 0x0C, 2, 0x01, 0x0E]), expectedSequence: 0)
    }
    func testWriteAndUnrecognizedInstructionsAreRejected() {
        for instruction: UInt8 in [0xD0, 0xD6, 0xDA, 0xE0, 0xE4, 0x20, 0x24, 0x2C] {
            XCTAssertThrowsError(try ChipRelayCommand(message([0, instruction, 0, 0]), expectedSequence: 0))
        }
        XCTAssertThrowsError(try ChipRelayCommand(message([0x80, 0xA4, 0, 0]), expectedSequence: 0))
    }
    func testSequenceReplayAndLimitAreRejected() {
        XCTAssertThrowsError(try ChipRelayCommand(message([0, 0xA4, 0, 0]), expectedSequence: 1))
        XCTAssertThrowsError(try ChipRelayCommand(message([0, 0xA4, 0, 0], sequence: 128), expectedSequence: 128))
        XCTAssertThrowsError(try ChipRelayCommand(message([0, 0xA4, 0, 0], sequence: true), expectedSequence: 1))
        XCTAssertThrowsError(try ChipRelayCommand(message([0, 0xA4, 0, 0], sequence: 0.5), expectedSequence: 0))
    }
    func testMalformedAndExtendedAPDUsAreRejected() {
        for bytes: [UInt8] in [[], [0, 0xA4], [0, 0xA4, 0, 0, 3, 1], [0, 0xA4, 0, 0, 0, 1, 0]] {
            XCTAssertThrowsError(try ChipRelayCommand(message(bytes), expectedSequence: 0))
        }
        XCTAssertThrowsError(try ChipRelayCommand(message(Array(repeating: 0, count: 262)), expectedSequence: 0))
    }
    func testClientSuccessIsNotACommand() {
        XCTAssertThrowsError(try ChipRelayCommand(["type": "verified", "chipAuthentication": true], expectedSequence: 0))
        XCTAssertThrowsError(try ChipRelayCommand(["type": "command", "sequence": 0, "command": "!"], expectedSequence: 0))
    }
}
