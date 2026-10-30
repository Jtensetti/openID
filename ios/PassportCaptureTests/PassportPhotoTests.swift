import XCTest
import UIKit
@testable import PassportCapture

final class PassportPhotoTests: XCTestCase {
    private let expected = PassportMRZ(documentNumber: "TEST12345", birth: "900215", expiry: "300215")
    private func mrzLine(number: String) -> String {
        func digit(_ value: String) -> String {
            let alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            return String(value.enumerated().reduce(0) { $0 + (alphabet.firstIndex(of: $1.element) ?? 0) * [7, 3, 1][$1.offset % 3] } % 10)
        }
        let first = number + digit(number), born = "900215" + digit("900215")
        let end = "300215" + digit("300215") + String(repeating: "<", count: 14) + "0"
        return first + "XXX" + born + "<" + end + digit(first + born + end)
    }
    // Generated layout only, no real passport or identity data.
    private func page(number: String = "TEST12345", clipped: Bool = false, blank: Bool = false) -> CGImage {
        let format = UIGraphicsImageRendererFormat(); format.scale = 1
        return UIGraphicsImageRenderer(size: CGSize(width: 1200, height: 1600), format: format).image { context in
            UIColor.darkGray.setFill(); context.fill(CGRect(x: 0, y: 0, width: 1200, height: 1600))
            guard !blank else { return }
            let x: CGFloat = clipped ? -100 : 100
            UIColor.white.setFill(); context.fill(CGRect(x: x, y: 448, width: 1000, height: 704))
            let attributes: [NSAttributedString.Key: Any] = [.font: UIFont.monospacedSystemFont(ofSize: 30, weight: .regular), .foregroundColor: UIColor.black]
            ("SYNTHETIC TEST DOCUMENT" as NSString).draw(at: CGPoint(x: x + 40, y: 480), withAttributes: attributes)
            UIColor.gray.setFill(); context.fill(CGRect(x: x + 50, y: 580, width: 220, height: 300))
            let first = "P<XXXEXAMPLE<<TEST".padding(toLength: 44, withPad: "<", startingAt: 0)
            (first as NSString).draw(at: CGPoint(x: x + 40, y: 1010), withAttributes: attributes)
            (mrzLine(number: number) as NSString).draw(at: CGPoint(x: x + 40, y: 1070), withAttributes: attributes)
        }.cgImage!
    }
    func testReadableSyntheticWholePageIsAcceptedLocally() {
        XCTAssertNil(PassportPhotoAssessment.evaluate(page(), expected: expected))
    }
    func testBlankClippedAndDifferentPassportDoNotFillFields() {
        XCTAssertNotNil(PassportPhotoAssessment.evaluate(page(blank: true), expected: expected))
        XCTAssertNotNil(PassportPhotoAssessment.evaluate(page(clipped: true), expected: expected))
        XCTAssertNotNil(PassportPhotoAssessment.evaluate(page(number: "TEST54321"), expected: expected))
    }
    func testOverlayFitsSmallAndLargeCameraRegions() {
        for size in [CGSize(width: 280, height: 400), CGSize(width: 440, height: 240)] {
            let frame = PassportPageFrame.rect(in: size)
            XCTAssertTrue(CGRect(origin: .zero, size: size).contains(frame))
            XCTAssertEqual(frame.width / frame.height, 1.42, accuracy: 0.001)
            XCTAssertEqual(frame.midX, size.width / 2)
            XCTAssertEqual(frame.midY, size.height / 2)
        }
    }
}
