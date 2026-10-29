import XCTest
import SwiftUI
@testable import PassportCapture

final class PaletteTests: XCTestCase {
    private func luminance(_ color: Color, traits: UITraitCollection) -> Double {
        let resolved = UIColor(color).resolvedColor(with: traits)
        var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 0
        XCTAssertTrue(resolved.getRed(&r, green: &g, blue: &b, alpha: &a))
        XCTAssertEqual(a, 1, accuracy: 0.001)
        func linear(_ x: CGFloat) -> Double { x <= 0.04045 ? Double(x) / 12.92 : pow((Double(x) + 0.055) / 1.055, 2.4) }
        return 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)
    }
    func testTextAndActionContrastInBothAppearances() {
        let pairs: [(String, Color, Color)] = [
            ("body", Palette.ink, Palette.paper), ("body panel", Palette.ink, Palette.surface),
            ("secondary", Palette.muted, Palette.paper), ("secondary panel", Palette.muted, Palette.surface),
            ("control code", Palette.ink, Palette.accentSurface), ("action", Palette.actionText, Palette.actionBackground),
            ("link", Palette.tint, Palette.paper), ("error", Palette.error, Palette.paper),
            ("error panel", Palette.error, Palette.surface), ("card", .white, Palette.cardEnd),
            ("card status", Palette.mint, Palette.cardEnd), ("privacy", Palette.mint, Palette.cardStart)
        ]
        for style in [UIUserInterfaceStyle.light, .dark] {
            for contrast in [UIAccessibilityContrast.normal, .high] {
                let traits = UITraitCollection(traitsFrom: [UITraitCollection(userInterfaceStyle: style), UITraitCollection(accessibilityContrast: contrast)])
                for (name, foreground, background) in pairs {
                    let a = luminance(foreground, traits: traits), b = luminance(background, traits: traits)
                    XCTAssertGreaterThanOrEqual((max(a, b) + 0.05) / (min(a, b) + 0.05), 4.5, "\(name), appearance \(style), contrast \(contrast)")
                }
            }
        }
    }
    func testBackgroundAndForegroundActuallyRespondToAppearance() {
        let light = UITraitCollection(userInterfaceStyle: .light), dark = UITraitCollection(userInterfaceStyle: .dark)
        XCTAssertGreaterThan(luminance(Palette.paper, traits: light), 0.8)
        XCTAssertLessThan(luminance(Palette.paper, traits: dark), 0.05)
        XCTAssertLessThan(luminance(Palette.ink, traits: light), 0.1)
        XCTAssertGreaterThan(luminance(Palette.ink, traits: dark), 0.8)
        XCTAssertNil(Bundle.main.object(forInfoDictionaryKey: "UIUserInterfaceStyle"), "The app must follow the system appearance")
    }
}
