import XCTest
import SwiftUI
@testable import PassportCapture

final class PaletteTests: XCTestCase {
    func testAllAlternateIconsArePackagedForTheSystemSwitcher() throws {
        let icons = try XCTUnwrap(Bundle.main.infoDictionary?["CFBundleIcons"] as? [String: Any])
        let alternatives = try XCTUnwrap(icons["CFBundleAlternateIcons"] as? [String: Any])
        XCTAssertEqual(Set(alternatives.keys), Set(TjippColor.allCases.compactMap(\.appIconName)))
        XCTAssertNotNil(icons["CFBundlePrimaryIcon"])
    }
    func testEveryThemeHasReadableActionsAndAccentsInBothAppearances() {
        for style in [UIUserInterfaceStyle.light, .dark] {
            let traits = UITraitCollection(userInterfaceStyle: style)
            for color in TjippColor.allCases {
                let theme = TjippTheme(selection: color, scheme: style == .dark ? .dark : .light)
                for (foreground, background) in [(theme.actionText, theme.actionBackground),
                    (theme.accent, Palette.paper), (theme.accent, Palette.surface), (Palette.ink, theme.softSurface)] {
                    let a = luminance(foreground, traits: traits), b = luminance(background, traits: traits)
                    XCTAssertGreaterThanOrEqual((max(a,b)+0.05)/(min(a,b)+0.05), 4.5, "\(color.title), \(style)")
                }
            }
        }
    }
    func testAllOriginalLogoVariantsArePackaged() {
        for variant in TjippColor.allCases {
            let image = UIImage(named: variant.asset)
            XCTAssertNotNil(image, "Missing original artwork for \(variant.title)")
            XCTAssertEqual(image?.size.width, image?.size.height)
        }
        XCTAssertNotNil(UIImage(named: "TjippWordmark"))
    }
    func testTextContrastOnEveryPersonalCardIncludingPattern() {
        func components(_ color: Color, _ traits: UITraitCollection) -> [Double] {
            var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 0
            UIColor(color).resolvedColor(with: traits).getRed(&r, green: &g, blue: &b, alpha: &a)
            return [Double(r), Double(g), Double(b)]
        }
        for style in [UIUserInterfaceStyle.light, .dark] {
            let traits = UITraitCollection(userInterfaceStyle: style)
            for variant in TjippColor.allCases {
                let base = components(Palette.surface, traits), accent = components(variant.color, traits)
                let ink = components(Palette.ink, traits)
                let tint = style == .dark ? 0.16 : 0.07
                // Worst-case background under text, including the strongest texture pixel.
                let background = (0..<3).map { (base[$0] * (1-tint) + accent[$0] * tint) * 0.935 + ink[$0] * 0.065 }
                let bg = Color(red: background[0], green: background[1], blue: background[2])
                let a = luminance(Palette.ink, traits: traits), b = luminance(bg, traits: traits)
                XCTAssertGreaterThanOrEqual((max(a,b)+0.05)/(min(a,b)+0.05), 4.5, "\(variant.title), \(style)")
            }
        }
    }
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
            ("error", Palette.error, Palette.paper),
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
