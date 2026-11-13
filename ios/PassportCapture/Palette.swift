import SwiftUI
import UIKit

/// Semantic colors follow the device appearance without an app-specific override.
enum Palette {
    private static let darkInk = UIColor(tjippHex: 0x10343B)
    private static let lightMint = UIColor(red: 0.73, green: 0.94, blue: 0.80, alpha: 1)
    private static func adaptive(_ light: UIColor, _ dark: UIColor) -> Color {
        Color(UIColor { traits in traits.userInterfaceStyle == .dark ? dark : light })
    }
    static let ink = adaptive(darkInk, UIColor(tjippHex: 0xF5F4EB))
    static let paper = adaptive(UIColor(tjippHex: 0xFAF8F2),
                                UIColor(tjippHex: 0x141716))
    static let surface = adaptive(UIColor(tjippHex: 0xFFFDF8), UIColor(tjippHex: 0x202623))
    static let muted = adaptive(UIColor(tjippHex: 0x5E6C6B),
                                UIColor(tjippHex: 0xAFB9B2))
    static let line = adaptive(UIColor(tjippHex: 0xD7DBD3), UIColor(tjippHex: 0x48504A))
    static let ivory = Color(UIColor(tjippHex: 0xF8F9EB))
    static let error = adaptive(UIColor(red: 0.68, green: 0.10, blue: 0.14, alpha: 1),
                                UIColor(red: 1, green: 0.48, blue: 0.48, alpha: 1))
    // Camera preview fixtures use fixed colors independent of screen appearance.
    static let cardStart = Color(darkInk)
    static let cardEnd = Color(red: 0.10, green: 0.26, blue: 0.27)
    static let mint = Color(lightMint)
}
