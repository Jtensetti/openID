import SwiftUI
import UIKit

/// Semantic colors follow the device appearance without an app-specific override.
enum Palette {
    private static let darkInk = UIColor(tjippHex: 0x10343B)
    private static let lightMint = UIColor(red: 0.73, green: 0.94, blue: 0.80, alpha: 1)
    private static func adaptive(_ light: UIColor, _ dark: UIColor) -> Color {
        Color(UIColor { traits in traits.userInterfaceStyle == .dark ? dark : light })
    }
    static let ink = adaptive(darkInk, UIColor(red: 0.90, green: 0.95, blue: 0.93, alpha: 1))
    static let paper = adaptive(UIColor(tjippHex: 0xFAF8F2),
                                UIColor(red: 0.04, green: 0.08, blue: 0.09, alpha: 1))
    static let surface = adaptive(UIColor(tjippHex: 0xFFFDF8), UIColor(red: 0.09, green: 0.15, blue: 0.16, alpha: 1))
    static let muted = adaptive(UIColor(tjippHex: 0x5E6C6B),
                                UIColor(red: 0.65, green: 0.75, blue: 0.74, alpha: 1))
    static let accentSurface = adaptive(UIColor(tjippHex: 0xEBEFE8), UIColor(red: 0.10, green: 0.25, blue: 0.21, alpha: 1))
    static let line = adaptive(UIColor(tjippHex: 0xD7DBD3), UIColor(tjippHex: 0x3A5153))
    static let ivory = Color(UIColor(tjippHex: 0xF8F9EB))
    static let tint = adaptive(darkInk, lightMint)
    static let actionBackground = adaptive(darkInk, lightMint)
    static let actionText = adaptive(UIColor(tjippHex: 0xF8F9EB), darkInk)
    static let error = adaptive(UIColor(red: 0.68, green: 0.10, blue: 0.14, alpha: 1),
                                UIColor(red: 1, green: 0.48, blue: 0.48, alpha: 1))
    // The ID card, camera overlays and privacy cover intentionally remain dark
    // in both appearances, with fixed light text over them.
    static let cardStart = Color(darkInk)
    static let cardEnd = Color(red: 0.10, green: 0.26, blue: 0.27)
    static let mint = Color(lightMint)
}
