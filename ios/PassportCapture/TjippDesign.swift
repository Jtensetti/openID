import SwiftUI

/// The names and RGB values are shared with folkidentitet.se.
enum TjippColor: String, CaseIterable, Identifiable {
    case hav, skog, aprikos, lera, sol, lavendel, ros, grafit
    var id: String { rawValue }
    var title: String { rawValue.capitalized }
    var hex: UInt32 {
        switch self {
        case .hav: return 0x070E3D
        case .skog: return 0x2B6A50
        case .aprikos: return 0xC96F49
        case .lera: return 0xAA5547
        case .sol: return 0xC08B22
        case .lavendel: return 0x79719D
        case .ros: return 0xB37583
        case .grafit: return 0x5F6669
        }
    }
    var color: Color { Color(UIColor(tjippHex: hex)) }
    var asset: String { "TjippSymbol-" + rawValue }
}

extension UIColor {
    convenience init(tjippHex: UInt32) {
        self.init(red: CGFloat((tjippHex >> 16) & 255) / 255,
                  green: CGFloat((tjippHex >> 8) & 255) / 255,
                  blue: CGFloat(tjippHex & 255) / 255, alpha: 1)
    }
}

/// One live theme is inherited by every screen, sheet, button and native control.
struct TjippTheme {
    var selection: TjippColor = .hav
    var scheme: ColorScheme = .light
    var actionBackground: Color { selection.color }
    var actionText: Color {
        let base = UIColor(tjippHex: selection.hex)
        let light = UIColor(tjippHex: 0xF8F9EB), dark = UIColor(tjippHex: 0x101B1E)
        let preferred = Self.contrast(base, light) >= Self.contrast(base, dark) ? light : dark
        if Self.contrast(base, preferred) >= 4.5 { return Color(preferred) }
        return Color(Self.contrast(base, .white) >= Self.contrast(base, .black) ? UIColor.white : UIColor.black)
    }
    var accent: Color {
        let traits = UITraitCollection(userInterfaceStyle: scheme == .dark ? .dark : .light)
        let backgrounds = [Palette.paper, Palette.surface].map { UIColor($0).resolvedColor(with: traits) }
        let base = UIColor(tjippHex: selection.hex)
        let target = UIColor(tjippHex: scheme == .dark ? 0xF8F9EB : 0x101B1E)
        for step in 0...20 {
            let candidate = Self.mix(base, target, fraction: CGFloat(step) / 20)
            if backgrounds.allSatisfy({ Self.contrast(candidate, $0) >= 4.5 }) { return Color(candidate) }
        }
        return Color(target)
    }
    var softSurface: Color {
        let traits = UITraitCollection(userInterfaceStyle: scheme == .dark ? .dark : .light)
        return Color(Self.mix(UIColor(Palette.surface).resolvedColor(with: traits),
                              UIColor(tjippHex: selection.hex), fraction: scheme == .dark ? 0.16 : 0.07))
    }
    private static func mix(_ first: UIColor, _ second: UIColor, fraction: CGFloat) -> UIColor {
        var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 0
        var x: CGFloat = 0, y: CGFloat = 0, z: CGFloat = 0, w: CGFloat = 0
        first.getRed(&r, green: &g, blue: &b, alpha: &a); second.getRed(&x, green: &y, blue: &z, alpha: &w)
        return UIColor(red: r + (x-r)*fraction, green: g + (y-g)*fraction, blue: b + (z-b)*fraction, alpha: 1)
    }
    private static func contrast(_ first: UIColor, _ second: UIColor) -> Double {
        func luminance(_ color: UIColor) -> Double {
            var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 0
            color.getRed(&r, green: &g, blue: &b, alpha: &a)
            func linear(_ x: CGFloat) -> Double { x <= 0.04045 ? Double(x)/12.92 : pow((Double(x)+0.055)/1.055, 2.4) }
            return 0.2126*linear(r) + 0.7152*linear(g) + 0.0722*linear(b)
        }
        let a = luminance(first), b = luminance(second)
        return (max(a,b)+0.05)/(min(a,b)+0.05)
    }
}
private struct TjippThemeKey: EnvironmentKey { static let defaultValue = TjippTheme() }
extension EnvironmentValues {
    var tjippTheme: TjippTheme {
        get { self[TjippThemeKey.self] }
        set { self[TjippThemeKey.self] = newValue }
    }
}
private struct TjippThemeModifier: ViewModifier {
    @AppStorage("tjipp.color") private var selection: TjippColor = .hav
    @Environment(\.colorScheme) private var scheme
    func body(content: Content) -> some View {
        let theme = TjippTheme(selection: selection, scheme: scheme)
        content.environment(\.tjippTheme, theme).tint(theme.accent).foregroundStyle(Palette.ink)
    }
}

enum TjippPattern: String, CaseIterable, Identifiable {
    case paper, grain, dunes, rings
    var id: String { rawValue }
    var title: String {
        switch self { case .paper: return "Papper"; case .grain: return "Ådring"; case .dunes: return "Dyner"; case .rings: return "Ringar" }
    }
}

struct TjippSymbol: View {
    @AppStorage("tjipp.color") private var selectedColor: TjippColor = .hav
    var color: TjippColor? = nil
    var size: CGFloat = 44
    var body: some View {
        Image((color ?? selectedColor).asset).resizable().scaledToFit()
            .frame(width: size, height: size).accessibilityHidden(true)
    }
}

struct TjippWordmark: View {
    @AppStorage("tjipp.color") private var selectedColor: TjippColor = .hav
    var body: some View {
        LinearGradient(stops: [.init(color: Palette.ink, location: 0),
                               .init(color: Palette.ink, location: 0.87),
                               .init(color: selectedColor.color, location: 0.87),
                               .init(color: selectedColor.color, location: 1)],
                       startPoint: .leading, endPoint: .trailing)
            .frame(width: 94, height: 41)
            .mask { Image("TjippWordmark").resizable().scaledToFit().saturation(0).colorInvert().brightness(0.3).contrast(4).luminanceToAlpha() }
            .accessibilityLabel("Tjipp")
    }
}

enum TjippLayout {
    static let margin: CGFloat = 24
    static let sectionGap: CGFloat = 24
    static let cardRadius: CGFloat = 24
    static let controlRadius: CGFloat = 17
    static let title = Font.system(.largeTitle, design: .serif)
}

struct TjippBrandHeader: View {
    var body: some View {
        HStack(spacing: 10) {
            TjippSymbol(size: 38)
            TjippWordmark()
            Spacer(minLength: 8)
            Text("Utveckling").font(.caption2.weight(.medium))
                .foregroundStyle(Palette.muted).padding(.horizontal, 10).padding(.vertical, 7)
                .background(Palette.surface, in: Capsule())
        }
    }
}

/// Shared page, section and control shapes keep secondary screens in the same family.
struct TjippPage<Content: View>: View {
    let title: String
    var showsBrand = false
    @ViewBuilder var content: () -> Content
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: TjippLayout.sectionGap) {
                if showsBrand { TjippBrandHeader() }
                Text(title).font(TjippLayout.title).fixedSize(horizontal: false, vertical: true)
                    .accessibilityAddTraits(.isHeader)
                content()
            }.frame(maxWidth: .infinity, alignment: .leading).padding(TjippLayout.margin)
        }.tjippScreen().toolbar(showsBrand ? .hidden : .visible, for: .navigationBar)
    }
}

struct TjippSection<Content: View>: View {
    var title: String? = nil
    @ViewBuilder var content: () -> Content
    init(_ title: String? = nil, @ViewBuilder content: @escaping () -> Content) {
        self.title = title; self.content = content
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let title { Text(title).font(.headline).accessibilityAddTraits(.isHeader) }
            content()
        }.frame(maxWidth: .infinity, alignment: .leading).padding(20)
            .background(Palette.surface, in: RoundedRectangle(cornerRadius: TjippLayout.cardRadius))
            .overlay { RoundedRectangle(cornerRadius: TjippLayout.cardRadius).stroke(Palette.line, lineWidth: 1) }
            .buttonStyle(TjippRowButtonStyle())
    }
}

struct TjippRowButtonStyle: ButtonStyle {
    @Environment(\.tjippTheme) private var theme
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.body.weight(.medium))
            .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
            .foregroundStyle(configuration.role == .destructive ? Palette.error : theme.accent)
            .contentShape(Rectangle()).opacity(!enabled ? 0.48 : configuration.isPressed ? 0.65 : 1)
    }
}

struct TjippNavigationRow: View {
    @Environment(\.tjippTheme) private var theme
    let title: String
    var symbol: String
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol).foregroundStyle(theme.accent).frame(width: 24).accessibilityHidden(true)
            Text(title).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(Palette.muted).accessibilityHidden(true)
        }.frame(minHeight: 44)
    }
}

struct TjippFieldStyle: TextFieldStyle {
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration.padding(16).frame(minHeight: 54)
            .background(Palette.paper, in: RoundedRectangle(cornerRadius: TjippLayout.controlRadius))
            .overlay { RoundedRectangle(cornerRadius: TjippLayout.controlRadius).stroke(Palette.line, lineWidth: 1) }
    }
}

struct TjippSecondaryButtonStyle: ButtonStyle {
    @Environment(\.tjippTheme) private var theme
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.headline).fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, minHeight: 44).padding(.horizontal, 18).padding(.vertical, 6)
            .foregroundStyle(configuration.role == .destructive ? Palette.error : theme.accent)
            .background(theme.softSurface, in: RoundedRectangle(cornerRadius: TjippLayout.controlRadius))
            .overlay { RoundedRectangle(cornerRadius: TjippLayout.controlRadius).stroke(Palette.line, lineWidth: 1) }
            .opacity(!enabled ? 0.48 : configuration.isPressed ? 0.65 : 1)
    }
}

extension View {
    func tjippTheme() -> some View { modifier(TjippThemeModifier()) }
    func tjippScreen() -> some View {
        self.background(Palette.paper).tjippTheme()
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(Palette.paper, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
    }
}

/// Quiet vector textures, separate from the original logo artwork and from status.
struct OrganicPattern: View {
    let pattern: TjippPattern
    let color: Color
    var body: some View {
        Canvas { context, size in
            switch pattern {
            case .paper:
                for i in 0..<260 {
                    let x = CGFloat((i * 73 + 19) % 997) / 997 * size.width
                    let y = CGFloat((i * 139 + 53) % 991) / 991 * size.height
                    context.fill(Path(ellipseIn: CGRect(x: x, y: y, width: 1, height: 1.6)), with: .color(color))
                }
            case .grain, .dunes:
                for i in -5..<22 {
                    let y = CGFloat(i) * 16
                    var path = Path()
                    path.move(to: CGPoint(x: -20, y: y))
                    path.addCurve(to: CGPoint(x: size.width + 20, y: y + 54),
                        control1: CGPoint(x: size.width * 0.28, y: y + (pattern == .grain ? -44 : 80)),
                        control2: CGPoint(x: size.width * 0.63, y: y + (pattern == .grain ? 100 : -72)))
                    context.stroke(path, with: .color(color), lineWidth: pattern == .grain ? 0.8 : 1.5)
                }
            case .rings:
                for i in 0..<18 {
                    let r = CGFloat(24 + i * 12)
                    var path = Path()
                    for step in 0...120 {
                        let angle = Double(step) * .pi / 60
                        let radius = r + CGFloat(sin(angle * 3 + 0.4) * 3 + cos(angle * 5) * 1.5)
                        let point = CGPoint(x: size.width * 0.9 + radius * CGFloat(cos(angle)),
                                            y: size.height * 0.3 + radius * 0.72 * CGFloat(sin(angle)))
                        if step == 0 { path.move(to: point) } else { path.addLine(to: point) }
                    }
                    path.closeSubpath()
                    context.stroke(path, with: .color(color), lineWidth: 1)
                }
            }
        }.clipped().allowsHitTesting(false).accessibilityHidden(true)
    }
}

struct TjippCardBackground: View {
    @AppStorage("tjipp.color") private var color: TjippColor = .hav
    @AppStorage("tjipp.pattern") private var pattern: TjippPattern = .paper
    @Environment(\.colorScheme) private var scheme
    var body: some View {
        RoundedRectangle(cornerRadius: 24).fill(Palette.surface)
            .overlay { RoundedRectangle(cornerRadius: 24).fill(color.color.opacity(scheme == .dark ? 0.16 : 0.07)) }
            .overlay {
                OrganicPattern(pattern: pattern, color: Palette.ink.opacity(0.065))
                    .mask(LinearGradient(colors: [.clear, .white], startPoint: .leading, endPoint: .trailing))
                    .clipShape(RoundedRectangle(cornerRadius: 24))
            }
            .overlay { RoundedRectangle(cornerRadius: 24).stroke(Palette.line, lineWidth: 1) }
    }
}

struct AppearanceView: View {
    @EnvironmentObject private var icons: AppIconController
    @Environment(\.tjippTheme) private var theme
    @AppStorage("tjipp.color") private var color: TjippColor = .hav
    @AppStorage("tjipp.pattern") private var pattern: TjippPattern = .paper
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 28) {
                Text("Ditt uttryck").font(TjippLayout.title)
                Text("Välj färg och mönster. Ditt val sparas på den här telefonen.")
                    .foregroundStyle(Palette.muted)
                HStack(spacing: 20) {
                    TjippSymbol(size: 72)
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Tjipp").font(.title2.weight(.semibold))
                        Text("\(color.title) · \(pattern.title)").font(.subheadline).foregroundStyle(Palette.ink)
                    }
                    Spacer(minLength: 0)
                }.padding(24).frame(minHeight: 145).background(TjippCardBackground())
                    .accessibilityElement(children: .combine).accessibilityIdentifier("appearance.preview")
                VStack(alignment: .leading, spacing: 12) {
                    Text("Färg").font(.title3.weight(.semibold))
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 85), spacing: 12)], spacing: 12) {
                        ForEach(TjippColor.allCases) { option in
                            Button { color = option; icons.update(for: option) } label: {
                                VStack(spacing: 9) {
                                    TjippSymbol(color: option, size: 44)
                                    Text(option.title).font(.subheadline)
                                    Image(systemName: color == option ? "checkmark.circle.fill" : "circle")
                                }.frame(maxWidth: .infinity, minHeight: 108).padding(8)
                                    .background(Palette.surface, in: RoundedRectangle(cornerRadius: 18))
                                    .overlay { RoundedRectangle(cornerRadius: 18).stroke(color == option ? theme.accent : Palette.line, lineWidth: color == option ? 2 : 1) }
                            }.buttonStyle(.plain).accessibilityLabel(option.title)
                                .accessibilityValue(color == option ? "Vald" : "Inte vald")
                                .accessibilityAddTraits(color == option ? .isSelected : [])
                                .accessibilityIdentifier("appearance.color.\(option.rawValue)")
                        }
                    }
                }
                VStack(alignment: .leading, spacing: 12) {
                    Text("Mönster").font(.title3.weight(.semibold))
                    ForEach(TjippPattern.allCases) { option in
                        Button { pattern = option } label: {
                            HStack(spacing: 16) {
                                OrganicPattern(pattern: option, color: color.color.opacity(0.35))
                                    .frame(width: 64, height: 48).background(Palette.surface, in: RoundedRectangle(cornerRadius: 10))
                                Text(option.title)
                                Spacer()
                                Image(systemName: pattern == option ? "checkmark.circle.fill" : "circle")
                            }.padding(12).background(Palette.surface, in: RoundedRectangle(cornerRadius: 16))
                        }.buttonStyle(.plain).accessibilityValue(pattern == option ? "Valt" : "Inte valt")
                            .accessibilityIdentifier("appearance.pattern.\(option.rawValue)")
                    }
                }
                Text("Appikonen följer \(icons.currentColor.title).")
                    .font(.footnote).foregroundStyle(Palette.muted).accessibilityIdentifier("appearance.icon-status")
                if let error = icons.error { Text(error).font(.footnote).foregroundStyle(Palette.error) }
                Text("Färgen är personlig. ID-status visas alltid med text och symbol.")
                    .font(.footnote).foregroundStyle(Palette.muted)
            }.padding(24)
        }.tjippScreen()
            .navigationTitle("Färg och mönster").navigationBarTitleDisplayMode(.inline)
    }
}

/// The system keyboard reduces the safe area, keeping the complete action visible.
struct BottomActionBar<Content: View>: View {
    @ViewBuilder var content: () -> Content
    var body: some View {
        VStack(spacing: 8, content: content)
            .padding(.horizontal, 24).padding(.vertical, 10)
            .frame(maxWidth: .infinity).background(Palette.paper)
            .overlay(alignment: .top) { Divider() }
    }
}

struct PassportPlacementView: View {
    @Environment(\.tjippTheme) private var theme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var placed = false
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            ZStack {
                RoundedRectangle(cornerRadius: 12).fill(theme.actionBackground)
                    .frame(width: 104, height: 142).rotationEffect(.degrees(-12))
                    .overlay { Image(systemName: "globe.europe.africa").font(.system(size: 38, weight: .ultraLight)).foregroundStyle(theme.actionText).offset(x: -12, y: 12) }
                RoundedRectangle(cornerRadius: 18).fill(Palette.surface)
                    .frame(width: 78, height: 148)
                    .overlay { RoundedRectangle(cornerRadius: 18).stroke(Palette.ink, lineWidth: 3) }
                    .overlay(alignment: .top) {
                        Capsule().fill(Palette.ink).frame(width: 28, height: 5).padding(.top, 8)
                    }
                    .overlay(alignment: .top) {
                        Image(systemName: "wave.3.right").font(.title2).foregroundStyle(Palette.ink)
                            .rotationEffect(.degrees(-90)).offset(y: 24)
                    }
                    .offset(x: placed || reduceMotion ? 24 : 58, y: placed || reduceMotion ? 18 : -14)
            }.frame(maxWidth: .infinity).frame(height: 190).accessibilityHidden(true)
            Text("Lägg telefonens överkant mot passet").font(.headline)
            Text("Lägg passet plant. Flytta telefonen långsamt tills den hittar chipet och håll sedan stilla.")
                .font(.subheadline).foregroundStyle(Palette.muted)
            Label("Två läsningar – håll mot samma pass när appen ber om det igen.", systemImage: "arrow.triangle.2.circlepath")
                .font(.footnote).foregroundStyle(Palette.muted)
        }.padding(20).background(Palette.surface, in: RoundedRectangle(cornerRadius: 20))
            .onAppear { if !reduceMotion { withAnimation(.easeInOut(duration: 1.8).repeatForever(autoreverses: true)) { placed = true } } }
    }
}
