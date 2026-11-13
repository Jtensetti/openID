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
    @Environment(\.colorScheme) private var scheme
    var body: some View {
        Image("TjippWordmark").resizable().scaledToFit().frame(width: 94, height: 41)
            .padding(.horizontal, scheme == .dark ? 8 : 0)
            .background(scheme == .dark ? Color(UIColor(tjippHex: 0xFAF8F2)) : .clear, in: RoundedRectangle(cornerRadius: 12))
            .accessibilityLabel("Tjipp")
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
    @AppStorage("tjipp.color") private var color: TjippColor = .hav
    @AppStorage("tjipp.pattern") private var pattern: TjippPattern = .paper
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 28) {
                Text("Ditt uttryck").font(.system(.largeTitle, design: .serif))
                Text("Välj färg och mönster. Ditt val sparas på den här telefonen.")
                    .foregroundStyle(Palette.muted)
                HStack(spacing: 20) {
                    TjippSymbol(size: 72)
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Tjipp").font(.title2.weight(.semibold))
                        Text("\(color.title) · \(pattern.title)").font(.subheadline).foregroundStyle(Palette.muted)
                    }
                    Spacer(minLength: 0)
                }.padding(24).frame(minHeight: 145).background(TjippCardBackground())
                    .accessibilityElement(children: .combine).accessibilityIdentifier("appearance.preview")
                VStack(alignment: .leading, spacing: 12) {
                    Text("Färg").font(.title3.weight(.semibold))
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 85), spacing: 12)], spacing: 12) {
                        ForEach(TjippColor.allCases) { option in
                            Button { color = option } label: {
                                VStack(spacing: 9) {
                                    TjippSymbol(color: option, size: 44)
                                    Text(option.title).font(.subheadline)
                                    Image(systemName: color == option ? "checkmark.circle.fill" : "circle")
                                }.frame(maxWidth: .infinity, minHeight: 108).padding(8)
                                    .background(Palette.surface, in: RoundedRectangle(cornerRadius: 18))
                                    .overlay { RoundedRectangle(cornerRadius: 18).stroke(color == option ? Palette.ink : Palette.line, lineWidth: color == option ? 2 : 1) }
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
                Text("Färgen är personlig. ID-status visas alltid med text och symbol.")
                    .font(.footnote).foregroundStyle(Palette.muted)
            }.padding(24)
        }.background(Palette.paper).foregroundStyle(Palette.ink)
            .navigationTitle("Färg och mönster").navigationBarTitleDisplayMode(.inline)
    }
}

/// The system keyboard reduces the safe area, keeping the complete action visible.
struct BottomActionBar<Content: View>: View {
    @ViewBuilder var content: () -> Content
    var body: some View {
        VStack(spacing: 4, content: content)
            .padding(.horizontal, 24).padding(.vertical, 10)
            .frame(maxWidth: .infinity).background(Palette.paper)
            .overlay(alignment: .top) { Divider() }
    }
}

struct PassportPlacementView: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var placed = false
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            ZStack {
                RoundedRectangle(cornerRadius: 12).fill(Palette.ink)
                    .frame(width: 104, height: 142).rotationEffect(.degrees(-12))
                    .overlay { Image(systemName: "globe.europe.africa").font(.system(size: 38, weight: .ultraLight)).foregroundStyle(Palette.ivory).offset(x: -12, y: 12) }
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
