import SwiftUI

struct GuidedCaptureView: View {
    @ObservedObject var camera: CaptureCamera
    var showsDiagnostics = false
    var body: some View {
        CaptureGuideView(guidance: camera.guidance, showsDiagnostics: showsDiagnostics) { CameraPreview(session: camera.session) }
    }
}

struct CaptureGuideView<Preview: View>: View {
    @Environment(\.dynamicTypeSize) private var textSize
    let guidance: CaptureGuidance
    var showsDiagnostics = false
    @ViewBuilder var preview: () -> Preview

    var body: some View {
        VStack(spacing: 20) {
            ZStack {
                preview()
                GeometryReader { geometry in
                    let width = geometry.size.width * 0.82
                    let height = geometry.size.height * 0.66
                    ZStack {
                        CaptureMask().fill(.black.opacity(0.38), style: FillStyle(eoFill: true))
                            .frame(width: geometry.size.width, height: geometry.size.height)
                        Ellipse().stroke(.white.opacity(0.35), lineWidth: 3).frame(width: width, height: height)
                        ForEach([false, true], id: \.self) { right in
                            DirectionArc(right: right)
                                .stroke(arcColor(right: right), style: StrokeStyle(lineWidth: 6, lineCap: .round))
                                .frame(width: width, height: height)
                        }
                        if guidance.confirmedPose != nil {
                            Image(systemName: "checkmark.circle.fill").font(.largeTitle).foregroundStyle(.green)
                        } else if guidance.pose != .front {
                            Image(systemName: guidance.pose == .side ? "arrow.right" : "arrow.left")
                                .font(.title.bold()).foregroundStyle(.white)
                                .offset(x: guidance.pose == .side ? width * 0.34 : -width * 0.34)
                        }
                    }.frame(width: geometry.size.width, height: geometry.size.height)
                }.allowsHitTesting(false).accessibilityHidden(true)
                VStack {
                    Text("Bild \(guidance.confirmedPose == nil ? min(3, guidance.completed + 1) : guidance.completed) av 3").font(.subheadline.monospacedDigit().weight(.medium))
                        .padding(.horizontal, 14).padding(.vertical, 8).background(.black.opacity(0.45), in: Capsule())
                    if showsDiagnostics {
                        HStack(spacing: 10) {
                            check("Avstånd", guidance.distanceOK)
                            check("Centrering", guidance.centered)
                            check("Vinkel", guidance.angleOK)
                            check("Bild", guidance.qualityOK)
                        }.padding(8).background(.black.opacity(0.8), in: RoundedRectangle(cornerRadius: 12))
                    }
                    Spacer()
                    if !textSize.isAccessibilitySize {
                    Text(guidance.hint).font(.subheadline.weight(.semibold))
                        .multilineTextAlignment(.center).padding(10).frame(maxWidth: .infinity)
                        .background(.black.opacity(0.8), in: RoundedRectangle(cornerRadius: 12))
                        .accessibilityIdentifier("capture.instruction")
                        .padding(8)
                    }
                }.foregroundStyle(.white).padding(.top, 20)
            }
            .aspectRatio(9.0 / 16, contentMode: .fit).frame(maxWidth: 260)
            .background(Palette.cardStart).clipShape(RoundedRectangle(cornerRadius: 28))
            .accessibilityElement(children: .contain).accessibilityLabel("Fotografering")
            .accessibilityValue("\(guidance.completed) av 3 bilder tagna").accessibilityIdentifier("capture.ring")
            if textSize.isAccessibilitySize {
                Text(guidance.hint).font(.headline).multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true).accessibilityIdentifier("capture.instruction")
            }
        }.frame(maxWidth: .infinity)
            .onChange(of: guidance.hint) { hint in
                if UIAccessibility.isVoiceOverRunning {
                    UIAccessibility.post(notification: .announcement, argument: hint)
                }
            }
    }

    private func arcColor(right: Bool) -> Color {
        let pose = guidance.confirmedPose ?? guidance.pose
        let active = pose == .front || (right ? pose == .side : pose == .opposite)
        return active ? (guidance.confirmedPose == nil ? Color.purple : Color.green) : .white.opacity(0.18)
    }

    private func check(_ title: String, _ ready: Bool) -> some View {
        VStack(spacing: 4) {
            Image(systemName: ready ? "checkmark.circle.fill" : "circle.dashed")
                .foregroundStyle(ready ? Palette.mint : Color.white.opacity(0.7))
            Text(title).font(.caption2)
        }.accessibilityElement(children: .ignore)
            .accessibilityLabel("\(title): \(ready ? "bra" : "behöver justeras")")
    }
}

private struct CaptureMask: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path(rect)
        path.addEllipse(in: CGRect(x: rect.width * 0.09, y: rect.height * 0.17,
                                  width: rect.width * 0.82, height: rect.height * 0.66))
        return path
    }
}

private struct DirectionArc: Shape {
    let right: Bool
    func path(in rect: CGRect) -> Path {
        var path = Path()
        // Two half-ellipses with small gaps at top and bottom.
        let start = right ? -82.0 : 98.0
        for index in 0...80 {
            let angle = (start + Double(index) * 164 / 80) * .pi / 180
            let point = CGPoint(x: rect.midX + rect.width / 2 * CGFloat(Darwin.cos(angle)),
                                y: rect.midY + rect.height / 2 * CGFloat(Darwin.sin(angle)))
            if index == 0 { path.move(to: point) } else { path.addLine(to: point) }
        }
        return path
    }
}
