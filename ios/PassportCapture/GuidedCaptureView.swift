import SwiftUI

struct GuidedCaptureView: View {
    @ObservedObject var camera: CaptureCamera
    var body: some View {
        CaptureGuideView(guidance: camera.guidance) { CameraPreview(session: camera.session) }
    }
}

struct CaptureGuideView<Preview: View>: View {
    let guidance: CaptureGuidance
    @ViewBuilder var preview: () -> Preview
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

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
                        Ellipse().trim(from: 0, to: guidance.progress)
                            .stroke(Palette.mint, style: StrokeStyle(lineWidth: 6, lineCap: .round))
                            .frame(width: height, height: width).rotationEffect(.degrees(-90))
                            .frame(width: width, height: height)
                            .animation(reduceMotion ? nil : .linear(duration: 0.12), value: guidance.progress)
                        if guidance.acceptable {
                            Ellipse().stroke(Palette.mint.opacity(0.45), lineWidth: 2)
                                .frame(width: width - 12, height: height - 12)
                        }
                    }.frame(width: geometry.size.width, height: geometry.size.height)
                }.allowsHitTesting(false).accessibilityHidden(true)
                VStack {
                    Text("\(min(3, guidance.completed + 1)) av 3").font(.subheadline.monospacedDigit().weight(.medium))
                        .padding(.horizontal, 14).padding(.vertical, 8).background(.black.opacity(0.45), in: Capsule())
                    Spacer()
                }.foregroundStyle(.white).padding(.top, 20)
            }
            .aspectRatio(9.0 / 16, contentMode: .fit).frame(maxWidth: 260)
            .background(Palette.ink).clipShape(RoundedRectangle(cornerRadius: 28))
            .accessibilityElement(children: .ignore).accessibilityLabel("Kamerafångst")
            .accessibilityValue("\(guidance.completed) av 3 bilder tagna").accessibilityIdentifier("capture.ring")
            VStack(spacing: 8) {
                Text(guidance.pose.title).font(.title3.weight(.semibold)).accessibilityIdentifier("capture.instruction")
                Text(guidance.hint).font(.subheadline).foregroundStyle(Palette.muted).accessibilityIdentifier("capture.hint")
            }.multilineTextAlignment(.center)
            HStack(spacing: 14) {
                ForEach(CapturePose.allCases, id: \.rawValue) { pose in
                    Label(pose.shortTitle, systemImage: pose.rawValue < guidance.completed ? "checkmark.circle.fill" : "circle")
                        .font(.caption).foregroundStyle(pose.rawValue <= guidance.completed ? Palette.ink : Palette.muted)
                }
            }.accessibilityElement(children: .combine)
        }.frame(maxWidth: .infinity)
            .onChange(of: guidance.hint) { hint in
                if UIAccessibility.isVoiceOverRunning {
                    UIAccessibility.post(notification: .announcement, argument: hint)
                }
            }
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
