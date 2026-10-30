import SwiftUI

struct GuidedCaptureView: View {
    @ObservedObject var camera: CaptureCamera
    var showsDiagnostics = false
    var body: some View {
        CaptureGuideView(guidance: camera.guidance, showsDiagnostics: showsDiagnostics) { CameraPreview(session: camera.session) }
    }
}

struct CaptureGuideView<Preview: View>: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let guidance: CaptureGuidance
    var showsDiagnostics = false
    @ViewBuilder var preview: () -> Preview

    var body: some View {
        VStack(spacing: 16) {
            ZStack {
                preview()
                GeometryReader { geometry in
                    let oval = CGRect(x: geometry.size.width * 0.09, y: geometry.size.height * 0.17,
                                      width: geometry.size.width * 0.82, height: geometry.size.height * 0.66)
                    CaptureMask().fill(.black.opacity(0.42), style: FillStyle(eoFill: true))
                    ForEach(0..<72, id: \.self) { index in
                        OvalSegment(index: index, oval: oval)
                            .stroke(segmentColor(index), style: StrokeStyle(lineWidth: 3, lineCap: .round))
                    }
                    .animation(reduceMotion ? nil : .easeOut(duration: 0.12), value: guidance.proximity)
                }.allowsHitTesting(false).accessibilityHidden(true)
                VStack {
                    Label(guidance.completed == 3 ? "Tre bilder tagna" : "Automatiskt", systemImage: "camera.fill")
                        .font(.caption.weight(.semibold)).lineLimit(1).minimumScaleFactor(0.7).padding(10)
                        .background(.black.opacity(0.65), in: Capsule())
                    Spacer()
                    if guidance.confirmedPose != nil {
                        Image(systemName: "checkmark.circle.fill").font(.system(size: 40))
                            .foregroundStyle(.green).padding(.bottom, 16).accessibilityHidden(true)
                    }
                    if showsDiagnostics {
                        HStack(spacing: 12) {
                            check("Avstånd", guidance.distanceOK)
                            check("Mitten", guidance.centered)
                            check("Vinkel", guidance.angleOK)
                            check("Bild", guidance.qualityOK)
                        }.padding(10).background(.black.opacity(0.8), in: RoundedRectangle(cornerRadius: 12))
                    }
                }.foregroundStyle(.white).padding(16)
            }
            // Preserve the complete portrait image, while reserving room for the instruction on short phones.
            .aspectRatio(9.0 / 16, contentMode: .fit)
            .frame(maxWidth: min(300, max(170, (UIScreen.main.bounds.height - 330) * 9 / 16)))
            .background(Palette.ink).clipShape(RoundedRectangle(cornerRadius: 28))
            .accessibilityElement(children: .ignore).accessibilityLabel("Fotografering")
            .accessibilityValue("\(guidance.completed) av 3 bilder tagna").accessibilityIdentifier("capture.ring")

            Text(guidance.hint).font(.headline).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true).accessibilityIdentifier("capture.instruction")
            HStack(spacing: 12) {
                ForEach(guidance.sequence, id: \.self) { pose in
                    let done = guidance.completedPoses.contains(pose)
                    Label(pose.shortTitle, systemImage: done ? "checkmark.circle.fill" : "circle")
                        .font(.caption.weight(pose == guidance.pose ? .bold : .regular))
                        .foregroundStyle(done ? Color.green : Palette.ink)
                        .accessibilityLabel("\(pose.shortTitle): \(done ? "bild tagen" : "återstår")")
                }
            }.accessibilityIdentifier("capture.steps")
        }.frame(maxWidth: .infinity)
            .onChange(of: guidance.hint) { hint in
                if UIAccessibility.isVoiceOverRunning { UIAccessibility.post(notification: .announcement, argument: hint) }
            }
    }

    private func segmentColor(_ index: Int) -> Color {
        let pose = OvalSegment.pose(for: index)
        if guidance.completedPoses.contains(pose) { return .green }
        guard guidance.completed < 3, guidance.pose == pose else { return .white.opacity(0.30) }
        let indices = (0..<72).filter { OvalSegment.pose(for: $0) == pose }
        let position = indices.firstIndex(of: index) ?? 0
        guard Double(position + 1) / Double(indices.count) <= guidance.proximity else { return .white.opacity(0.45) }
        // Amber means geometry is close but image quality still needs attention.
        return guidance.acceptable ? .green : .orange
    }
    private func check(_ title: String, _ ready: Bool) -> some View {
        VStack(spacing: 4) {
            Image(systemName: ready ? "checkmark.circle.fill" : "circle.dashed")
                .foregroundStyle(ready ? Palette.mint : Color.white.opacity(0.7))
            Text(title).font(.caption2)
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
private struct OvalSegment: Shape {
    let index: Int
    let oval: CGRect
    static func pose(for index: Int) -> CapturePose {
        if (6..<30).contains(index) { return .side }
        if (42..<66).contains(index) { return .opposite }
        return .front
    }
    func path(in rect: CGRect) -> Path {
        let angle = (Double(index) * 5 - 90) * .pi / 180
        let x = CGFloat(cos(angle)), y = CGFloat(sin(angle))
        var path = Path()
        path.move(to: CGPoint(x: oval.midX + x * oval.width / 2, y: oval.midY + y * oval.height / 2))
        path.addLine(to: CGPoint(x: oval.midX + x * (oval.width / 2 + 9), y: oval.midY + y * (oval.height / 2 + 9)))
        return path
    }
}

struct CaptureIntroduction: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var turned = false
    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "person.crop.circle")
                .font(.system(size: 64, weight: .light))
                .rotation3DEffect(.degrees(reduceMotion ? 0 : (turned ? 25 : -25)), axis: (x: 0, y: 1, z: 0))
                .accessibilityHidden(true)
            Text("Vi tar tre bilder automatiskt").font(.title3.bold())
            Text("Titta mot kameran och vrid huvudet lite åt båda hållen i den ordning som visas. Strecken visar hur nära rätt position du är.")
                .font(.subheadline).multilineTextAlignment(.center)
        }.onAppear {
            guard !reduceMotion else { return }
            withAnimation(.easeInOut(duration: 1.4).repeatForever(autoreverses: true)) { turned = true }
        }
    }
}
