#if DEBUG && targetEnvironment(simulator)
import SwiftUI

struct CapturePreviewFixture: View {
    @State private var guidance = CaptureGuidance(holdProgress: 0.55, acceptable: true, hint: "Håll kvar")
    var body: some View {
        NavigationStack {
            ScrollView {
                CaptureGuideView(guidance: guidance) {
                    ZStack {
                        LinearGradient(colors: [Palette.ink, Palette.muted], startPoint: .topLeading, endPoint: .bottomTrailing)
                        Image(systemName: "person.fill").resizable().scaledToFit().foregroundStyle(.white.opacity(0.45))
                            .frame(width: 180).offset(y: 36)
                    }
                }.padding(24)
            }.background(Palette.paper).navigationTitle("Förhandsvisa kameran").navigationBarTitleDisplayMode(.inline)
                .safeAreaInset(edge: .bottom) {
                    HStack {
                        Button("Nästa position") {
                            let next = min(2, guidance.completed + 1)
                            guidance = CaptureGuidance(pose: CapturePose(rawValue: next)!, completed: next,
                                holdProgress: 0.55, acceptable: true, hint: "Håll kvar")
                        }.accessibilityIdentifier("capture.preview.next")
                        Spacer()
                        Button("Simulera saknat ansikte") {
                            guidance.holdProgress = 0; guidance.acceptable = false; guidance.hint = "Placera ansiktet i ovalen"
                        }.accessibilityIdentifier("capture.preview.missing")
                    }.font(.caption).padding().background(Palette.paper)
                }
        }
    }
}
#endif
