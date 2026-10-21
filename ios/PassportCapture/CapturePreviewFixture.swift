#if DEBUG && targetEnvironment(simulator)
import SwiftUI

struct CapturePreviewFixture: View {
    @State private var guidance = CaptureGuidance(hint: CapturePose.front.title)
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
                                hint: CapturePose(rawValue: next)!.title)
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
struct UsabilityPreviewFixture: View {
    @EnvironmentObject var model: WalletModel
    var body: some View {
        NavigationStack {
            List {
                Text("TESTDATA – inga riktiga ID")
                NavigationLink("Passformulär") { EnrollmentView(flow: model.verification) }
                NavigationLink("Kontrollkod med stor text") {
                    ScrollView {
                        ControlCodeView(code: "012345").padding(24)
                        Text("Kontrollera att samma sex siffror visas hos tjänsten.").padding()
                    }.environment(\.dynamicTypeSize, .accessibility5)
                }
                NavigationLink("Kameraguide med stor text") {
                    ScrollView {
                        CaptureGuideView(guidance: CaptureGuidance(hint: "Vrid huvudet lite åt höger")) { Color.gray }
                            .padding(24)
                    }.environment(\.dynamicTypeSize, .accessibility5)
                }
            }.navigationTitle("Tillgänglighetsprov")
        }
    }
}
#endif
