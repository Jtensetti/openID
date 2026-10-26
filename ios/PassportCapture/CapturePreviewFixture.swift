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
/// Only renders the real decision view with synthetic data; no identity or server connection is created.
struct ApprovalPreviewFixture: View {
    private let arguments = ProcessInfo.processInfo.arguments
    @State private var expiresAt = Date().timeIntervalSince1970 + 120
    var body: some View {
        NavigationStack {
            ApprovalView(request: WalletRequest(id: String(repeating: "a", count: 64),
                relyingParty: "Syntetisk testtjänst", purpose: "Kontrollera en begäran utan att legitimera någon.",
                code: "012345", expiresAt: arguments.contains("--expired") ? 0 : expiresAt,
                signMessage: arguments.contains("--sign") ? String(repeating: "Detta är en syntetisk underskrift utan rättslig verkan.\n", count: 6) : nil,
                verification: arguments.contains("--pin") ? "pin" : nil))
        }.environment(\.dynamicTypeSize, arguments.contains("--largest-text") ? .accessibility5 : .large)
    }
}
#endif
