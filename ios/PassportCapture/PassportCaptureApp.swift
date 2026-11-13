import SwiftUI

@main struct PassportCaptureApp: App {
    @StateObject private var model = WalletModel()
    @Environment(\.scenePhase) private var phase
    var body: some Scene {
        WindowGroup {
            Group {
                #if DEBUG && targetEnvironment(simulator)
                if ProcessInfo.processInfo.arguments.contains("--recovery-preview") || ProcessInfo.processInfo.arguments.contains("--design-preview") {
                    RecoveryPreviewFixture()
                } else if ProcessInfo.processInfo.arguments.contains("--passport-guide-preview") {
                    PassportGuidePreviewFixture()
                } else if ProcessInfo.processInfo.arguments.contains("--capture-guide-preview") {
                    CapturePreviewFixture()
                } else if ProcessInfo.processInfo.arguments.contains("--usability-preview") {
                    UsabilityPreviewFixture()
                } else if ProcessInfo.processInfo.arguments.contains("--approval-preview") {
                    ApprovalPreviewFixture()
                } else if ProcessInfo.processInfo.arguments.contains("--large-text-preview") {
                    WalletRootView().environment(\.dynamicTypeSize, .accessibility5)
                } else {
                    WalletRootView()
                }
                #else
                WalletRootView()
                #endif
            }.environmentObject(model).tjippTheme()
                .onOpenURL { model.open($0) }
                .onChange(of: phase) { value in
                    if value == .background { model.lock() }
                }
                // Cover app-switcher snapshots and interruptions without cancelling an active Face ID/NFC prompt.
                .overlay {
                    if phase != .active {
                        ZStack { Palette.paper.ignoresSafeArea(); VStack(spacing: 20) { TjippSymbol(size: 72); Text("Tjipp är låst").font(TjippLayout.title); Image(systemName: "lock").foregroundStyle(Palette.muted) } }
                    }
                }
        }
    }
}
