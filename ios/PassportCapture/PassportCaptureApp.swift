import SwiftUI

@main struct PassportCaptureApp: App {
    @StateObject private var model = WalletModel()
    @Environment(\.scenePhase) private var phase
    var body: some Scene {
        WindowGroup {
            Group {
                #if DEBUG && targetEnvironment(simulator)
                if ProcessInfo.processInfo.arguments.contains("--capture-guide-preview") {
                    CapturePreviewFixture()
                } else {
                    WalletRootView()
                }
                #else
                WalletRootView()
                #endif
            }.environmentObject(model)
                .onOpenURL { model.open($0) }
                .onChange(of: phase) { value in
                    if value == .background { model.lock() }
                }
                // Cover app-switcher snapshots and interruptions without cancelling an active Face ID/NFC prompt.
                .overlay {
                    if phase != .active {
                        ZStack { Palette.ink.ignoresSafeArea(); Label("openID", systemImage: "lock.shield").font(.largeTitle.bold()).foregroundStyle(Palette.mint) }
                    }
                }
        }
    }
}
