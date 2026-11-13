import SwiftUI
import UIKit

extension TjippColor {
    var appIconName: String? { self == .hav ? nil : "AppIcon-" + rawValue }
}

@MainActor final class AppIconController: ObservableObject {
    @Published private(set) var changing = false
    @Published private(set) var error: String?
    private var desired: TjippColor = .hav
    var currentColor: TjippColor {
        TjippColor.allCases.first { $0.appIconName == UIApplication.shared.alternateIconName } ?? .hav
    }
    func update(for color: TjippColor) {
        desired = color
        applyIfNeeded()
    }
    private func applyIfNeeded() {
        #if DEBUG && targetEnvironment(simulator)
        let environment = ProcessInfo.processInfo.environment
        if environment["TJIPP_TEST_ICON_CHANGES"] != "1" &&
            (environment["TJIPP_DISABLE_ICON_CHANGES"] == "1" || environment["XCTestConfigurationFilePath"] != nil) { return }
        #endif
        let application = UIApplication.shared
        guard application.applicationState == .active, application.supportsAlternateIcons, !changing else { return }
        guard application.alternateIconName != desired.appIconName else { error = nil; return }
        let requested = desired
        changing = true; error = nil
        application.setAlternateIconName(requested.appIconName) { [weak self] error in
            Task { @MainActor in
                guard let self else { return }
                self.changing = false
                self.error = error == nil ? nil : "Appikonen kunde inte bytas. Välj färgen igen för att försöka på nytt."
                if error == nil && self.desired != requested { self.applyIfNeeded() }
            }
        }
    }
}
