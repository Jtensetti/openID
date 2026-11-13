import SwiftUI
import UIKit

extension TjippColor {
    var appIconName: String? { self == .hav ? nil : "AppIcon-" + rawValue }
}

@MainActor final class AppIconController: ObservableObject {
    @Published private(set) var changing = false
    @Published private(set) var error: String?
    @Published private(set) var currentColor: TjippColor
    private var desired: TjippColor = .hav
    init() {
        let currentName = UIApplication.shared.alternateIconName
        currentColor = TjippColor.allCases.first { $0.appIconName == currentName } ?? .hav
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
        guard currentColor != desired else { error = nil; return }
        let requested = desired
        changing = true; error = nil
        application.setAlternateIconName(requested.appIconName) { [weak self] error in
            Task { @MainActor in
                guard let self else { return }
                // Reading alternateIconName while iOS presents its confirmation can block
                // the main thread. Publish the completed change instead of querying in View.body.
                if error == nil { self.currentColor = requested }
                self.changing = false
                self.error = error == nil ? nil : "Appikonen kunde inte bytas. Välj färgen igen för att försöka på nytt."
                if error == nil && self.desired != requested { self.applyIfNeeded() }
            }
        }
    }
}
