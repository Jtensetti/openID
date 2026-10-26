import Foundation

struct AppBuild {
    let version: String
    let number: String
    static var current: AppBuild {
        AppBuild(version: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "–",
                 number: Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "–")
    }
    var display: String { "\(version) (\(number))" }
}
