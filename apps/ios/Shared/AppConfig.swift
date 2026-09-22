import Foundation

/// Identifiers shared by the app and its packet tunnel. They come from the
/// Info.plist (build settings in project.yml), so one place names them.
enum AppConfig {
    static let subsystem = Bundle.main.bundleIdentifier ?? "boundgate"

    /// the app group both share: the node's state directory lives in it
    static var appGroup: String { value("BGAppGroup") }
    /// the keychain access group the device key lives in (team prefix included)
    static var keychainGroup: String { value("BGKeychainGroup") }
    /// bundle identifier of the packet tunnel extension
    static var tunnelBundleID: String { value("BGTunnelBundleID") }

    static func stateDir() throws -> URL {
        guard let c = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) else {
            throw CoreError("the app group \(appGroup) is not available: the app is not signed with its entitlement")
        }
        return c.appendingPathComponent("boundgate", isDirectory: true)
    }

    /// Why the packet tunnel last ended on its own: the extension writes it,
    /// the app shows it (iOS passes the provider's error on only as a generic
    /// "the VPN session failed").
    static var tunnelErrorFile: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)?.appendingPathComponent("tunnel-error.txt")
    }

    /// embed.Config (docs/EMBED.md)
    static func engineConfig(autoUp: Bool, memoryLimitMiB: Int) throws -> [String: Any] {
        var c: [String: Any] = ["state_dir": try stateDir().path, "platform": "ios", "name": deviceName, "auto_up": autoUp, "log_level": "info"]
        if memoryLimitMiB > 0 { c["memory_limit_mib"] = memoryLimitMiB }
        return c
    }

    static var deviceName: String {
        #if canImport(UIKit) && !targetEnvironment(macCatalyst)
        // "Martins-iPhone.local": the name the user gave the phone, as a host name
        let h = ProcessInfo.processInfo.hostName
        return h.hasSuffix(".local") ? String(h.dropLast(6)) : h
        #else
        return Host.current().localizedName ?? ProcessInfo.processInfo.hostName
        #endif
    }

    private static func value(_ key: String) -> String {
        (Bundle.main.object(forInfoDictionaryKey: key) as? String) ?? ""
    }
}

struct CoreError: LocalizedError {
    let message: String
    init(_ m: String) { message = m }
    var errorDescription: String? { message }
}
