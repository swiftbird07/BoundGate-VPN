#if os(macOS)
import Foundation
import ServiceManagement
import AppKit

/// The background service: boundgate-node as a LaunchDaemon that ships inside
/// the app bundle (Contents/Library/LaunchDaemons) and is registered through
/// SMAppService. macOS asks the user to allow it under
/// System Settings > General > Login Items & Extensions.
public enum ServiceState: Equatable, Sendable {
    case notRegistered, requiresApproval, enabled
    case unavailable(String)  // not running from an app bundle, plist missing, unsigned
}

public protocol ServiceControlling: Sendable {
    func state() -> ServiceState
    func register() throws
    func unregister() throws
    func openApprovalSettings()
}

public struct LaunchDaemonService: ServiceControlling {
    /// The plist is named after its Label, <bundle id>.node (build-app.sh).
    public static var plistName: String { (Bundle.main.bundleIdentifier ?? "com.boundgate") + ".node.plist" }
    public init() {}

    private var service: SMAppService { SMAppService.daemon(plistName: Self.plistName) }

    public func state() -> ServiceState {
        guard Bundle.main.bundleURL.pathExtension == "app" else { return .unavailable("not running from BoundGate.app") }
        switch service.status {
        case .notRegistered: return .notRegistered
        case .requiresApproval: return .requiresApproval
        case .enabled: return .enabled
        // A daemon that was never registered is reported as notFound on
        // macOS 14/15/26, not as notRegistered; registering creates the
        // entry. A really missing plist surfaces from register() instead.
        case .notFound: return .notRegistered
        @unknown default: return .unavailable("unknown service state")
        }
    }

    public func register() throws { try service.register() }
    public func unregister() throws { try service.unregister() }
    public func openApprovalSettings() { SMAppService.openSystemSettingsLoginItems() }
}
#endif
