import Foundation
import NetworkExtension
import os
import BoundGateKit
import BoundGateUI

/// The app's side of the tunnel. While the VPN is off the app runs the node
/// itself (it can show status, enroll and forget, not route); while it is
/// on, the node runs in the packet tunnel and requests go there. Only one of
/// them holds the state directory (docs/EMBED.md).
@MainActor
final class TunnelController: ObservableObject, TunnelControl {
    @Published private(set) var vpn: VPNState = .off
    @Published private(set) var engineError: String?

    private var manager: NETunnelProviderManager?
    private var local: CoreEngine?
    private let platform = AppPlatform()
    private var observer: NSObjectProtocol?

    var client: DaemonClient? {
        switch vpn {
        case .on, .connecting, .disconnecting:
            guard let session = manager?.connection as? NETunnelProviderSession else { return nil }
            return DaemonClient(transport: ProviderTransport(session: session))
        case .off, .unavailable:
            return local.map { DaemonClient(transport: $0) }
        }
    }

    init() {
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.update() }
        }
        Task { await load() }
    }

    private func load() async {
        do {
            manager = try await NETunnelProviderManager.loadAllFromPreferences().first
        } catch {
            vpn = .unavailable(error.localizedDescription)
        }
        update()
    }

    private func update() {
        let before = vpn
        switch manager?.connection.status {
        case .connected: vpn = .on
        case .connecting, .reasserting: vpn = .connecting
        case .disconnecting: vpn = .disconnecting
        case .invalid, .disconnected, .none: if case .unavailable = vpn {} else { vpn = .off }
        @unknown default: vpn = .off
        }
        if vpn == .off || { if case .unavailable = vpn { return true }; return false }() {
            if local == nil { startLocal(retries: before == .off ? 0 : 20) }
        }
    }

    /// The tunnel may still hold the state directory for a moment after it stopped.
    private func startLocal(retries: Int) {
        do {
            let key = try DeviceKey.load(create: true)
            local = try CoreEngine(config: try AppConfig.engineConfig(autoUp: false, memoryLimitMiB: 0), platform: platform, key: key)
            engineError = nil
        } catch {
            engineError = error.localizedDescription
            if retries > 0, error.localizedDescription.hasPrefix("embed: busy") {
                Task { try? await Task.sleep(nanoseconds: 500_000_000); if self.local == nil { self.startLocal(retries: retries - 1) } }
            }
        }
    }

    func connect() async throws {
        let m = manager ?? NETunnelProviderManager()
        let proto = (m.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppConfig.tunnelBundleID
        if let s = try? client?.status(), let c = s.control { proto.serverAddress = c } else if proto.serverAddress == nil { proto.serverAddress = "BoundGate" }
        m.protocolConfiguration = proto
        m.localizedDescription = "BoundGate"
        m.isEnabled = true
        try await m.saveToPreferences() // the first time, iOS asks the user to allow the VPN configuration
        try await m.loadFromPreferences()
        manager = m
        // hand the state directory to the tunnel
        local?.stop()
        local = nil
        do {
            try m.connection.startVPNTunnel()
        } catch {
            startLocal(retries: 0)
            throw error
        }
        update()
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    func tunnelMemory() async -> Double? {
        guard let session = manager?.connection as? NETunnelProviderSession, vpn == .on else { return nil }
        let t = ProviderTransport(session: session)
        return await Task.detached {
            guard let (code, body) = try? t.request(method: "GET", path: "/x/memory", body: nil, timeout: 5), code == 200,
                  let m = try? JSONDecoder().decode(TunnelMemory.self, from: body) else { return nil }
            return m.footprintMiB
        }.value
    }
}

/// The app's own node cannot route: bringing the overlay up is the tunnel's job.
final class AppPlatform: CorePlatform {
    private let logger = Logger(subsystem: AppConfig.subsystem, category: "core")
    func apply(settingsJSON: String) throws -> Int32 { throw CoreError("the tunnel runs in the VPN extension: use Connect") }
    func releaseTunnel() {}
    func log(level: Int32, line: String) { logger.log(level: level >= 8 ? .error : level >= 4 ? .default : .info, "\(line, privacy: .public)") }
}

/// Requests of the daemon's API as provider messages to the running tunnel.
struct ProviderTransport: NodeTransport, @unchecked Sendable {
    let session: NETunnelProviderSession

    func request(method: String, path: String, body: Data?, timeout: Int) throws -> (status: Int, body: Data) {
        let msg = try JSONEncoder().encode(AppMessage(method: method, path: path, body: body))
        let done = DispatchSemaphore(value: 0)
        var answer: Data?
        do {
            try session.sendProviderMessage(msg) { answer = $0; done.signal() }
        } catch {
            throw DaemonError.unreachable("The tunnel is not running (\(error.localizedDescription)).")
        }
        if done.wait(timeout: .now() + .seconds(timeout)) == .timedOut {
            throw DaemonError.unreachable("The tunnel did not answer in time.")
        }
        guard let answer, let reply = try? JSONDecoder().decode(AppReply.self, from: answer) else {
            throw DaemonError.unreachable("The tunnel is not running.")
        }
        return (reply.status, reply.body)
    }
}
