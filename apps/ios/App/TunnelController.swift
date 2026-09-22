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
    private let logger = Logger(subsystem: AppConfig.subsystem, category: "app")
    private var tunnelError: String?
    /// The state directory belongs to the tunnel from Connect until the
    /// tunnel is off again: status notifications that arrive late (from
    /// saving the configuration) must not start the app's engine in between.
    private var handedOver = false

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
            logger.warning("VPN configurations: \(error.localizedDescription, privacy: .public)")
            vpn = .unavailable(error.localizedDescription)
        }
        update()
    }

    func takeTunnelError() -> String? {
        defer { tunnelError = nil }
        return tunnelError
    }

    /// The tunnel ended without the user: find out why (the extension's own
    /// words first, else what iOS reports).
    private func collectTunnelError() {
        if let f = AppConfig.tunnelErrorFile, let d = try? Data(contentsOf: f), let s = String(data: d, encoding: .utf8), !s.isEmpty {
            try? FileManager.default.removeItem(at: f)
            tunnelError = s
            logger.error("tunnel ended: \(s, privacy: .public)")
            return
        }
        manager?.connection.fetchLastDisconnectError { [weak self] err in
            guard let err = err as NSError? else { return }
            let under = (err.userInfo[NSUnderlyingErrorKey] as? NSError)?.localizedDescription
            Task { @MainActor in
                self?.tunnelError = under ?? err.localizedDescription
                self?.logger.error("tunnel ended: \(self?.tunnelError ?? "", privacy: .public)")
            }
        }
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
        let ended = vpn == .off && (before == .connecting || before == .on || before == .disconnecting)
        if ended, !userStopped {
            collectTunnelError()
        }
        if ended {
            handedOver = false
            userStopped = false
        }
        if handedOver { return }
        if vpn == .off || { if case .unavailable = vpn { return true }; return false }() {
            if local == nil { startLocal(retries: ended ? 20 : 0) }
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
            logger.error("engine: \(error.localizedDescription, privacy: .public)")
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
        handedOver = true
        local?.stop()
        local = nil
        do {
            try m.connection.startVPNTunnel()
        } catch {
            handedOver = false
            startLocal(retries: 0)
            throw error
        }
        update()
    }

    private var userStopped = false

    func disconnect() {
        userStopped = true
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
