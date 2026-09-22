#if os(iOS)
import Foundation
import SwiftUI
import BoundGateKit

/// The system VPN (NETunnelProviderManager) as the iOS app sees it.
public enum VPNState: Equatable, Sendable {
    case off, connecting, on, disconnecting
    case unavailable(String)
}

/// What the app target provides: the packet tunnel and the node to talk to.
/// While the tunnel is off the app runs the node itself (status, enrollment);
/// while it is on, the node runs in the extension and requests go there as
/// provider messages (docs/EMBED.md, "One engine per state directory").
@MainActor
public protocol TunnelControl: AnyObject {
    var vpn: VPNState { get }
    /// nil while no engine answers (engineError says why)
    var client: DaemonClient? { get }
    var engineError: String? { get }
    /// why the tunnel ended on its own the last time, once (then it is cleared)
    func takeTunnelError() -> String?
    /// memory of the packet tunnel process in MiB (footprint, what iOS limits to 50), while it runs
    func tunnelMemory() async -> Double?
    func connect() async throws
    func disconnect()
}

/// What the screen shows, like Phase on the Mac without the service states.
public enum MobilePhase: Equatable {
    case noEngine(String)
    case unconfigured, needsEnroll, pending, revoked
    case ready, connecting, loginRequired, connected
}

@MainActor
public final class MobileModel: ObservableObject {
    @Published public var status: NodeStatus?
    @Published public var busy: String?
    @Published public var actionError: String?
    @Published public var pinToConfirm: String?
    @Published public var loginInProgress = false
    @Published public var rate: Traffic.Rate?
    @Published public var memoryMiB: Double?
    @Published public private(set) var vpn: VPNState = .off
    /// why no engine answers; published so that the screen follows it
    @Published public private(set) var engineError: String?
    public var openURL: ((URL) -> Void)?

    let tunnel: TunnelControl
    private var timer: Timer?
    private var lastTraffic: Traffic.Reading?

    public init(tunnel: TunnelControl) { self.tunnel = tunnel }

    public func start() {
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in Task { @MainActor in self?.refresh() } }
    }

    public var phase: MobilePhase {
        guard let s = status else { return .noEngine(engineError ?? "Starting…") }
        if s.state == "unconfigured" { return .unconfigured }
        switch s.enrollment ?? "unknown" {
        case "approved": break
        case "pending", "confirmed": return .pending
        case "revoked": return .revoked
        default: return .needsEnroll
        }
        switch vpn {
        case .off, .unavailable: return .ready
        case .connecting, .disconnecting: return .connecting
        case .on: break
        }
        if s.hubs?.contains(where: \.connected) == true { return .connected }
        if s.loginRequired == true { return .loginRequired }
        return .connecting
    }

    public func refresh() {
        vpn = tunnel.vpn
        engineError = tunnel.engineError
        if let e = tunnel.takeTunnelError() { actionError = "The tunnel stopped: \(e)" }
        guard let client = tunnel.client else { status = nil; return }
        let on = vpn == .on
        Task.detached {
            let result = Result { try client.status() }
            let mem = on ? await self.tunnel.tunnelMemory() : nil
            await MainActor.run {
                switch result {
                case .success(let s): self.status = s
                case .failure(let e):
                    // the extension is starting or stopping: keep the last picture for a moment
                    if !on { self.status = nil }
                    if case DaemonError.unreachable = e {} else { self.actionError = e.localizedDescription }
                }
                self.memoryMiB = mem
                let now = Traffic.Reading(status: self.status, at: Date())
                self.rate = Traffic.rate(from: self.lastTraffic, to: now)
                self.lastTraffic = now
            }
        }
    }

    // MARK: actions

    private func run(_ label: String, _ work: @escaping @Sendable (DaemonClient) throws -> Void) {
        guard busy == nil, let client = tunnel.client else { return }
        busy = label; actionError = nil
        Task.detached {
            let result = Result { try work(client) }
            await MainActor.run {
                self.busy = nil
                if case .failure(let e) = result {
                    if case DaemonError.pinUnconfirmed(let fp) = e { self.pinToConfirm = fp } else { self.actionError = e.localizedDescription }
                }
                self.refresh()
            }
        }
    }

    public func configure(control: String, name: String) {
        run("Saving") { try $0.configure(DaemonSettings(controlAddr: control, name: name.isEmpty ? nil : name)) }
    }

    public func enroll(acceptPin: String? = nil) {
        pinToConfirm = nil
        run("Requesting access") { _ = try $0.enroll(acceptPin: acceptPin) }
    }

    public func declinePin() { pinToConfirm = nil }

    public func connect() {
        guard busy == nil else { return }
        busy = "Connecting"; actionError = nil
        Task {
            do { try await tunnel.connect() } catch { actionError = error.localizedDescription }
            busy = nil
            refresh()
        }
    }

    public func disconnect() {
        tunnel.disconnect()
        refresh()
    }

    public func signIn() {
        guard busy == nil, let client = tunnel.client else { return }
        busy = "Signing in"; actionError = nil
        Task.detached {
            let result = Result { try client.login() }
            await MainActor.run {
                self.busy = nil
                switch result {
                case .failure(let e): self.actionError = e.localizedDescription
                case .success(let start):
                    guard let url = URL(string: start.url), url.scheme == "https" || url.scheme == "http" else {
                        self.actionError = "The control plane sent no usable sign-in address."; return
                    }
                    self.loginInProgress = true
                    self.openURL?(url)
                    self.waitForLogin(flow: start.flowId, client: client)
                }
            }
        }
    }

    private func waitForLogin(flow: String, client: DaemonClient) {
        Task.detached {
            var outcome: Result<LoginResult, Error> = .failure(DaemonError.refused("the sign-in took too long"))
            for _ in 0..<12 { // up to ~5 minutes, 25 s per long poll
                outcome = Result { try client.loginWait(flow: flow) }
                if case .success(let r) = outcome, r.status == "pending" { continue }
                break
            }
            let final = outcome
            await MainActor.run {
                self.loginInProgress = false
                switch final {
                case .success(let r) where r.status == "failed": self.actionError = r.error ?? "The sign-in failed."
                case .failure(let e): self.actionError = e.localizedDescription
                default: break
                }
                self.refresh()
            }
        }
    }

    public func signOut() { run("Signing out") { _ = try $0.logout() } }

    /// Forgets the control plane; the device key stays.
    public func forget() {
        tunnel.disconnect()
        run("Forgetting") { try $0.reset() }
    }
}
#endif
