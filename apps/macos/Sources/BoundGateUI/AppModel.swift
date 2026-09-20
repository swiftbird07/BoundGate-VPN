import Foundation
import SwiftUI
import AppKit
import BoundGateKit

/// What the panel shows, derived from the service state and the daemon status.
public enum Phase: Equatable {
    case serviceMissing      // daemon not reachable and not installed
    case serviceApproval     // registered, waiting for the user in System Settings
    case serviceDown(String) // installed or external, but the socket does not answer
    case unconfigured        // daemon runs, no control plane yet
    case needsEnroll
    case pending             // enrolled, waiting for the admin (pending or confirmed)
    case revoked
    case ready               // approved, tunnel down
    case connecting
    case loginRequired       // tunnel up, hubs want a user session
    case connected
}

@MainActor
public final class AppModel: ObservableObject {
    @Published public var status: NodeStatus?
    @Published public var service: ServiceState = .notRegistered
    @Published public var unreachable: String?
    @Published public var busy: String?       // label of the action in flight
    @Published public var actionError: String?
    @Published public var profiles: [String] = []
    @Published public var profile: String = UserDefaults.standard.string(forKey: "profile") ?? "" {
        didSet { UserDefaults.standard.set(profile, forKey: "profile") }
    }
    @Published public var loginInProgress = false

    let client: DaemonClient
    let installer: ServiceControlling
    private var timer: Timer?

    public init(client: DaemonClient = DaemonClient(), installer: ServiceControlling = LaunchDaemonService()) {
        self.client = client
        self.installer = installer
    }

    public var phase: Phase {
        guard let s = status else {
            switch service {
            case .requiresApproval: return .serviceApproval
            case .enabled: return .serviceDown(unreachable ?? "The background service does not answer.")
            case .notRegistered, .unavailable: return unreachable == nil || isMissing ? .serviceMissing : .serviceDown(unreachable!)
            }
        }
        if s.state == "unconfigured" { return .unconfigured }
        switch s.enrollment ?? "unknown" {
        case "approved": break
        case "pending", "confirmed": return .pending
        case "revoked": return .revoked
        default: return .needsEnroll
        }
        switch s.state {
        case "starting": return .connecting
        case "up":
            if s.hubs?.contains(where: \.connected) == true { return .connected }
            if s.loginRequired == true { return .loginRequired }
            return .connecting
        default: return .ready
        }
    }

    private var isMissing: Bool { unreachable?.contains("not running") ?? true }

    public var needsAttention: Bool {
        switch phase { case .loginRequired, .pending, .needsEnroll, .unconfigured, .serviceApproval, .serviceMissing, .revoked: return true; default: return false }
    }
    public var isConnected: Bool { phase == .connected }

    // MARK: polling

    public func start() {
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in Task { @MainActor in self?.refresh() } }
    }

    public func refresh() {
        let client = self.client, installer = self.installer
        Task.detached {
            let svc = installer.state()
            let result = Result { try client.status() }
            let names = (try? client.profiles()) ?? []
            await MainActor.run {
                self.service = svc
                switch result {
                case .success(let s): self.status = s; self.unreachable = nil
                case .failure(let e): self.status = nil; self.unreachable = e.localizedDescription
                }
                if !names.isEmpty || self.status != nil { self.profiles = names }
            }
        }
    }

    // MARK: actions

    private func run(_ label: String, _ work: @escaping @Sendable (DaemonClient) throws -> Void, then: (@MainActor () -> Void)? = nil) {
        guard busy == nil else { return }
        busy = label; actionError = nil
        let client = self.client
        Task.detached {
            let result = Result { try work(client) }
            await MainActor.run {
                self.busy = nil
                if case .failure(let e) = result { self.actionError = e.localizedDescription }
                self.refresh()
                if case .success = result { then?() }
            }
        }
    }

    public func installService() {
        actionError = nil
        do { try installer.register() } catch {
            let e = error as NSError
            // SMAppServiceErrorDomain 1 (kSMErrorAlreadyRegistered / "Operation not permitted"):
            // the daemon waits for the user's consent in System Settings
            if e.domain == "SMAppServiceErrorDomain", e.code == 1, installer.state() == .requiresApproval {
                installer.openApprovalSettings()
            } else {
                actionError = "Could not register the background service: \(error.localizedDescription) (\(e.domain) \(e.code))"
            }
        }
        if installer.state() == .requiresApproval { installer.openApprovalSettings() }
        refresh()
    }

    public func uninstallService() {
        actionError = nil
        let installer = self.installer
        run("Removing…") { c in _ = try? c.down(); try installer.unregister() }
    }

    public func openApprovalSettings() { installer.openApprovalSettings() }

    public func configure(control: String) { run("Saving…") { try $0.configure(DaemonSettings(controlAddr: control)) } }
    public func forgetControlPlane() { run("Resetting…") { c in _ = try? c.down(); try c.reset() } }
    /// First contact with a control plane: the key it presents, waiting for
    /// the person to compare and accept it (EnrollCard).
    @Published public var pinToConfirm: String?

    public func enroll(acceptPin: String? = nil) {
        guard busy == nil else { return }
        busy = "Requesting access…"; actionError = nil
        let client = self.client
        Task.detached {
            let result = Result { try client.enroll(acceptPin: acceptPin) }
            await MainActor.run {
                self.busy = nil
                switch result {
                case .success: self.pinToConfirm = nil
                case .failure(DaemonError.pinUnconfirmed(let fp)): self.pinToConfirm = fp
                case .failure(let e): self.pinToConfirm = nil; self.actionError = e.localizedDescription
                }
                self.refresh()
            }
        }
    }
    public func declinePin() { pinToConfirm = nil }
    public func disconnect() { run("Disconnecting…") { _ = try $0.down() } }
    public func logout() { run("Signing out…") { _ = try $0.logout() } }

    public func connect() {
        let profile = self.profile
        run("Connecting…", { c in
            _ = try c.up(profile: profile.isEmpty ? nil : profile)
            // the hubs answer within a moment: either they admit the node or they want a user
            for _ in 0..<16 {
                let s = try c.status()
                if s.hubs?.contains(where: \.connected) == true || s.loginRequired == true { break }
                Thread.sleep(forTimeInterval: 0.5)
            }
        }, then: { [weak self] in
            // the person just pressed Connect: take them to the sign-in without another click
            if let self, self.status?.loginRequired == true, self.status?.hubs?.contains(where: \.connected) != true { self.signIn() }
        })
    }

    public func signIn() {
        guard !loginInProgress else { return }
        loginInProgress = true; actionError = nil
        let client = self.client
        Task.detached {
            let result: Result<Void, Error>
            do {
                let start = try client.login()
                guard let url = URL(string: start.url), url.scheme == "https" || url.scheme == "http" else {
                    throw DaemonError.protocolError("login URL")
                }
                await MainActor.run { _ = NSWorkspace.shared.open(url) }
                let deadline = Date().addingTimeInterval(600)
                var done = false
                while !done, Date() < deadline {
                    let r = try client.loginWait(flow: start.flowId)
                    if r.status == "failed" { throw DaemonError.refused("Sign-in failed: \(r.error ?? "unknown reason")") }
                    done = r.status == "done"
                }
                if !done { throw DaemonError.refused("Sign-in timed out.") }
                result = .success(())
            } catch { result = .failure(error) }
            await MainActor.run {
                self.loginInProgress = false
                if case .failure(let e) = result { self.actionError = e.localizedDescription }
                self.refresh()
            }
        }
    }
}
