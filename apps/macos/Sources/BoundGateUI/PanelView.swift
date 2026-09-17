import SwiftUI
import BoundGateKit

/// The window behind the menu-bar icon.
public struct PanelView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    public init(model: AppModel) { self.model = model }

    public var body: some View {
        let t = Theme.of(scheme)
        VStack(spacing: 12) {
            header
            content
            if let e = model.actionError { Notice(tone: .bad, text: e) }
            footer
        }
        .padding(14)
        .frame(width: 340)
        .background(t.bg)
        .environment(\.theme, t)
        .tint(Theme.accent)
    }

    private var t: Theme { Theme.of(scheme) }

    // MARK: header / footer

    private var header: some View {
        HStack(spacing: 10) {
            LogoTile(size: 30)
            Text("BoundGate").font(.display(17)).foregroundStyle(t.text)
            Spacer()
            statePill
        }
    }

    @ViewBuilder private var statePill: some View {
        if let b = model.busy { Pill(text: b, tone: .accent) } else {
            switch model.phase {
            case .connected: Pill(text: "Connected", tone: .ok)
            case .connecting: Pill(text: "Connecting", tone: .accent)
            case .loginRequired: Pill(text: "Sign-in needed", tone: .accent)
            case .ready: Pill(text: "Disconnected", tone: .idle)
            case .pending: Pill(text: "Awaiting approval", tone: .accent)
            case .revoked: Pill(text: "Revoked", tone: .bad)
            case .needsEnroll, .unconfigured: Pill(text: "Setup", tone: .accent)
            case .serviceMissing, .serviceApproval, .serviceDown: Pill(text: "Service off", tone: .idle)
            }
        }
    }

    private var footer: some View {
        HStack(spacing: 8) {
            if let s = model.status, let name = s.nodeName {
                Image(systemName: s.hardwareBound == true ? "cpu" : "key").font(.system(size: 10.5, weight: .medium)).foregroundStyle(t.text3)
                Text(name).font(.body(11.5)).foregroundStyle(t.text3).lineLimit(1)
            }
            Spacer()
            Button(action: showMenu) {
                Image(systemName: "gearshape").font(.system(size: 13, weight: .medium)).foregroundStyle(t.text2)
                    .padding(4).contentShape(Rectangle())
            }.buttonStyle(.plain)
        }
        .padding(.horizontal, 2)
    }

    private func showMenu() {
        var items: [PopupMenu.Item] = []
        if model.status != nil, model.status?.state != "unconfigured" {
            if model.status?.user != nil { items.append(.action("Sign out") { model.logout() }) }
            items.append(.action("Forget this control plane…") { confirmForget() })
            items.append(.separator)
        }
        if model.service == .enabled || model.service == .requiresApproval {
            items.append(.action("Remove background service") { model.uninstallService() })
        }
        items.append(.action("Quit BoundGate") { NSApp.terminate(nil) })
        PopupMenu.show(items)
    }

    private func confirmForget() {
        let a = NSAlert()
        a.messageText = "Forget this control plane?"
        a.informativeText = "The address, its pinned key and the administrators' keys are removed. This Mac keeps its device key and can enroll again, here or elsewhere."
        a.addButton(withTitle: "Forget"); a.addButton(withTitle: "Cancel")
        a.alertStyle = .warning
        if a.runModal() == .alertFirstButtonReturn { model.forgetControlPlane() }
    }

    // MARK: content per phase

    @ViewBuilder private var content: some View {
        switch model.phase {
        case .serviceMissing: ServiceCard(model: model, approval: false)
        case .serviceApproval: ServiceCard(model: model, approval: true)
        case .serviceDown(let why):
            Card {
                Text("The background service does not answer").font(.display(15)).foregroundStyle(t.text)
                Text(why).font(.body(12)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
                Text("Logs: /var/log/boundgate").font(.mono(11)).foregroundStyle(t.text3)
            }
        case .unconfigured: SetupCard(model: model)
        case .needsEnroll: EnrollCard(model: model)
        case .pending: PendingCard(model: model)
        case .revoked:
            Card {
                Text("This device was revoked").font(.display(15)).foregroundStyle(t.text)
                Text("An administrator revoked this Mac's key. A revoked key never comes back; ask your administrator how to proceed.")
                    .font(.body(12)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
            }
        case .ready, .connecting, .loginRequired, .connected: ConnectionCard(model: model)
        }
    }
}

// MARK: - cards

struct ServiceCard: View {
    @ObservedObject var model: AppModel
    var approval: Bool
    @Environment(\.theme) private var t
    var body: some View {
        Card {
            Text(approval ? "Allow the background service" : "Install the background service").font(.display(15)).foregroundStyle(t.text)
            Text(approval
                 ? "macOS wants your consent: switch on BoundGate under System Settings › General › Login Items & Extensions."
                 : "The tunnel runs in a small system service, so it keeps working when this window is closed. macOS will ask you to allow it.")
                .font(.body(12)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
            if case .unavailable(let why) = model.service {
                Notice(tone: .warn, text: "Not available: \(why).")
            }
            Button(approval ? "Open System Settings" : "Install service") { approval ? model.openApprovalSettings() : model.installService() }
                .buttonStyle(BGButtonStyle(kind: .primary, large: true))
                .disabled({ if case .unavailable = model.service { return true }; return false }())
        }
    }
}

struct SetupCard: View {
    @ObservedObject var model: AppModel
    @State private var control = ""
    @Environment(\.theme) private var t
    var body: some View {
        Card {
            Text("Which network is this Mac joining?").font(.display(15)).foregroundStyle(t.text)
            Text("Enter the address of your BoundGate control plane. Your administrator has it.")
                .font(.body(12)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
            TextField("boundgate.example.com", text: $control)
                .textFieldStyle(.plain).font(.mono(13)).foregroundStyle(t.text)
                .padding(.horizontal, 10).padding(.vertical, 8)
                .background(RoundedRectangle(cornerRadius: Theme.radiusSm, style: .continuous).fill(t.panel2))
                .overlay(RoundedRectangle(cornerRadius: Theme.radiusSm, style: .continuous).strokeBorder(t.borderStrong))
                .onSubmit(submit)
            Button("Continue", action: submit).buttonStyle(BGButtonStyle(kind: .primary, large: true))
                .disabled(control.trimmingCharacters(in: .whitespaces).isEmpty || model.busy != nil)
        }
    }
    private func submit() {
        let c = control.trimmingCharacters(in: .whitespaces)
        if !c.isEmpty { model.configure(control: c) }
    }
}

struct EnrollCard: View {
    @ObservedObject var model: AppModel
    @Environment(\.theme) private var t
    var body: some View {
        Card {
            Text("Request access").font(.display(15)).foregroundStyle(t.text)
            if let s = model.status {
                InfoRow(label: "Control plane", value: s.control ?? "–", mono: true)
                if let pin = s.controlPin, !pin.isEmpty {
                    FingerprintView(title: "Key of the control plane", fingerprint: pin)
                    Text("This Mac trusts that key from now on. If your administrator gave you its fingerprint, compare it before you continue.")
                        .font(.body(11.5)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
                }
                if let e = s.controlError, !e.isEmpty { Notice(tone: .warn, text: e) }
                else if let e = s.enrollmentError, !e.isEmpty { Notice(tone: .warn, text: e) }
            }
            Button("Request access") { model.enroll() }.buttonStyle(BGButtonStyle(kind: .primary, large: true)).disabled(model.busy != nil)
        }
    }
}

struct PendingCard: View {
    @ObservedObject var model: AppModel
    @Environment(\.theme) private var t
    var body: some View {
        Card {
            Text("Waiting for your administrator").font(.display(15)).foregroundStyle(t.text)
            Text(model.status?.enrollment == "confirmed"
                 ? "Confirmed. The last step is the administrator's signature; this window updates by itself."
                 : "Give this fingerprint to your administrator over a channel you trust. They compare all of it before they approve this Mac.")
                .font(.body(12)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
            FingerprintView(title: "Fingerprint of this Mac", fingerprint: model.status?.fingerprint ?? "")
            InfoRow(label: "Device name", value: model.status?.nodeName ?? "–")
        }
    }
}

struct ConnectionCard: View {
    @ObservedObject var model: AppModel
    @Environment(\.theme) private var t

    var body: some View {
        let s = model.status ?? NodeStatus(state: "down")
        let phase = model.phase
        VStack(spacing: 12) {
            Card {
                switch phase {
                case .connected:
                    let hub = s.hubs?.first(where: { $0.primary && $0.connected }) ?? s.hubs?.first(where: \.connected)
                    HStack(alignment: .firstTextBaseline) {
                        Text(s.overlayIp ?? "").font(.display(22)).foregroundStyle(t.text).textSelection(.enabled)
                        Spacer()
                        if let since = s.since, since.timeIntervalSince1970 > 0 { Text(since, style: .relative).font(.body(11.5)).foregroundStyle(t.text3) }
                    }
                    InfoRow(label: "Through", value: hub?.name ?? "–")
                    if let u = s.user { InfoRow(label: "Signed in as", value: u.displayName) }
                    InfoRow(label: "Networks", value: networks(s))
                case .loginRequired:
                    Text("Sign in to finish connecting").font(.display(15)).foregroundStyle(t.text)
                    Text(model.loginInProgress ? "Continue in your browser. This window updates when you are done."
                                               : "The network wants to know who is using this Mac.")
                        .font(.body(12)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
                case .connecting:
                    Text("Connecting…").font(.display(15)).foregroundStyle(t.text)
                    ForEach(s.hubs ?? []) { h in InfoRow(label: h.name, value: h.error?.isEmpty == false ? h.error! : h.state) }
                default:
                    Text("Not connected").font(.display(15)).foregroundStyle(t.text)
                    if !model.profiles.isEmpty {
                        HStack {
                            Text("Route").font(.body(12)).foregroundStyle(t.text2)
                            Spacer()
                            Button {
                                PopupMenu.show([.action("Everything offered", checked: model.profile.isEmpty) { model.profile = "" }]
                                    + model.profiles.map { p in .action(p, checked: model.profile == p) { model.profile = p } })
                            } label: {
                                HStack(spacing: 6) {
                                    Text(model.profile.isEmpty ? "Everything offered" : model.profile)
                                    Image(systemName: "chevron.up.chevron.down").font(.system(size: 9, weight: .semibold))
                                }
                            }.buttonStyle(BGButtonStyle())
                        }
                    }
                }
                ForEach(s.skippedRoutes ?? [], id: \.self) { Notice(tone: .warn, text: "Not routed: \($0)") }
                if phase != .connected, let e = s.lastError, !e.isEmpty { Notice(tone: .bad, text: e) }
                if let e = s.bindingError, !e.isEmpty { Notice(tone: .bad, text: "This Mac's approval does not verify: \(e)") }
                if let e = s.controlError, !e.isEmpty { Notice(tone: .warn, text: "Control plane: \(e)") }
            }
            switch phase {
            case .ready:
                Button("Connect") { model.connect() }.buttonStyle(BGButtonStyle(kind: .primary, large: true)).disabled(model.busy != nil)
            case .loginRequired:
                HStack(spacing: 8) {
                    Button(model.loginInProgress ? "Waiting for the browser…" : "Sign in") { model.signIn() }
                        .buttonStyle(BGButtonStyle(kind: .primary, large: true)).disabled(model.loginInProgress)
                    Button("Disconnect") { model.disconnect() }.buttonStyle(BGButtonStyle(large: true)).disabled(model.busy != nil)
                }
            default:
                Button("Disconnect") { model.disconnect() }.buttonStyle(BGButtonStyle(large: true)).disabled(model.busy != nil)
            }
        }
    }

    private func networks(_ s: NodeStatus) -> String {
        let r = s.routes ?? []
        if r.isEmpty { return "none" }
        return r.count <= 2 ? r.joined(separator: ", ") : "\(r[0]), \(r[1]) +\(r.count - 2)"
    }
}
