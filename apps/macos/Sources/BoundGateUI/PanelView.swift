#if os(macOS)
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
            if let u = model.update, let v = u.installed, !v.isEmpty {
                Notice(tone: .info, text: "BoundGate \(v) is installed. The background service restarts from it in a moment.")
            } else if let u = model.update, u.available, let latest = u.latest { UpdateCard(model: model, update: u, latest: latest) }
            KeyWarningView(model: model)
            content
            if let n = model.updateNote { Notice(tone: .info, text: n) }
            if let e = model.actionError { Notice(tone: .bad, text: e) }
            footer
        }
        .padding(14)
        .frame(width: 340)
        .background(t.bg)
        .background(GeometryReader { g in Color.clear.preference(key: PanelHeight.self, value: g.size.height) })
        .onPreferenceChange(PanelHeight.self) { height = $0 }
        .background(FitWindow(height: height))
        .environment(\.theme, t)
        .tint(Theme.accent)
    }

    /// the panel's own height, for FitWindow
    @State private var height: CGFloat = 0

    private var t: Theme { Theme.of(scheme) }

    // MARK: header / footer

    private var header: some View {
        HStack(spacing: 10) {
            LogoTile(size: 30)
            VStack(alignment: .leading, spacing: 0) {
                Text("BoundGate").font(.display(17)).foregroundStyle(t.text)
                // with several meshes it matters which one this is
                if model.hasSeveralNetworks, let n = model.currentNetwork {
                    Text(n.label).font(.body(11.5)).foregroundStyle(t.text3).lineLimit(1)
                }
            }
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
            if model.networks.canAdd {
                items.append(.action("Add network…") { askForNetwork() })
            }
            if model.hasSeveralNetworks, let n = model.currentNetwork {
                items.append(.action("Remove \(n.label)…") { confirmRemove(n) })
            } else {
                items.append(.action("Forget this control plane…") { confirmForget() })
            }
            items.append(.separator)
        }
        if model.status?.state == "unconfigured", model.networks.canAdd, !model.networks.networks.isEmpty {
            items.append(.action("Add network…") { askForNetwork() })
            items.append(.separator)
        }
        if model.service == .enabled || model.service == .requiresApproval {
            items.append(.action("Remove background service") { model.uninstallService() })
        }
        if model.status != nil { items.append(.action("Check for Updates…") { model.checkForUpdates() }) }
        items.append(.action("Quit BoundGate") { NSApp.terminate(nil) })
        PopupMenu.show(items)
    }

    /// Another mesh: its address and what to call it. It gets a device key
    /// of its own, so it enrolls and is approved on its own.
    private func askForNetwork() {
        let a = NSAlert()
        a.messageText = "Add a network"
        a.informativeText = "This Mac gets a device key of its own in the new network, enrolls there and has to be approved there. One network is connected at a time."
        let name = NSTextField(frame: NSRect(x: 0, y: 30, width: 280, height: 24))
        name.placeholderString = "Name, e.g. Work"
        let addr = NSTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        addr.placeholderString = "Control plane, e.g. vpn.corp.example"
        let box = NSView(frame: NSRect(x: 0, y: 0, width: 280, height: 54))
        box.addSubview(name); box.addSubview(addr)
        a.accessoryView = box
        a.addButton(withTitle: "Add and switch"); a.addButton(withTitle: "Cancel")
        a.window.initialFirstResponder = name
        guard a.runModal() == .alertFirstButtonReturn else { return }
        let control = addr.stringValue.trimmingCharacters(in: .whitespaces)
        guard !control.isEmpty else { return }
        model.addNetwork(name: name.stringValue.trimmingCharacters(in: .whitespaces), control: control)
    }

    private func confirmRemove(_ n: NetworkInfo) {
        let a = NSAlert()
        a.messageText = "Remove \(n.label)?"
        let own = (n.dir ?? "").isEmpty
            ? "This Mac keeps its device key for this network and can enroll there again."
            : "Its device key goes with it: this Mac becomes a stranger to that control plane."
        a.informativeText = "\(own) Revoke this node in that network's admin UI afterwards."
        a.addButton(withTitle: "Remove"); a.addButton(withTitle: "Cancel")
        a.alertStyle = .warning
        if a.runModal() == .alertFirstButtonReturn { model.removeNetwork(n.id) }
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
                    .fixedSize(horizontal: false, vertical: true)
                Text(why).font(.body(12)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
                if model.service == .enabled {
                    // macOS ties a registered service to the app that registered it: after the app
                    // was replaced by one with another signature, it refuses to start the old entry
                    Text("If the app was replaced or moved, macOS may refuse to start the service it registered before. Registering it again fixes that; this Mac keeps its identity.")
                        .font(.body(12)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
                    Button("Register the service again") { model.reinstallService() }
                        .buttonStyle(BGButtonStyle(kind: .primary, large: true))
                }
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

struct UpdateCard: View {
    @ObservedObject var model: AppModel
    var update: UpdateStatus
    var latest: String
    @Environment(\.theme) private var t
    var body: some View {
        Card {
            Text("Update available").font(.display(15)).foregroundStyle(t.text)
            Text("BoundGate \(latest) is out; this is \(update.current). The release is signed, and the background service checks that signature before it installs anything.")
                .font(.body(11.5)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
            if update.canInstall {
                Button("Install and restart") { model.installUpdate() }
                    .buttonStyle(BGButtonStyle(kind: .primary, large: true)).disabled(model.busy != nil)
                Text("Disconnects for a moment.").font(.body(11)).foregroundStyle(t.text2)
            } else if let hint = update.installHint {
                Text(hint).font(.body(11.5)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
            }
            if let page = update.pageUrl, let url = URL(string: page), url.scheme == "https" {
                Button("Release notes") { NSWorkspace.shared.open(url) }.buttonStyle(BGButtonStyle(kind: .secondary))
            }
        }
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
                    Text("This Mac trusts that key.")
                        .font(.body(11.5)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
                }
                // "this control plane's key has not been accepted yet" is where every new Mac
                // starts, and this card is about exactly that: not a warning
                if let e = [s.controlError, s.enrollmentError].compactMap({ $0 }).first(where: { !$0.isEmpty }),
                   model.pinToConfirm == nil, !e.contains("has not been accepted yet") {
                    Notice(tone: .warn, text: e)
                }
            }
            if let pin = model.pinToConfirm {
                FingerprintView(title: "Control plane key", fingerprint: pin)
                Text("This Mac has not talked to this control plane before and will trust this key from now on. Compare it with the fingerprint your administrator gave you (admin UI, Nodes). If it differs, somebody else is answering at that address: do not continue.")
                    .font(.body(11.5)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
                Button("It matches: request access") { model.enroll(acceptPin: pin) }
                    .buttonStyle(BGButtonStyle(kind: .primary, large: true)).disabled(model.busy != nil)
                Button("Cancel") { model.declinePin() }.buttonStyle(BGButtonStyle(kind: .secondary)).disabled(model.busy != nil)
            } else {
                Button("Request access") { model.enroll() }.buttonStyle(BGButtonStyle(kind: .primary, large: true)).disabled(model.busy != nil)
            }
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
                    InfoRow(label: "Through", value: (hub?.name ?? "–") + (hub?.transport == "tcp" ? " · over TCP" : ""))
                    if let u = s.user { InfoRow(label: "Signed in as", value: u.displayName) }
                    else { InfoRow(label: "User", value: model.loginInProgress ? "continue in your browser…" : "not signed in") }
                    if s.user == nil, let h = s.signIn {
                        Notice(tone: .warn, text: "\(h.via ?? "The network") lets \(h.target) through only for a signed-in user.")
                    }
                    InfoRow(label: "Networks", value: networks(s))
                    RouteRow(model: model)
                    DetailsView(status: s, hub: hub, rate: model.rate)
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
                    RouteRow(model: model)
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
            case .connected where s.user == nil:
                // A session is no longer a condition of the tunnel, so nothing
                // asks for one; what needs a person is the policies' to say.
                // Signing in stays the user's choice, always at hand.
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
/// The menu-bar window grows with its content but does not shrink with it:
/// after a notice or the details went away it stayed as tall as before, with
/// the panel centred in it and a gap above and below. This sets the window to
/// the panel's height, keeping its top edge under the menu bar.
/// What this node routes, and in which mesh. The daemon swaps the routes
/// under a running tunnel, so the route is the same question whether the node
/// is up or down; another network is a bigger step -- the daemon ends this
/// node and starts the other one (docs/NETWORKS.md) -- but it is the same
/// choice to the person: "Work, everything" instead of "Private, LAN only".
private struct RouteRow: View {
    @ObservedObject var model: AppModel
    @Environment(\.theme) private var t

    /// the profiles of a network that is not running: every daemon has the
    /// built-ins, a profile from a file is only known where it lies
    private static let builtIn = ["full", "lan-only", "wan-only"]

    private var current: String { model.profile.isEmpty ? "full" : model.profile }

    private var label: String {
        guard model.hasSeveralNetworks, let n = model.currentNetwork else { return profileLabel(current) }
        return "\(n.label) · \(profileLabel(current))"
    }

    var body: some View {
        if model.profiles.count > 1 || model.hasSeveralNetworks {
            HStack {
                Text(model.hasSeveralNetworks ? "Network" : "Route").font(.body(12)).foregroundStyle(t.text2)
                Spacer()
                Button { PopupMenu.show(items()) } label: {
                    HStack(spacing: 6) {
                        Text(label)
                        Image(systemName: "chevron.up.chevron.down").font(.system(size: 9, weight: .semibold))
                    }
                }.buttonStyle(BGButtonStyle()).disabled(model.busy != nil)
            }
        }
    }

    private func items() -> [PopupMenu.Item] {
        guard model.hasSeveralNetworks else {
            return model.profiles.map { p in .action(profileLabel(p), checked: current == p) { model.setProfile(p) } }
        }
        let here = model.currentNetwork?.id
        var items: [PopupMenu.Item] = []
        for (i, n) in model.networks.networks.enumerated() {
            if i > 0 { items.append(.separator) }
            items.append(.header(n.label))
            let mine = n.id == here
            for p in mine ? model.profiles : Self.builtIn {
                items.append(.action("   " + profileLabel(p), checked: mine && current == p) {
                    if mine { model.setProfile(p) } else { model.selectNetwork(n.id, profile: p) }
                })
            }
        }
        return items
    }
}

/// The built-in profiles by what they do; a profile from a file by its name.
private func profileLabel(_ name: String) -> String {
    switch name {
    case "full": return "Full"
    case "lan-only": return "LAN only"
    case "wan-only": return "WAN only"
    default: return name
    }
}

private struct FitWindow: NSViewRepresentable {
    var height: CGFloat
    func makeNSView(context: Context) -> NSView { NSView() }
    func updateNSView(_ view: NSView, context: Context) {
        let height = self.height
        guard height > 0 else { return }
        // not during SwiftUI's own layout pass
        DispatchQueue.main.async {
            guard let w = view.window else { return }
            let content = w.contentRect(forFrameRect: w.frame)
            guard abs(content.height - height) >= 0.5 else { return }
            let fitted = NSRect(x: content.minX, y: content.maxY - height, width: content.width, height: height)
            w.setFrame(w.frameRect(forContentRect: fitted), display: true)
        }
    }
}

private struct PanelHeight: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}
#endif
