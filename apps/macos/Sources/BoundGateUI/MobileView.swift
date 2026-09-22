#if os(iOS)
import SwiftUI
import BoundGateKit

/// The iOS app's one screen: the Mac panel's cards, full width.
public struct MobileView: View {
    @ObservedObject var model: MobileModel
    @Environment(\.colorScheme) private var scheme
    @Environment(\.openURL) private var openURL

    public init(model: MobileModel) { self.model = model }

    public var body: some View {
        let t = Theme.of(scheme)
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    header
                    content
                    if let e = model.actionError { Notice(tone: .bad, text: e) }
                    if let s = model.status, let name = s.nodeName {
                        HStack(spacing: 6) {
                            Image(systemName: s.hardwareBound == true ? "cpu" : "key").font(.system(size: 11, weight: .medium))
                            Text(name).font(.body(12))
                            Spacer()
                        }
                        .foregroundStyle(t.text3).padding(.horizontal, 4)
                    }
                }
                .padding(16)
            }
            .background(t.bg.ignoresSafeArea())
            .toolbar { ToolbarItem(placement: .topBarTrailing) { menu } }
        }
        .environment(\.theme, t)
        .tint(Theme.accent)
        .onAppear { model.openURL = { openURL($0) } }
    }

    private var t: Theme { Theme.of(scheme) }

    private var header: some View {
        HStack(spacing: 10) {
            LogoTile(size: 34)
            Text("BoundGate").font(.display(20)).foregroundStyle(t.text)
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
            case .noEngine: Pill(text: "Not running", tone: .idle)
            }
        }
    }

    private var menu: some View {
        Menu {
            if model.status?.user != nil { Button("Sign out") { model.signOut() } }
            if model.status != nil, model.status?.state != "unconfigured" {
                Button("Forget this control plane", role: .destructive) { model.forget() }
            }
        } label: {
            Image(systemName: "ellipsis.circle").foregroundStyle(t.text2)
        }
    }

    @ViewBuilder private var content: some View {
        switch model.phase {
        case .noEngine(let why):
            Card {
                Text("BoundGate is not running").font(.display(16)).foregroundStyle(t.text)
                Text(why).font(.body(13)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
            }
        case .unconfigured: MobileSetupCard(model: model)
        case .needsEnroll: MobileEnrollCard(model: model)
        case .pending:
            Card {
                Text("Waiting for your administrator").font(.display(16)).foregroundStyle(t.text)
                Text(model.status?.enrollment == "confirmed"
                     ? "Confirmed. The last step is the administrator's signature; this screen updates by itself."
                     : "Give this fingerprint to your administrator over a channel you trust. They compare all of it before they approve this device.")
                    .font(.body(13)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
                FingerprintView(title: "Fingerprint of this device", fingerprint: model.status?.fingerprint ?? "")
            }
        case .revoked:
            Card {
                Text("This device was revoked").font(.display(16)).foregroundStyle(t.text)
                Text("An administrator revoked this device's key. A revoked key never comes back; ask your administrator how to proceed.")
                    .font(.body(13)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
            }
        case .ready, .connecting, .loginRequired, .connected: MobileConnectionCard(model: model)
        }
    }
}

struct MobileSetupCard: View {
    @ObservedObject var model: MobileModel
    @State private var control = ""
    // the name the node already uses (shown below the card); UIDevice.name is
    // only "iPhone" for apps without a special entitlement
    @State private var name = ""
    @Environment(\.theme) private var t
    var body: some View {
        Card {
            Text("Which network is this device joining?").font(.display(16)).foregroundStyle(t.text)
            Text("Enter the address of your BoundGate control plane. Your administrator has it.")
                .font(.body(13)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
            field("vpn.example.com", text: $control, mono: true)
                .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                .onChange(of: control) { v in if v != v.lowercased() { control = v.lowercased() } }
            field("Device name", text: $name, mono: false)
            Button("Continue") { model.configure(control: control.trimmingCharacters(in: .whitespaces), name: name) }
                .buttonStyle(BGButtonStyle(kind: .primary, large: true))
                .disabled(control.trimmingCharacters(in: .whitespaces).isEmpty || model.busy != nil)
        }
        .onAppear { if name.isEmpty { name = model.status?.nodeName ?? "" } }
        .onChange(of: model.status?.nodeName) { n in if name.isEmpty, let n { name = n } }
    }
    private func field(_ prompt: String, text: Binding<String>, mono: Bool) -> some View {
        TextField(prompt, text: text)
            .font(mono ? .mono(15) : .body(15)).foregroundStyle(t.text)
            .padding(.horizontal, 12).padding(.vertical, 10)
            .background(RoundedRectangle(cornerRadius: Theme.radiusSm, style: .continuous).fill(t.panel2))
            .overlay(RoundedRectangle(cornerRadius: Theme.radiusSm, style: .continuous).strokeBorder(t.borderStrong))
    }
}

struct MobileEnrollCard: View {
    @ObservedObject var model: MobileModel
    @Environment(\.theme) private var t
    var body: some View {
        Card {
            Text("Request access").font(.display(16)).foregroundStyle(t.text)
            if let s = model.status {
                InfoRow(label: "Control plane", value: s.control ?? "–", mono: true)
                if let e = [s.controlError, s.enrollmentError].compactMap({ $0 }).first(where: { !$0.isEmpty }),
                   model.pinToConfirm == nil, !e.contains("has not been accepted yet") {
                    Notice(tone: .warn, text: e)
                }
            }
            if let pin = model.pinToConfirm {
                FingerprintView(title: "Control plane key", fingerprint: pin)
                Text("This device has not talked to this control plane before and will trust this key from now on. Compare it with the fingerprint your administrator gave you. If it differs, somebody else is answering at that address: do not continue.")
                    .font(.body(12.5)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
                Button("It matches: request access") { model.enroll(acceptPin: pin) }
                    .buttonStyle(BGButtonStyle(kind: .primary, large: true)).disabled(model.busy != nil)
                Button("Cancel") { model.declinePin() }.buttonStyle(BGButtonStyle(kind: .secondary))
            } else {
                Button("Request access") { model.enroll() }.buttonStyle(BGButtonStyle(kind: .primary, large: true)).disabled(model.busy != nil)
            }
        }
    }
}

struct MobileConnectionCard: View {
    @ObservedObject var model: MobileModel
    @Environment(\.theme) private var t

    var body: some View {
        let s = model.status ?? NodeStatus(state: "down")
        let phase = model.phase
        VStack(spacing: 14) {
            Card {
                switch phase {
                case .connected:
                    let hub = s.hubs?.first(where: { $0.primary && $0.connected }) ?? s.hubs?.first(where: \.connected)
                    HStack(alignment: .firstTextBaseline) {
                        Text(s.overlayIp ?? "").font(.display(26)).foregroundStyle(t.text).textSelection(.enabled)
                        Spacer()
                        if let since = s.since, since.timeIntervalSince1970 > 0 { Text(since, style: .relative).font(.body(12)).foregroundStyle(t.text3) }
                    }
                    InfoRow(label: "Through", value: (hub?.name ?? "–") + (hub?.transport == "tcp" ? " · over TCP" : ""))
                    if let u = s.user { InfoRow(label: "Signed in as", value: u.displayName) }
                    InfoRow(label: "Networks", value: (s.routes ?? []).isEmpty ? "none" : (s.routes ?? []).joined(separator: ", "))
                    DetailsView(status: s, hub: hub, rate: model.rate)
                    if let m = model.memoryMiB {
                        // the packet tunnel may use 50 MiB before iOS ends it
                        InfoRow(label: "Tunnel memory", value: String(format: "%.1f of 50 MiB", m))
                    }
                case .loginRequired:
                    Text("Sign in to finish connecting").font(.display(16)).foregroundStyle(t.text)
                    Text(model.loginInProgress ? "Continue in the browser, then come back here."
                                               : "The network wants to know who is using this device.")
                        .font(.body(13)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
                case .connecting:
                    Text("Connecting…").font(.display(16)).foregroundStyle(t.text)
                    ForEach(s.hubs ?? []) { h in InfoRow(label: h.name, value: h.error?.isEmpty == false ? h.error! : h.state) }
                default:
                    Text("Not connected").font(.display(16)).foregroundStyle(t.text)
                    if case .unavailable(let why) = model.vpn { Notice(tone: .warn, text: why) }
                }
                ForEach(s.skippedRoutes ?? [], id: \.self) { Notice(tone: .warn, text: "Not routed: \($0)") }
                if phase != .connected, let e = s.lastError, !e.isEmpty { Notice(tone: .bad, text: e) }
                if let e = s.bindingError, !e.isEmpty { Notice(tone: .bad, text: "This device's approval does not verify: \(e)") }
                if let e = s.controlError, !e.isEmpty { Notice(tone: .warn, text: "Control plane: \(e)") }
            }
            switch phase {
            case .ready:
                Button("Connect") { model.connect() }.buttonStyle(BGButtonStyle(kind: .primary, large: true)).disabled(model.busy != nil)
            case .loginRequired:
                Button(model.loginInProgress ? "Waiting for the browser…" : "Sign in") { model.signIn() }
                    .buttonStyle(BGButtonStyle(kind: .primary, large: true)).disabled(model.loginInProgress || model.busy != nil)
                Button("Disconnect") { model.disconnect() }.buttonStyle(BGButtonStyle(large: true))
            default:
                Button("Disconnect") { model.disconnect() }.buttonStyle(BGButtonStyle(large: true))
            }
        }
    }
}
#endif
