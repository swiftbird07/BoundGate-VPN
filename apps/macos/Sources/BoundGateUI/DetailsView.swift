import SwiftUI
import BoundGateKit

/// Numbers and protocols of the running connection. Closed until somebody asks:
/// most people want to know that it works, not how.
struct DetailsView: View {
    var status: NodeStatus
    var hub: HubStatus?
    var rate: Traffic.Rate?
    @AppStorage("showDetails") private var open = false
    @Environment(\.theme) private var t
    @Environment(\.staticRender) private var staticRender

    init(status: NodeStatus, hub: HubStatus?, rate: Traffic.Rate?) {
        self.status = status; self.hub = hub; self.rate = rate
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Button { withAnimation(.easeOut(duration: 0.15)) { open.toggle() } } label: {
                HStack(spacing: 6) {
                    Image(systemName: "chevron.right").font(.system(size: 9, weight: .bold)).rotationEffect(.degrees(open ? 90 : 0))
                    Text("Details").font(.body(12, .medium))
                    Spacer()
                }
                .foregroundStyle(t.text2).contentShape(Rectangle())
            }.buttonStyle(.plain)
            if open {
                // a panel under the menu bar cannot grow past the screen; an image has no scrolling
                if staticRender { sections } else { ScrollView { sections }.frame(height: min(430, sectionsHeight)) }
            }
        }
        .padding(.top, 2)
    }

    /// enough for what is shown, so a short list does not leave a hole
    private var sectionsHeight: CGFloat {
        let rows = 11 + (status.hubs?.count ?? 1) - 1 + (status.paths?.count ?? 0) + ((status.routes?.count ?? 0) > 2 ? status.routes!.count : 0)
        return CGFloat(rows) * 21 + 4 * 44
    }

    @ViewBuilder private var sections: some View {
        VStack(alignment: .leading, spacing: 10) {
                section("Traffic") {
                    if let tot = Traffic.totals(status) {
                        InfoRow(label: "Received", value: Traffic.bytes(tot.bytesIn) + (rate.map { " · " + Traffic.perSecond($0.bytesInPerSecond) } ?? ""))
                        InfoRow(label: "Sent", value: Traffic.bytes(tot.bytesOut) + (rate.map { " · " + Traffic.perSecond($0.bytesOutPerSecond) } ?? ""))
                        if tot.packetsIn > 0 || tot.packetsOut > 0 {
                            InfoRow(label: "Packets", value: "\(Traffic.count(tot.packetsIn)) in · \(Traffic.count(tot.packetsOut)) out")
                        }
                    } else {
                        Text("The background service does not count yet; it does from the next update on.")
                            .font(.body(11.5)).foregroundStyle(t.text2).fixedSize(horizontal: false, vertical: true)
                    }
                }
                section("Tunnel") {
                    InfoRow(label: "Protocol", value: Traffic.tunnelProtocol(hub?.transport))
                    if let h = hub { InfoRow(label: "Hub", value: h.addr, mono: true) }
                    if let i = status.interface, !i.isEmpty { InfoRow(label: "Device", value: i + (status.mtu.map { " · MTU \($0)" } ?? ""), mono: true) }
                    ForEach((status.hubs ?? []).filter { $0.id != hub?.id }) { h in
                        InfoRow(label: "Standby", value: h.name + " · " + (h.connected ? (h.transport == "tcp" ? "TCP" : "QUIC") : h.state))
                    }
                    ForEach(status.paths ?? []) { p in
                        InfoRow(label: p.peer, value: p.via + " · ↓ " + Traffic.bytes(p.bytesIn ?? 0) + " ↑ " + Traffic.bytes(p.bytesOut ?? 0))
                    }
                    if let r = status.routes, r.count > 2 { InfoRow(label: "Routes", value: r.joined(separator: "\n"), mono: true) }
                }
                section("Control plane") {
                    InfoRow(label: "Address", value: status.control ?? "–", mono: true)
                    InfoRow(label: "Protocol", value: Traffic.controlProtocol(status.controlTransport))
                    if let p = status.policies { InfoRow(label: "Policies", value: "\(p)" + (status.snapshotVersion.map { " · snapshot \($0)" } ?? "")) }
                    if let f = status.flows { InfoRow(label: "Connections", value: "\(f) open" + ((status.flowsDenied ?? 0) > 0 ? " · \(status.flowsDenied!) denied" : "")) }
                }
                section(Self.thisDevice) {
                    InfoRow(label: "Device key", value: Traffic.keyKind(status.keyKind, hardwareBound: status.hardwareBound))
                    if let v = status.version, !v.isEmpty { InfoRow(label: "Version", value: v, mono: true) }
                }
        }
    }

    #if os(macOS)
    static let thisDevice = "This Mac"
    #else
    static let thisDevice = "This device"
    #endif

    @ViewBuilder private func section<C: View>(_ title: String, @ViewBuilder _ rows: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title.uppercased()).font(.body(10.5, .semibold)).kerning(0.6).foregroundStyle(t.text3)
            rows()
        }
        .padding(10).frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: Theme.radiusSm, style: .continuous).fill(t.panel2))
    }
}
