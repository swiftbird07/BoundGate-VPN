// Developer tool, not shipped.
//   bgtool status                 what the app would read from the daemon ($BOUNDGATE_SOCKET)
//   bgtool snap DIR               render the panel in every state, light and dark, to PNG
//   bgtool icon DIR               draw the app icon as DIR/BoundGate.iconset
import AppKit
import SwiftUI
import BoundGateKit
import BoundGateUI

struct MockService: ServiceControlling {
    var s: ServiceState
    func state() -> ServiceState { s }
    func register() throws {}
    func unregister() throws {}
    func openApprovalSettings() {}
}

@MainActor func png<V: View>(_ view: V, scale: CGFloat, to url: URL) throws {
    let r = ImageRenderer(content: view)
    r.scale = scale
    guard let cg = r.cgImage else { throw DaemonError.protocolError("render failed") }
    let rep = NSBitmapImageRep(cgImage: cg)
    try rep.representation(using: .png, properties: [:])!.write(to: url)
}

@MainActor func snap(dir: URL) throws {
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let fp = "6199 76af 23a9 d2bb cd79 f603 959b ad79 220f dc34 b70f c28e c8c1 366f 00d7 8558"
    let pin = "8e3d 11c1 5db7 dc80 431b b248 6a13 d438 6030 ca13 7170 dfa9 ac07 2b93 cb47 a78d"
    func base(_ state: String, _ enrollment: String) -> NodeStatus {
        var s = NodeStatus(state: state)
        s.enrollment = enrollment; s.nodeName = "Adas-MacBook-Pro"; s.fingerprint = fp; s.control = "bg.example.com:443"
        s.controlPin = pin; s.keyKind = "softkey"; s.hardwareBound = false
        return s
    }
    var connected = base("up", "approved")
    connected.overlayIp = "10.44.0.5"; connected.since = Date().addingTimeInterval(-3725)
    connected.hubs = [HubStatus(name: "hel1", addr: "hel1.example.com:443", state: "connected", error: nil, primary: true)]
    connected.routes = ["10.44.0.0/16", "10.60.0.0/24", "172.16.8.0/22"]
    connected.skippedRoutes = ["192.168.178.0/24 (overlaps 192.168.178.0/24 on en0)"]
    connected.user = UserStatus(subject: "u1", username: "martin", email: nil, groups: ["vpn-users"], expiresAt: nil)
    var login = base("up", "approved"); login.loginRequired = true
    login.hubs = [HubStatus(name: "hel1", addr: "hel1.example.com:443", state: "refused", error: "login required", primary: false)]
    var failed = base("down", "approved")
    failed.lastError = "the overlay pool 10.21.0.0/16 overlaps 10.21.0.9/32 on utun8: another interface of this machine already uses that range (usually a second VPN)"

    let chain = "control plane https://bg.example.com:443: Get \"https://bg.example.com:443/api/v1/node/enroll/status\": transport: pin control plane key: "
    var unpinned = base("down", "unknown"); unpinned.controlPin = nil
    unpinned.controlError = chain + "the key of this control plane has not been accepted yet; enrolling shows it for comparison"
    var unreachableCP = base("down", "unknown")
    unreachableCP.controlError = "control plane https://bg.example.com:443: Get \"https://bg.example.com:443/api/v1/node/enroll/status\": dial udp: lookup bg.example.com: no such host"
    var soft = base("down", "pending")
    soft.keyWarning = "This Mac's identity is a software key: a file that anyone with administrator rights, a backup or malware can copy to another machine. This Mac has a Secure Enclave; the node kept the software key it enrolled with. A new identity in the Secure Enclave cannot be copied (the Mac then has to be approved again)."
    soft.hardwareKeyAvailable = true
    var softOnly = connected
    softOnly.keyWarning = "This Mac's identity is a software key: a file that anyone with administrator rights, a backup or malware can copy to another machine. No usable Secure Enclave was found (Intel Macs without a T2 chip have none, or the helper boundgate-sekey is missing from the app), so it cannot be bound to the hardware."
    let cases: [(String, NodeStatus?, ServiceState, String?)] = [
        ("1-service", nil, .notRegistered, "The background service is not running."),
        ("2-approval", nil, .requiresApproval, "The background service is not running."),
        ("2b-service-down", nil, .enabled, "The background service is not running."),
        ("3-setup", NodeStatus(state: "unconfigured"), .enabled, nil),
        ("4-enroll", base("down", "unknown"), .enabled, nil),
        ("4b-enroll-pin", unpinned, .enabled, nil),
        ("4c-enroll-error", unreachableCP, .enabled, nil),
        ("4d-softkey", soft, .enabled, nil),
        ("4e-softkey-no-enclave", softOnly, .enabled, nil),
        ("5-pending", base("down", "pending"), .enabled, nil),
        ("6-ready", base("down", "approved"), .enabled, nil),
        ("7-login", login, .enabled, nil),
        ("8-connected", connected, .enabled, nil),
        ("9-error", failed, .enabled, nil),
    ]
    for (name, status, svc, unreachable) in cases {
        for scheme in [ColorScheme.dark, .light] {
            let m = AppModel(client: DaemonClient(socketPath: "/nonexistent"), installer: MockService(s: svc))
            m.status = status; m.service = svc; m.unreachable = unreachable
            if name == "6-ready" { m.profiles = ["home", "work"] }
            if name == "4b-enroll-pin" { m.pinToConfirm = "5c1f aa42 0702 4bc8 c981 a780 ff32 7b82 8156 9d8c 512a 53d4 8c4a 5df5 0add 4db5" }
            let v = PanelView(model: m).environment(\.colorScheme, scheme)
            try png(v, scale: 2, to: dir.appendingPathComponent("\(name)-\(scheme == .dark ? "dark" : "light").png"))
        }
    }
    // menu bar icons on a light strip
    let icons = HStack(spacing: 14) {
        Image(nsImage: MenuBarIcon.image(connected: false, attention: false))
        Image(nsImage: MenuBarIcon.image(connected: false, attention: true))
        Image(nsImage: MenuBarIcon.image(connected: true, attention: false))
    }.padding(10).background(Color(white: 0.92))
    try png(icons, scale: 4, to: dir.appendingPathComponent("menubar-icons.png"))
}

/// macOS app icon: the tile of docs/DESIGN.md inside Apple's icon grid
/// (824 of 1024, so it sits like other icons in the Dock).
struct AppIcon: View {
    var body: some View {
        ZStack {
            Color.clear
            ZStack {
                RoundedRectangle(cornerRadius: 824 * 232 / 1024, style: .continuous).fill(Theme.charcoal)
                MarkShape().stroke(Theme.accent, style: StrokeStyle(lineWidth: 824 * 57 / 1024, lineCap: .round, lineJoin: .round))
            }.frame(width: 824, height: 824)
        }.frame(width: 1024, height: 1024)
    }
}

@MainActor func icon(dir: URL) throws {
    let set = dir.appendingPathComponent("BoundGate.iconset")
    try FileManager.default.createDirectory(at: set, withIntermediateDirectories: true)
    for (pt, scale) in [(16, 1), (16, 2), (32, 1), (32, 2), (128, 1), (128, 2), (256, 1), (256, 2), (512, 1), (512, 2)] {
        let px = CGFloat(pt * scale)
        let name = scale == 1 ? "icon_\(pt)x\(pt).png" : "icon_\(pt)x\(pt)@2x.png"
        try png(AppIcon().scaleEffect(px / 1024).frame(width: px, height: px), scale: 1, to: set.appendingPathComponent(name))
    }
}

let args = CommandLine.arguments.dropFirst()
do {
    switch args.first {
    case "status":
        let s = try DaemonClient().status()
        print("state=\(s.state) enrollment=\(s.enrollment ?? "-") node=\(s.nodeName ?? "-") overlay=\(s.overlayIp ?? "-") control=\(s.control ?? "-")")
        print("hubs=\((s.hubs ?? []).map { "\($0.name):\($0.state)" }.joined(separator: ",")) since=\(s.since.map { "\($0)" } ?? "-") fingerprint=\(s.fingerprint ?? "-")")
    case "snap":
        try MainActor.assumeIsolated { try snap(dir: URL(fileURLWithPath: args.dropFirst().first ?? "snapshots")) }
    case "icon":
        try MainActor.assumeIsolated { try icon(dir: URL(fileURLWithPath: args.dropFirst().first ?? ".")) }
    default:
        FileHandle.standardError.write(Data("usage: bgtool status | snap DIR | icon DIR\n".utf8)); exit(2)
    }
} catch {
    FileHandle.standardError.write(Data("bgtool: \(error.localizedDescription)\n".utf8)); exit(1)
}
