import SwiftUI
#if os(macOS)
import AppKit
#else
import UIKit
#endif

struct Card<Content: View>: View {
    @Environment(\.theme) private var t
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 10) { content }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(t.panel))
            .overlay(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).strokeBorder(t.border))
    }
}

struct Pill: View {
    enum Tone { case ok, warn, bad, info, idle, accent }
    var text: String
    var tone: Tone
    @Environment(\.theme) private var t
    var body: some View {
        let c: Color = { switch tone { case .ok: return t.ok; case .warn: return t.warn; case .bad: return t.bad; case .info: return t.info; case .idle: return t.text3; case .accent: return Theme.accent } }()
        HStack(spacing: 6) {
            Circle().fill(c).frame(width: 7, height: 7)
            Text(text).font(.body(11.5, .semibold)).foregroundStyle(tone == .accent ? t.text : c)
        }
        .padding(.horizontal, 9).padding(.vertical, 4)
        .background(Capsule().fill(c.opacity(0.13)))
        .overlay(Capsule().strokeBorder(c.opacity(0.35)))
    }
}

/// What the daemon reports is written for a log: the whole chain, with the
/// request in it (`control plane https://host:443: Get "https://…": transport:
/// pin control plane key: the key …`). In a card, the last link says it.
func readable(_ error: String) -> String {
    var s = error
    // up to and including the quoted URL of the failed request
    if let r = s.range(of: #"(Get|Post|Put|Delete|Head) "[^"]*": "#, options: .regularExpression) { s = String(s[r.upperBound...]) }
    for prefix in ["transport: ", "pin control plane key: ", "controlclient: "] where s.hasPrefix(prefix) { s = String(s.dropFirst(prefix.count)) }
    guard let first = s.first else { return error }
    return first.uppercased() + s.dropFirst()
}

struct Notice: View {
    enum Tone { case warn, bad, info }
    var tone: Tone
    var text: String
    @Environment(\.theme) private var t
    var body: some View {
        let c = tone == .warn ? t.warn : tone == .bad ? t.bad : t.info
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: tone == .info ? "info.circle" : "exclamationmark.triangle").font(.system(size: 12, weight: .semibold)).foregroundStyle(c).padding(.top, 1)
            Text(readable(text)).font(.body(12)).foregroundStyle(t.text).fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: Theme.radiusSm, style: .continuous).fill(c.opacity(0.10)))
        .overlay(RoundedRectangle(cornerRadius: Theme.radiusSm, style: .continuous).strokeBorder(c.opacity(0.30)))
    }
}

struct InfoRow: View {
    var label: String
    var value: String
    var mono = false
    @Environment(\.theme) private var t
    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).font(.body(12)).foregroundStyle(t.text2)
            Spacer(minLength: 12)
            Text(value).font(mono ? .mono(12) : .body(12, .medium)).foregroundStyle(t.text).multilineTextAlignment(.trailing).textSelection(.enabled)
        }
    }
}

/// The one thing this product promises is a key that cannot be copied. When a
/// Mac does not have one, that is said loudly, on every card, until it is fixed.
#if os(macOS)
struct KeyWarningView: View {
    @ObservedObject var model: AppModel
    @Environment(\.theme) private var t
    var body: some View {
        if let w = model.status?.keyWarning, !w.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.octagon.fill").font(.system(size: 17, weight: .bold)).foregroundStyle(t.bad)
                    Text("Software key: this Mac's identity can be copied").font(.display(14)).foregroundStyle(t.text)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text(w).font(.body(12)).foregroundStyle(t.text).fixedSize(horizontal: false, vertical: true)
                if model.status?.hardwareKeyAvailable == true {
                    Button("Move to the Secure Enclave…") { confirm() }
                        .buttonStyle(BGButtonStyle(kind: .primary, large: true)).disabled(model.busy != nil)
                }
            }
            .padding(12)
            .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(t.bad.opacity(0.14)))
            .overlay(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).strokeBorder(t.bad.opacity(0.65), lineWidth: 1.5))
        }
    }
    private func confirm() {
        let a = NSAlert()
        a.messageText = "Give this Mac a new identity in the Secure Enclave?"
        a.informativeText = "The software key is deleted and a new key is made inside the Secure Enclave, where it cannot be copied. To the control plane this is a new device: it asks for access again and an administrator has to approve it. Ask them to revoke the old entry."
        a.addButton(withTitle: "New identity"); a.addButton(withTitle: "Cancel")
        a.alertStyle = .warning
        if a.runModal() == .alertFirstButtonReturn { model.useHardwareKey() }
    }
}
#endif

/// Puts text on the clipboard, on either platform.
func copyToClipboard(_ s: String) {
    #if os(macOS)
    NSPasteboard.general.clearContents(); NSPasteboard.general.setString(s, forType: .string)
    #else
    UIPasteboard.general.string = s
    #endif
}

/// 64 hex digits in four rows of four groups: made for reading aloud and
/// comparing, which is the whole point of showing it.

struct FingerprintView: View {
    var title: String
    var fingerprint: String
    @Environment(\.theme) private var t
    @State private var copied = false

    private var rows: [String] {
        let groups = fingerprint.split(separator: " ").map(String.init)
        return stride(from: 0, to: groups.count, by: 4).map { groups[$0..<min($0 + 4, groups.count)].joined(separator: "  ") }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(title.uppercased()).font(.body(10.5, .semibold)).kerning(0.6).foregroundStyle(t.text3)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button(copied ? "Copied" : "Copy") {
                    copyToClipboard(fingerprint)
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                }.buttonStyle(.plain).font(.body(11, .semibold)).foregroundStyle(t.text2)
            }
            VStack(alignment: .leading, spacing: 3) {
                ForEach(rows, id: \.self) { Text($0).font(.mono(12.5)).foregroundStyle(t.text) }
            }
            .padding(10).frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: Theme.radiusSm, style: .continuous).fill(t.panel2))
            .textSelection(.enabled)
        }
    }
}

/// A native pop-up menu from plain SwiftUI buttons: styled like the rest of
/// the panel (and visible in rendered snapshots, which AppKit-backed SwiftUI
/// menus are not).
#if os(macOS)
@MainActor
enum PopupMenu {
    enum Item { case action(String, checked: Bool = false, () -> Void), separator }

    private final class Target: NSObject {
        let run: () -> Void
        init(_ run: @escaping () -> Void) { self.run = run }
        @objc func fire() { run() }
    }

    static func show(_ items: [Item]) {
        let menu = NSMenu()
        var targets: [Target] = []
        for item in items {
            switch item {
            case .separator: menu.addItem(.separator())
            case .action(let title, let checked, let run):
                let t = Target(run); targets.append(t)
                let mi = NSMenuItem(title: title, action: #selector(Target.fire), keyEquivalent: "")
                mi.target = t; mi.state = checked ? .on : .off
                menu.addItem(mi)
            }
        }
        menu.popUp(positioning: nil, at: NSEvent.mouseLocation, in: nil)
        withExtendedLifetime(targets) {}
    }
}
#endif
