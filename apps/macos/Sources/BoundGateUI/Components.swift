import SwiftUI
import AppKit

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

struct Notice: View {
    enum Tone { case warn, bad, info }
    var tone: Tone
    var text: String
    @Environment(\.theme) private var t
    var body: some View {
        let c = tone == .warn ? t.warn : tone == .bad ? t.bad : t.info
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: tone == .info ? "info.circle" : "exclamationmark.triangle").font(.system(size: 12, weight: .semibold)).foregroundStyle(c).padding(.top, 1)
            Text(text).font(.body(12)).foregroundStyle(t.text).fixedSize(horizontal: false, vertical: true)
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
                Spacer()
                Button(copied ? "Copied" : "Copy") {
                    NSPasteboard.general.clearContents(); NSPasteboard.general.setString(fingerprint, forType: .string)
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
