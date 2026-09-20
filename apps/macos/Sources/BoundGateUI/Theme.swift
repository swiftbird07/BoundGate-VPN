import SwiftUI

/// The tokens of docs/DESIGN.md (web/src/app.css), for both appearances.
public struct Theme {
    public let bg, panel, panel2, panel3, border, borderStrong, text, text2, text3, ok, warn, bad, info, logoGround, logoMark, accentSoft: Color

    public static let accent = Color(hex: 0xFFCC00)
    public static let accentHi = Color(hex: 0xFFD83D)
    public static let onAccent = Color(hex: 0x2A2A2A)
    public static let charcoal = Color(hex: 0x2A2A2A)
    public static let radius: CGFloat = 14
    public static let radiusSm: CGFloat = 10

    public static let dark = Theme(
        bg: Color(hex: 0x1D1D1D), panel: Color(hex: 0x2A2A2A), panel2: Color(hex: 0x343434), panel3: Color(hex: 0x3E3E3E),
        border: Color.white.opacity(0.08), borderStrong: Color.white.opacity(0.17),
        text: Color(hex: 0xF5F2EA), text2: Color(hex: 0xB9B4A8), text3: Color(hex: 0x868074),
        ok: Color(hex: 0x5FD38D), warn: Color(hex: 0xFF9F45), bad: Color(hex: 0xFF6B6B), info: Color(hex: 0x7DB8FF),
        logoGround: accent, logoMark: charcoal, accentSoft: accent.opacity(0.10))

    public static let light = Theme(
        bg: Color(hex: 0xF4F2EB), panel: .white, panel2: Color(hex: 0xF0EDE4), panel3: Color(hex: 0xE6E2D6),
        border: Color(hex: 0x2A2A2A).opacity(0.10), borderStrong: Color(hex: 0x2A2A2A).opacity(0.24),
        text: Color(hex: 0x2A2A2A), text2: Color(hex: 0x5D594F), text3: Color(hex: 0x8B8678),
        ok: Color(hex: 0x178A4A), warn: Color(hex: 0xC2560A), bad: Color(hex: 0xCF3030), info: Color(hex: 0x1F62C4),
        logoGround: charcoal, logoMark: accent, accentSoft: accent.opacity(0.20))

    public static func of(_ scheme: ColorScheme) -> Theme { scheme == .dark ? .dark : .light }
}

extension Color {
    init(hex: UInt32) {
        self.init(.sRGB, red: Double((hex >> 16) & 0xFF) / 255, green: Double((hex >> 8) & 0xFF) / 255, blue: Double(hex & 0xFF) / 255, opacity: 1)
    }
}

extension Font {
    /// Headings, the wordmark and large numbers: the rounded system face.
    static func display(_ size: CGFloat, _ weight: Font.Weight = .bold) -> Font { .system(size: size, weight: weight, design: .rounded) }
    static func body(_ size: CGFloat = 13, _ weight: Font.Weight = .regular) -> Font { .system(size: size, weight: weight) }
    static func mono(_ size: CGFloat = 12) -> Font { .system(size: size, design: .monospaced) }
}

private struct ThemeKey: EnvironmentKey { static let defaultValue = Theme.dark }
extension EnvironmentValues {
    var theme: Theme { get { self[ThemeKey.self] } set { self[ThemeKey.self] = newValue } }
}

/// Primary: yellow fill, charcoal text. Secondary: surface step with a border.
struct BGButtonStyle: ButtonStyle {
    enum Kind { case primary, secondary, danger }
    var kind: Kind = .secondary
    var large = false
    @Environment(\.theme) private var t
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        let pressed = configuration.isPressed
        configuration.label
            .font(.body(large ? 15 : 13, .semibold))
            // a label that does not fit wraps; it is never cut off with an ellipsis
            .multilineTextAlignment(.center).lineLimit(large ? 2 : 1).fixedSize(horizontal: !large, vertical: true)
            .frame(maxWidth: large ? .infinity : nil)
            .padding(.horizontal, large ? 18 : 12).padding(.vertical, large ? 11 : 6)
            .foregroundStyle(kind == .primary ? Theme.onAccent : (kind == .danger ? t.bad : t.text))
            .background(RoundedRectangle(cornerRadius: Theme.radiusSm, style: .continuous)
                .fill(kind == .primary ? (pressed ? Theme.accentHi : Theme.accent) : (pressed ? t.panel3 : t.panel2)))
            .overlay(RoundedRectangle(cornerRadius: Theme.radiusSm, style: .continuous)
                .strokeBorder(kind == .primary ? Color.clear : t.border))
            .opacity(enabled ? 1 : 0.5)
            .animation(.easeOut(duration: 0.12), value: pressed)
    }
}
