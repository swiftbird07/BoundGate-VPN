import SwiftUI
#if os(macOS)
import AppKit
#endif

/// The mark: two interlocked rounded frames on a 1024 grid (docs/DESIGN.md).
public struct MarkShape: Shape {
    public init() {}
    public func path(in rect: CGRect) -> Path {
        let s = min(rect.width, rect.height) / 1024
        let ox = rect.midX - 512 * s, oy = rect.midY - 512 * s
        var p = Path()
        for (x, y) in [(148.0, 268.0), (414.0, 456.0)] {
            p.addRoundedRect(in: CGRect(x: ox + x * s, y: oy + y * s, width: 462 * s, height: 300 * s),
                             cornerSize: CGSize(width: 76 * s, height: 76 * s), style: .circular)
        }
        return p
    }
}

/// The mark on its tile. `adaptive`: charcoal tile on light surfaces, yellow
/// tile on dark ones, like Logo.svelte.
public struct LogoTile: View {
    var size: CGFloat
    @Environment(\.theme) private var t
    public init(size: CGFloat) { self.size = size }
    public var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 232 / 1024, style: .continuous).fill(t.logoGround)
            MarkShape().stroke(t.logoMark, style: StrokeStyle(lineWidth: size * 57 / 1024, lineCap: .round, lineJoin: .round))
        }
        .frame(width: size, height: size)
    }
}

#if os(macOS)
public enum MenuBarIcon {
    /// Template image for the menu bar. Connected: the full mark. Otherwise
    /// the second frame is dashed: one end has no connection. `attention`
    /// adds a dot (login or approval needed).
    public static func image(connected: Bool, attention: Bool) -> NSImage {
        let size = NSSize(width: 20, height: 16)
        let img = NSImage(size: size, flipped: true) { rect in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            ctx.setStrokeColor(NSColor.black.cgColor)
            ctx.setLineWidth(1.6); ctx.setLineCap(.round); ctx.setLineJoin(.round)
            let a = CGRect(x: 1.5, y: 1.5, width: 11, height: 8), b = CGRect(x: 7.5, y: 6.5, width: 11, height: 8)
            ctx.addPath(CGPath(roundedRect: a, cornerWidth: 2.4, cornerHeight: 2.4, transform: nil)); ctx.strokePath()
            if !connected { ctx.setLineDash(phase: 0, lengths: [2.2, 2.6]); ctx.setAlpha(0.75) }
            ctx.addPath(CGPath(roundedRect: b, cornerWidth: 2.4, cornerHeight: 2.4, transform: nil)); ctx.strokePath()
            if attention {
                ctx.setLineDash(phase: 0, lengths: []); ctx.setAlpha(1)
                ctx.setBlendMode(.clear); ctx.fillEllipse(in: CGRect(x: 13, y: -1, width: 8, height: 8))
                ctx.setBlendMode(.normal); ctx.setFillColor(NSColor.black.cgColor); ctx.fillEllipse(in: CGRect(x: 14.5, y: 0.5, width: 5, height: 5))
            }
            return true
        }
        img.isTemplate = true
        return img
    }
}
#endif
