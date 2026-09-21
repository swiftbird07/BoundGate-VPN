import Foundation
import BoundGateKit

/// Totals and rates of what the tunnels carry. The daemon counts IP packets per
/// tunnel; the app reads those counters every two seconds and the difference
/// of two readings is the rate.
public enum Traffic {
    public struct Totals: Equatable, Sendable {
        public var bytesIn: UInt64 = 0, bytesOut: UInt64 = 0, packetsIn: UInt64 = 0, packetsOut: UInt64 = 0
        /// false with a daemon that does not count yet (before v0.1.5)
        public var counted = false
    }

    public struct Reading: Sendable {
        var totals: Totals?
        var at: Date
        public init(status: NodeStatus?, at: Date) { totals = status.flatMap(Traffic.totals); self.at = at }
    }

    public struct Rate: Equatable, Sendable {
        public var bytesInPerSecond: Double
        public var bytesOutPerSecond: Double
        public init(bytesInPerSecond: Double, bytesOutPerSecond: Double) {
            self.bytesInPerSecond = bytesInPerSecond; self.bytesOutPerSecond = bytesOutPerSecond
        }
    }

    /// Everything this Mac sent and received through the overlay: hub tunnels plus direct and relayed paths.
    public static func totals(_ s: NodeStatus) -> Totals? {
        var t = Totals()
        for h in s.hubs ?? [] {
            if h.bytesIn != nil || h.bytesOut != nil { t.counted = true }
            t.bytesIn += h.bytesIn ?? 0; t.bytesOut += h.bytesOut ?? 0
            t.packetsIn += h.packetsIn ?? 0; t.packetsOut += h.packetsOut ?? 0
        }
        for p in s.paths ?? [] {
            if p.bytesIn != nil || p.bytesOut != nil { t.counted = true }
            t.bytesIn += p.bytesIn ?? 0; t.bytesOut += p.bytesOut ?? 0
        }
        return t.counted ? t : nil
    }

    /// nil when there is nothing to compare: first reading, not connected, or the
    /// counters started over (a tunnel was replaced).
    public static func rate(from a: Reading?, to b: Reading) -> Rate? {
        guard let a, let x = a.totals, let y = b.totals else { return nil }
        let dt = b.at.timeIntervalSince(a.at)
        guard dt > 0.2, dt < 30, y.bytesIn >= x.bytesIn, y.bytesOut >= x.bytesOut else { return nil }
        return Rate(bytesInPerSecond: Double(y.bytesIn - x.bytesIn) / dt, bytesOutPerSecond: Double(y.bytesOut - x.bytesOut) / dt)
    }

    /// 1.4 MB, 312 kB, 87 B: decimal units, as Finder and Activity Monitor show them.
    public static func bytes(_ n: UInt64) -> String {
        if n < 1000 { return "\(n) B" }
        var v = Double(n) / 1000, unit = 0
        let units = ["kB", "MB", "GB", "TB", "PB"]
        while v >= 1000, unit < units.count - 1 { v /= 1000; unit += 1 }
        return String(format: v < 10 ? "%.2f %@" : v < 100 ? "%.1f %@" : "%.0f %@", v, units[unit])
    }

    public static func perSecond(_ v: Double) -> String { bytes(UInt64(max(0, v.rounded()))) + "/s" }

    public static func count(_ n: UInt64) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal; f.groupingSeparator = "\u{202F}"; f.usesGroupingSeparator = true
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    /// What carries the packets to a hub, in words.
    public static func tunnelProtocol(_ transport: String?) -> String {
        switch transport {
        case "tcp": return "CONNECT-IP · HTTP/1.1 (TCP)"
        case "quic": return "CONNECT-IP · HTTP/3 (QUIC)"
        default: return "–"
        }
    }

    public static func controlProtocol(_ transport: String?) -> String {
        switch transport {
        case "h3": return "HTTP/3 (QUIC)"
        case "h2": return "HTTP/2 (TCP fallback)"
        default: return "–"
        }
    }

    public static func keyKind(_ kind: String?, hardwareBound: Bool?) -> String {
        switch kind {
        case "secure-enclave": return "Secure Enclave"
        case "tpm2": return "TPM 2.0"
        case "softkey": return "Software key (file)"
        default: return (kind ?? "–") + (hardwareBound == true ? " · hardware" : "")
        }
    }
}
