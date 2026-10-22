import Foundation

// The JSON of the daemon socket (internal/node/ipc, node.Status). Unknown
// fields are ignored, missing ones are nil: the app must keep working with a
// daemon that is a version ahead or behind.

public struct UserStatus: Codable, Equatable, Sendable {
    public var subject: String
    public var username: String?
    public var email: String?
    public var groups: [String]?
    public var expiresAt: Date?

    public init(subject: String, username: String? = nil, email: String? = nil, groups: [String]? = nil, expiresAt: Date? = nil) {
        self.subject = subject; self.username = username; self.email = email; self.groups = groups; self.expiresAt = expiresAt
    }

    public var displayName: String { username?.isEmpty == false ? username! : (email?.isEmpty == false ? email! : subject) }
}

public struct HubStatus: Codable, Equatable, Sendable, Identifiable {
    public var name: String
    public var addr: String
    public var state: String
    public var error: String?
    public var transport: String?   // "quic", or "tcp" on the fallback for networks that block UDP
    public var primary: Bool
    public var since: Date?
    /// what the tunnel to this hub carried since `since` (daemons before v0.1.5 do not count)
    public var bytesIn: UInt64?
    public var bytesOut: UInt64?
    public var packetsIn: UInt64?
    public var packetsOut: UInt64?

    public init(name: String, addr: String, state: String, error: String? = nil, transport: String? = nil, primary: Bool = false) {
        self.name = name; self.addr = addr; self.state = state; self.error = error; self.transport = transport; self.primary = primary
    }

    public var id: String { name }
    public var connected: Bool { state == "connected" }
}

/// A tunnel with another node that does not go through a hub's routing: direct, or relayed.
public struct PathStatus: Codable, Equatable, Sendable, Identifiable {
    public var peer: String
    public var via: String     // "direct" or "relay <hub>"
    public var side: String?
    public var since: Date?
    public var bytesIn: UInt64?
    public var bytesOut: UInt64?

    public init(peer: String, via: String, bytesIn: UInt64? = nil, bytesOut: UInt64? = nil) {
        self.peer = peer; self.via = via; self.bytesIn = bytesIn; self.bytesOut = bytesOut
    }
    public var id: String { peer + via }
}

/// A node refused a connection of this device that a signed-in user would be
/// let through; from the control plane, shown while nobody is signed in.
public struct SignInHint: Codable, Equatable, Sendable {
    public var dst: String
    public var port: Int?
    public var proto: String?
    public var name: String?
    public var via: String?
    public var at: Date?

    /// "nas.home (192.168.178.10:443)", or the address alone
    public var target: String {
        let addr = (port ?? 0) != 0 ? (dst.contains(":") ? "[\(dst)]:\(port!)" : "\(dst):\(port!)") : dst
        if let n = name, !n.isEmpty { return "\(n) (\(addr))" }
        return addr
    }
}

public struct NodeStatus: Codable, Equatable, Sendable {
    public var state: String
    public var profile: String?
    public var overlayIp: String?
    public var kind: String?
    public var roles: [String]?
    public var user: UserStatus?
    public var loginRequired: Bool?
    public var signIn: SignInHint?
    public var hubs: [HubStatus]?
    public var paths: [PathStatus]?
    public var routes: [String]?
    public var skippedRoutes: [String]?
    public var since: Date?
    public var lastError: String?
    public var lastClose: String?
    public var nodeName: String?
    public var nodeId: String?
    public var fingerprint: String?
    public var keyKind: String?
    public var hardwareBound: Bool?
    /// Set when the device key is weaker than it should be (a software key on a Mac).
    public var keyWarning: String?
    /// A new identity would be hardware-bound (Secure Enclave).
    public var hardwareKeyAvailable: Bool?
    public var enrollment: String?
    public var enrollmentError: String?
    public var control: String?
    public var controlError: String?
    public var controlPin: String?
    /// what carried the control plane's last answer: "h3" (UDP) or "h2" (the TCP fallback)
    public var controlTransport: String?
    /// tunnel device and its MTU while connected
    public var interface: String?
    public var mtu: Int?
    public var version: String?
    public var snapshotVersion: UInt64?
    public var adminKeys: [String]?
    public var binding: String?
    public var bindingError: String?
    public var policies: Int?
    public var flows: Int?
    public var flowsDenied: Int?
    /// Which mesh this node belongs to, when the daemon knows several
    /// (docs/NETWORKS.md); nil with a single network.
    public var networkId: String?
    public var networkName: String?

    public init(state: String) { self.state = state }
}

/// One mesh this device belongs to (GET /v1/networks, docs/NETWORKS.md).
public struct NetworkInfo: Codable, Equatable, Sendable, Identifiable {
    public var id: String
    public var name: String
    public var controlAddr: String
    public var controlServerName: String?
    public var nodeName: String?
    /// its state directory, relative to the daemon's state root; empty for
    /// the network that owns the root
    public var dir: String?
    /// what its control plane said last: a network that is not running has
    /// no control channel to ask
    public var lastEnrollment: String?

    public init(id: String, name: String, controlAddr: String, lastEnrollment: String? = nil) {
        self.id = id; self.name = name; self.controlAddr = controlAddr; self.lastEnrollment = lastEnrollment
    }

    /// what to show: the name, or the address it was never named after
    public var label: String { name.isEmpty ? controlAddr : name }
}

/// The daemon's networks and which one runs.
public struct NetworkList: Codable, Equatable, Sendable {
    public var current: String
    public var networks: [NetworkInfo]
    /// Set when this daemon holds the one network it was given, and says
    /// why (a configuration file, privilege separation, a packet tunnel).
    public var single: String?

    public init(current: String = "", networks: [NetworkInfo] = [], single: String? = nil) {
        self.current = current; self.networks = networks; self.single = single
    }

    public var currentNetwork: NetworkInfo? { networks.first { $0.id == current } }
    /// whether this daemon can be given another network at all
    public var canAdd: Bool { single == nil || single!.isEmpty }
}

/// A network to add (POST /v1/networks).
public struct NewNetwork: Codable, Sendable {
    public var name: String
    public var controlAddr: String
    public var controlServerName: String?
    public var nodeName: String?
    /// switch to it as soon as it is stored, coming up in `profile`
    public var select: Bool
    public var profile: String?

    public init(name: String, controlAddr: String, controlServerName: String? = nil, nodeName: String? = nil, select: Bool = false, profile: String? = nil) {
        self.name = name; self.controlAddr = controlAddr; self.controlServerName = controlServerName
        self.nodeName = nodeName; self.select = select; self.profile = profile
    }
}

public struct EnrollStatus: Codable, Sendable {
    public var nodeId: String?
    public var name: String?
    public var status: String
    public var fingerprint: String?
    public var overlayIp: String?
}

public struct LoginStart: Codable, Sendable {
    public var flowId: String
    public var url: String
}

public struct LoginResult: Codable, Sendable {
    public var status: String  // pending | done | failed
    public var error: String?
}

public struct DaemonSettings: Codable, Sendable {
    public var controlAddr: String
    public var controlServerName: String?
    public var name: String?
    public init(controlAddr: String, controlServerName: String? = nil, name: String? = nil) {
        self.controlAddr = controlAddr; self.controlServerName = controlServerName; self.name = name
    }
}

/// What the daemon knows about releases (GET /v1/update). The daemon verifies
/// the release's signature; the app only shows the result and asks it to install.
public struct UpdateStatus: Codable, Sendable, Equatable {
    public var current: String
    public var latest: String?
    public var available: Bool
    public var checkedAt: Date?
    public var error: String?
    public var pageUrl: String?
    public var canInstall: Bool
    public var installHint: String?
    public var installing: Bool?
    /// put in place, the daemon has not restarted from it yet
    public var installed: String?
}

/// What a repair did (POST /v1/repair): the daemon gives this host back what
/// a run that is gone took with it -- the resolver above all -- and applies
/// again what a node that is running should have (R144).
public struct RepairReport: Codable, Sendable, Equatable {
    public var undone: Int
    public var removed: [String]?
    /// entries of a node that is still running: they were left alone
    public var leftAlone: [String]?
    public var reapplied: Bool?
    /// one sentence, ready to show
    public var summary: String
}

struct ErrorBody: Codable {
    var error: String
    /// set when enrolling needs the user to accept this control plane key first
    var controlPin: String?
    enum CodingKeys: String, CodingKey { case error; case controlPin = "control_pin" }
}

public enum DaemonError: Error, LocalizedError, Equatable {
    case unreachable(String)  // no socket, no permission, daemon not running
    case refused(String)      // the daemon answered with an error
    case protocolError(String)
    /// first contact: the control plane presents this key, nothing is pinned yet
    case pinUnconfirmed(String)

    public var errorDescription: String? {
        switch self {
        case .pinUnconfirmed(let fp): return "the control plane presents a key that is not pinned yet: \(fp)"
        case .unreachable(let s): return s
        case .refused(let s): return s
        case .protocolError(let s): return "unexpected answer from the daemon: \(s)"
        }
    }
}

extension JSONDecoder {
    /// Go writes RFC 3339 with up to nine fractional digits; Foundation's
    /// .iso8601 strategy accepts none or exactly three.
    static let daemon: JSONDecoder = {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        d.dateDecodingStrategy = .custom { dec in
            let s = try dec.singleValueContainer().decode(String.self)
            if let t = parseRFC3339(s) { return t }
            throw DecodingError.dataCorrupted(.init(codingPath: dec.codingPath, debugDescription: "not a timestamp: \(s)"))
        }
        return d
    }()
}

func parseRFC3339(_ s: String) -> Date? {
    var str = s
    // cut the fraction to milliseconds
    if let dot = str.firstIndex(of: ".") {
        var end = str.index(after: dot)
        while end < str.endIndex, str[end].isNumber { end = str.index(after: end) }
        let frac = String(str[str.index(after: dot)..<end]).prefix(3)
        str = String(str[..<dot]) + "." + frac.padding(toLength: 3, withPad: "0", startingAt: 0) + String(str[end...])
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.date(from: str)
    }
    return ISO8601DateFormatter().date(from: str)
}
