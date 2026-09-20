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

    public init(name: String, addr: String, state: String, error: String? = nil, transport: String? = nil, primary: Bool = false) {
        self.name = name; self.addr = addr; self.state = state; self.error = error; self.transport = transport; self.primary = primary
    }

    public var id: String { name }
    public var connected: Bool { state == "connected" }
}

public struct NodeStatus: Codable, Equatable, Sendable {
    public var state: String
    public var profile: String?
    public var overlayIp: String?
    public var kind: String?
    public var roles: [String]?
    public var user: UserStatus?
    public var loginRequired: Bool?
    public var hubs: [HubStatus]?
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
    public var enrollment: String?
    public var enrollmentError: String?
    public var control: String?
    public var controlError: String?
    public var controlPin: String?
    public var adminKeys: [String]?
    public var binding: String?
    public var bindingError: String?
    public var policies: Int?
    public var flows: Int?
    public var flowsDenied: Int?

    public init(state: String) { self.state = state }
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
