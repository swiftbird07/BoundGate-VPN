import Foundation

/// Talks HTTP/1.0 over the daemon's unix socket. URLSession cannot do unix
/// sockets, and the protocol is tiny: one request per connection, the daemon
/// closes after the answer. Blocking calls; use from a background task.
public struct DaemonClient: Sendable {
    public static let defaultSocket = "/var/run/boundgate/node.sock"
    public let socketPath: String

    public init(socketPath: String? = nil) {
        self.socketPath = socketPath ?? ProcessInfo.processInfo.environment["BOUNDGATE_SOCKET"] ?? Self.defaultSocket
    }

    public func status() throws -> NodeStatus { try call("GET", "/v1/status", timeout: 5) }
    public func profiles() throws -> [String] { try call("GET", "/v1/profiles", timeout: 5) }
    public func configure(_ s: DaemonSettings) throws { let _: [String: String] = try call("POST", "/v1/configure", body: s, timeout: 10) }
    public func reset() throws { let _: [String: String] = try call("POST", "/v1/reset", timeout: 10) }
    /// acceptPin: the control plane fingerprint the user accepted. Without a
    /// pinned key and without it, the daemon answers `.pinUnconfirmed`.
    public func enroll(acceptPin: String? = nil) throws -> EnrollStatus {
        try call("POST", "/v1/enroll", body: acceptPin.map { ["accept_pin": $0] } ?? [:], timeout: 40)
    }
    public func up(profile: String?) throws -> NodeStatus {
        try call("POST", "/v1/up", body: ["profile": profile ?? ""], timeout: 45)
    }
    public func down() throws -> NodeStatus { try call("POST", "/v1/down", timeout: 30) }
    public func login() throws -> LoginStart { try call("POST", "/v1/login", timeout: 30) }
    public func loginWait(flow: String) throws -> LoginResult { try call("GET", "/v1/login/\(flow)?wait=25s", timeout: 40) }
    public func logout() throws -> NodeStatus { try call("POST", "/v1/logout", timeout: 40) }

    // MARK: transport

    private func call<Out: Decodable>(_ method: String, _ path: String, timeout: Int) throws -> Out {
        try call(method, path, body: Optional<[String: String]>.none, timeout: timeout)
    }

    private func call<In: Encodable, Out: Decodable>(_ method: String, _ path: String, body: In?, timeout: Int) throws -> Out {
        var payload = Data()
        if let body {
            let enc = JSONEncoder()
            enc.keyEncodingStrategy = .convertToSnakeCase
            payload = try enc.encode(body)
        }
        var head = "\(method) \(path) HTTP/1.0\r\nHost: node\r\nConnection: close\r\n"
        if body != nil { head += "Content-Type: application/json\r\n" }
        head += "Content-Length: \(payload.count)\r\n\r\n"
        let raw = try roundTrip(Data(head.utf8) + payload, timeout: timeout)

        guard let sep = raw.range(of: Data("\r\n\r\n".utf8)),
              let statusLine = String(data: raw[..<sep.lowerBound], encoding: .utf8)?.split(separator: "\r\n").first else {
            throw DaemonError.protocolError("no HTTP header")
        }
        let parts = statusLine.split(separator: " ")
        guard parts.count >= 2, let code = Int(parts[1]) else { throw DaemonError.protocolError(String(statusLine)) }
        let bodyData = raw[sep.upperBound...]
        if code != 200 {
            let err = try? JSONDecoder().decode(ErrorBody.self, from: bodyData)
            if let pin = err?.controlPin, !pin.isEmpty { throw DaemonError.pinUnconfirmed(pin) }
            throw DaemonError.refused(err?.error ?? "HTTP \(code)")
        }
        do { return try JSONDecoder.daemon.decode(Out.self, from: bodyData) } catch {
            throw DaemonError.protocolError("\(error)")
        }
    }

    private func roundTrip(_ request: Data, timeout: Int) throws -> Data {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw DaemonError.unreachable("socket: \(String(cString: strerror(errno)))") }
        defer { close(fd) }
        var tv = timeval(tv_sec: timeout, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        let cap = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count < cap else { throw DaemonError.unreachable("socket path too long") }
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            for (i, b) in pathBytes.enumerated() { buf[i] = b }
        }
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        if rc != 0 {
            let e = errno
            switch e {
            case ENOENT, ECONNREFUSED: throw DaemonError.unreachable("The background service is not running.")
            case EACCES, EPERM: throw DaemonError.unreachable("No permission to talk to the background service (the socket belongs to the admin group).")
            default: throw DaemonError.unreachable(String(cString: strerror(e)))
            }
        }
        var sent = 0
        try request.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
            while sent < buf.count {
                let n = write(fd, buf.baseAddress! + sent, buf.count - sent)
                if n <= 0 { throw DaemonError.unreachable("write: \(String(cString: strerror(errno)))") }
                sent += n
            }
        }
        var out = Data()
        var chunk = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            let n = read(fd, &chunk, chunk.count)
            if n == 0 { break }
            if n < 0 {
                if errno == EINTR { continue }
                throw DaemonError.unreachable(errno == EAGAIN ? "The background service did not answer in time." : "read: \(String(cString: strerror(errno)))")
            }
            out.append(contentsOf: chunk[0..<n])
            if out.count > 8 << 20 { throw DaemonError.protocolError("answer too large") }
        }
        return out
    }
}
