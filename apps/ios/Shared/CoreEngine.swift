import Foundation
import BoundGateCore
import BoundGateKit

/// What an engine needs from its host besides the key.
protocol CorePlatform: AnyObject {
    /// Install the network settings (JSON of netcfg.NetworkSettings) and
    /// return the tunnel's descriptor.
    func apply(settingsJSON: String) throws -> Int32
    func releaseTunnel()
    func log(level: Int32, line: String)
    /// The node's status (JSON of GET /v1/status) whenever its state, its
    /// enrollment, the need for a sign-in or a hub connection changed.
    func statusChanged(statusJSON: String)
}

extension CorePlatform {
    func statusChanged(statusJSON: String) {}
}

/// The node from libboundgate (docs/EMBED.md). It answers the daemon's API,
/// so the app talks to it with the same DaemonClient as the Mac app.
final class CoreEngine: NodeTransport, @unchecked Sendable {
    private let handle: Int64
    private let context: Unmanaged<Context>
    private let lock = NSLock()
    private var stopped = false

    /// what the C callbacks reach through ctx
    final class Context {
        weak var platform: CorePlatform?
        let key: DeviceKey
        init(platform: CorePlatform, key: DeviceKey) { self.platform = platform; self.key = key }
    }

    static var version: String {
        guard let v = bg_version() else { return "?" }
        defer { bg_free(v) }
        return String(cString: v)
    }

    /// Throws CoreError; one starting with "embed: busy" means the other side
    /// (app or tunnel) holds the state directory.
    init(config: [String: Any], platform: CorePlatform, key: DeviceKey) throws {
        let json = String(data: try JSONSerialization.data(withJSONObject: config), encoding: .utf8)!
        let ctx = Unmanaged.passRetained(Context(platform: platform, key: key))
        var p = bg_platform()
        p.ctx = ctx.toOpaque()
        p.apply = { ctx, settings, err in
            let c = Unmanaged<Context>.fromOpaque(ctx!).takeUnretainedValue()
            guard let platform = c.platform else { err?.pointee = strdup("the tunnel is gone"); return -1 }
            do { return try platform.apply(settingsJSON: String(cString: settings!)) } catch {
                err?.pointee = strdup(error.localizedDescription); return -1
            }
        }
        p.release = { ctx in
            Unmanaged<Context>.fromOpaque(ctx!).takeUnretainedValue().platform?.releaseTunnel()
        }
        p.public_key = { ctx, out, cap, err in
            let c = Unmanaged<Context>.fromOpaque(ctx!).takeUnretainedValue()
            do {
                let der = try c.key.publicKeyDER()
                guard der.count <= Int(cap) else { err?.pointee = strdup("public key too large"); return -1 }
                der.copyBytes(to: out!, count: der.count)
                return Int32(der.count)
            } catch { err?.pointee = strdup(error.localizedDescription); return -1 }
        }
        p.sign = { ctx, digest, n, out, cap, err in
            let c = Unmanaged<Context>.fromOpaque(ctx!).takeUnretainedValue()
            do {
                let sig = try c.key.sign(digest: Data(bytes: digest!, count: Int(n)))
                guard sig.count <= Int(cap) else { err?.pointee = strdup("signature too large"); return -1 }
                sig.copyBytes(to: out!, count: sig.count)
                return Int32(sig.count)
            } catch { err?.pointee = strdup(error.localizedDescription); return -1 }
        }
        p.log = { ctx, level, line in
            Unmanaged<Context>.fromOpaque(ctx!).takeUnretainedValue().platform?.log(level: level, line: String(cString: line!))
        }
        p.status_changed = { ctx, status in
            Unmanaged<Context>.fromOpaque(ctx!).takeUnretainedValue().platform?.statusChanged(statusJSON: String(cString: status!))
        }
        p.hardware_bound = key.hardwareBound ? 1 : 0
        var err: UnsafeMutablePointer<CChar>?
        let h = key.kind.withCString { kind -> Int64 in
            p.key_kind = kind // copied by bg_start
            return bg_start(json, &p, &err)
        }
        if h == 0 {
            ctx.release()
            var msg = "the BoundGate core did not start"
            if let err { msg = String(cString: err); bg_free(err) }
            throw CoreError(msg)
        }
        handle = h
        context = ctx
    }

    func request(method: String, path: String, body: Data?, timeout: Int) throws -> (status: Int, body: Data) {
        var status: Int32 = 0
        let out: UnsafeMutablePointer<CChar>? = method.withCString { m in
            path.withCString { pth in
                if let body, !body.isEmpty {
                    return body.withUnsafeBytes { b in
                        bg_request(handle, m, pth, b.bindMemory(to: UInt8.self).baseAddress, Int32(body.count), &status)
                    }
                }
                return bg_request(handle, m, pth, nil, 0, &status)
            }
        }
        guard let out else { throw DaemonError.unreachable("the BoundGate core did not answer") }
        defer { bg_free(out) }
        return (Int(status), Data(bytes: out, count: strlen(out)))
    }

    func networkChanged() { bg_network_changed(handle) }

    func stop() {
        lock.lock()
        defer { lock.unlock() }
        guard !stopped else { return }
        stopped = true
        bg_stop(handle)
        context.release()
    }

    deinit { stop() }
}

/// A provider message: one request of the node API, from the app to the tunnel.
struct AppMessage: Codable {
    var method: String
    var path: String
    var body: Data?
}

/// The tunnel's answer. status 0 with no body: a question for the tunnel
/// itself (memory) that it answered in body.
struct AppReply: Codable {
    var status: Int
    var body: Data
}

/// Memory of the packet tunnel process: what iOS counts against its 50 MiB.
struct TunnelMemory: Codable {
    var footprintMiB: Double
    var availableMiB: Double
}
