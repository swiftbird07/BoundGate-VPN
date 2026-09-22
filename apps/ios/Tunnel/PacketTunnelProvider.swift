import Foundation
import Network
import NetworkExtension
import os
import BoundGateCore

/// The packet tunnel: runs the node (libboundgate) while the user wants the
/// VPN. The node asks for network settings in one piece (apply); the provider
/// hands them to the system and gives the node the utun it got. The app talks
/// to the node through provider messages carrying the daemon's API requests.
final class PacketTunnelProvider: NEPacketTunnelProvider, CorePlatform {
    private let logger = Logger(subsystem: AppConfig.subsystem, category: "core")
    private var engine: CoreEngine?
    private var monitor: NWPathMonitor?
    private let lock = NSLock()
    private var pendingStart: ((Error?) -> Void)?
    private var stopping = false

    // MARK: lifecycle

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        if let f = AppConfig.tunnelErrorFile { try? FileManager.default.removeItem(at: f) }
        do {
            let key = try DeviceKey.load(create: false)
            // 50 MiB is the limit for the whole process; the Go heap gets 30 of it
            let config = try AppConfig.engineConfig(autoUp: true, memoryLimitMiB: 30)
            // the app stops its own engine right before starting the tunnel;
            // give it a moment to let go of the state directory
            var tries = 0
            while true {
                do {
                    engine = try CoreEngine(config: config, platform: self, key: key)
                    break
                } catch where error.localizedDescription.hasPrefix("embed: busy") && tries < 20 {
                    tries += 1
                    Thread.sleep(forTimeInterval: 0.25)
                }
            }
        } catch {
            logger.error("start: \(error.localizedDescription, privacy: .public)")
            Self.record(error.localizedDescription)
            completionHandler(error)
            return
        }
        logger.info("core \(CoreEngine.version, privacy: .public) started")
        lock.lock(); pendingStart = completionHandler; lock.unlock()
        // the node brings the overlay up once it has its snapshot; if it
        // cannot (not approved, control plane unreachable) the tunnel ends
        // with the node's own explanation
        DispatchQueue.global().asyncAfter(deadline: .now() + 25) { [weak self] in
            guard let self else { return }
            self.lock.lock(); let waiting = self.pendingStart != nil; self.lock.unlock()
            if waiting { self.finishStart(CoreError(self.startProblem())) }
        }
        let m = NWPathMonitor()
        var first = true
        m.pathUpdateHandler = { [weak self] _ in
            if first { first = false; return }
            self?.engine?.networkChanged()
        }
        m.start(queue: DispatchQueue(label: "boundgate.path"))
        monitor = m
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lock.lock(); stopping = true; lock.unlock()
        monitor?.cancel()
        engine?.stop()
        engine = nil
        finishStart(CoreError("stopped"))
        completionHandler()
    }

    override func sleep(completionHandler: @escaping () -> Void) { completionHandler() }
    override func wake() { engine?.networkChanged() }

    private func finishStart(_ error: Error?) {
        lock.lock()
        let done = pendingStart
        pendingStart = nil
        let s = stopping
        lock.unlock()
        if let error, done != nil, !s {
            logger.error("start: \(error.localizedDescription, privacy: .public)")
            Self.record(error.localizedDescription)
        }
        done?(error)
    }

    /// Leaves the reason for the app (AppConfig.tunnelErrorFile).
    static func record(_ reason: String) {
        guard let f = AppConfig.tunnelErrorFile else { return }
        try? Data(reason.utf8).write(to: f, options: .atomic)
    }

    /// Why the overlay did not come up, in the node's words.
    private func startProblem() -> String {
        guard let engine, let (code, body) = try? engine.request(method: "GET", path: "/v1/status", body: nil, timeout: 5), code == 200,
              let s = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            return "the BoundGate core did not answer"
        }
        for k in ["last_error", "binding_error", "control_error", "enrollment_error"] {
            if let v = s[k] as? String, !v.isEmpty { return v }
        }
        if let e = s["enrollment"] as? String, e != "approved" { return "this device is not approved yet (\(e))" }
        return "the network did not come up within 25 seconds"
    }

    // MARK: CorePlatform

    func apply(settingsJSON: String) throws -> Int32 {
        let s = try JSONDecoder().decode(NetSettings.self, from: Data(settingsJSON.utf8))
        guard let (addr, _) = s.address.splitPrefix() else { throw CoreError("bad overlay address \(s.address)") }
        let ns = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: s.excluded?.first(where: { !$0.contains(":") }) ?? "127.0.0.1")
        let v4 = NEIPv4Settings(addresses: [addr], subnetMasks: ["255.255.255.255"])
        v4.includedRoutes = s.routes.compactMap { r in
            guard let (net, bits) = r.splitPrefix(), !net.contains(":") else { return nil }
            return NEIPv4Route(destinationAddress: net, subnetMask: mask(bits))
        }
        v4.excludedRoutes = (s.excluded ?? []).filter { !$0.contains(":") }.map { NEIPv4Route(destinationAddress: $0, subnetMask: "255.255.255.255") }
        ns.ipv4Settings = v4
        ns.mtu = NSNumber(value: s.mtu)
        let done = DispatchSemaphore(value: 0)
        var failure: Error?
        setTunnelNetworkSettings(ns) { e in failure = e; done.signal() }
        done.wait()
        if let failure { throw failure }
        let fd = bg_utun_fd()
        guard fd >= 0 else { throw CoreError("the system did not open a tunnel device") }
        logger.info("applied \(s.address, privacy: .public), \(s.routes.count) routes, mtu \(s.mtu)")
        finishStart(nil)
        return fd
    }

    /// The overlay went down inside the node (disconnect, revoked): the VPN ends with it.
    func releaseTunnel() {
        lock.lock(); let s = stopping; lock.unlock()
        if !s {
            Self.record(startProblem())
            cancelTunnelWithError(nil)
        }
    }

    func log(level: Int32, line: String) {
        switch level {
        case ..<0: logger.debug("\(line, privacy: .public)")
        case 0..<4: logger.info("\(line, privacy: .public)")
        case 4..<8: logger.warning("\(line, privacy: .public)")
        default: logger.error("\(line, privacy: .public)")
        }
    }

    // MARK: messages from the app

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        DispatchQueue.global().async { [weak self] in
            guard let self, let msg = try? JSONDecoder().decode(AppMessage.self, from: messageData) else { completionHandler?(nil); return }
            var reply: AppReply
            if msg.path == "/x/memory" {
                reply = AppReply(status: 200, body: (try? JSONEncoder().encode(Self.memory())) ?? Data())
            } else if let engine = self.engine, let (code, body) = try? engine.request(method: msg.method, path: msg.path, body: msg.body, timeout: 60) {
                reply = AppReply(status: code, body: body)
            } else {
                reply = AppReply(status: 503, body: Data(#"{"error":"the tunnel's core is not running"}"#.utf8))
            }
            completionHandler?(try? JSONEncoder().encode(reply))
        }
    }

    /// phys_footprint is what iOS holds against the extension's limit.
    static func memory() -> TunnelMemory {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count) }
        }
        let footprint = kr == KERN_SUCCESS ? Double(info.phys_footprint) / 1_048_576 : -1
        return TunnelMemory(footprintMiB: footprint, availableMiB: Double(os_proc_available_memory()) / 1_048_576)
    }
}

/// netcfg.NetworkSettings as the core writes it.
struct NetSettings: Decodable {
    var address: String
    var mtu: Int
    var routes: [String]
    var excluded: [String]?
}

private extension String {
    func splitPrefix() -> (String, Int)? {
        let parts = split(separator: "/")
        guard parts.count == 2, let bits = Int(parts[1]) else { return nil }
        return (String(parts[0]), bits)
    }
}

private func mask(_ bits: Int) -> String {
    let m: UInt32 = bits == 0 ? 0 : ~UInt32(0) << (32 - UInt32(bits))
    return "\(m >> 24 & 255).\(m >> 16 & 255).\(m >> 8 & 255).\(m & 255)"
}
