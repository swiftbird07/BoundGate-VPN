import Foundation

/// A copy of the tunnel's log in the app group (tunnel.log, the one before as
/// tunnel.log.1, at most 1 MiB each). The system log of a phone needs a
/// sysdiagnose; this file can be taken from a development build with
///
///   xcrun devicectl device copy from --device <id> \
///     --domain-type appGroupDataContainer --domain-identifier <app group> \
///     --source tunnel.log --destination tunnel.log
///
/// It holds what the system log holds: the core's lines, what the path
/// monitor saw and the settings handed to the system (docs/IOS.md).
final class TunnelLog {
    static let shared = TunnelLog()

    private let queue = DispatchQueue(label: "boundgate.tunnellog")
    private let url: URL?
    private var handle: FileHandle?
    private var size: UInt64 = 0
    private let limit: UInt64 = 1 << 20
    private let stamp: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    private init() {
        url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AppConfig.appGroup)?.appendingPathComponent("tunnel.log")
    }

    func write(_ line: String) {
        let now = Date()
        queue.async { [self] in
            guard let url else { return }
            if handle == nil { open(url) }
            guard let handle else { return }
            let data = Data("\(stamp.string(from: now)) \(line)\n".utf8)
            handle.write(data)
            size += UInt64(data.count)
            if size > limit { rotate(url) }
        }
    }

    private func open(_ url: URL) {
        let fm = FileManager.default
        if !fm.fileExists(atPath: url.path) { fm.createFile(atPath: url.path, contents: nil) }
        handle = try? FileHandle(forWritingTo: url)
        size = (try? handle?.seekToEnd()) ?? 0
    }

    private func rotate(_ url: URL) {
        try? handle?.close()
        handle = nil
        let old = url.appendingPathExtension("1")
        try? FileManager.default.removeItem(at: old)
        try? FileManager.default.moveItem(at: url, to: old)
        open(url)
    }
}
