// boundgate-sekey: the Secure Enclave side of the device key of a macOS node.
//
// boundgate-node is Go without cgo, and the Secure Enclave is only reachable
// through Apple's frameworks; this helper is the bridge. It holds no state and
// makes no decisions:
//
//   boundgate-sekey available          exit 0 when this Mac has a Secure Enclave
//   boundgate-sekey create             new P-256 key  -> {"blob","public"}
//   boundgate-sekey public  < blob     -> {"public"}
//   boundgate-sekey sign <hex sha256>  < blob -> {"signature"} (ASN.1 DER)
//
// The private key is generated inside the Secure Enclave and never leaves it.
// "blob" is what CryptoKit calls the key's dataRepresentation: the key wrapped
// by this one Secure Enclave, useless on any other machine. The node keeps it
// in its state directory; no keychain is involved, so the root daemon, which
// has no login keychain, can use it. The key is usable without user presence -
// the daemon connects unattended. What the hardware adds is that the key
// cannot be copied off the machine, not that a person approves each use.
//
// Values are base64 (standard, padded), one JSON object on stdout; errors go
// to stderr with exit status 1.
import CryptoKit
import Foundation
import Security

// CryptoKit signs a Digest, and the only public way to get one is to hash a
// message. TLS hands the node a finished SHA-256 digest, so this type carries
// those 32 bytes through.
struct PrehashedSHA256: Digest {
    static var byteCount: Int { 32 }
    let bytes: [UInt8]

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
    var description: String { "SHA256 digest (prehashed)" }
    func hash(into hasher: inout Hasher) { hasher.combine(bytes) }
    static func == (a: PrehashedSHA256, b: PrehashedSHA256) -> Bool { a.bytes == b.bytes }
}

struct Failure: Error, CustomStringConvertible {
    let description: String
    init(_ d: String) { description = d }
}

func readBlob() throws -> Data {
    let input = FileHandle.standardInput.readDataToEndOfFile()
    let text = String(decoding: input, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    guard let blob = Data(base64Encoded: text), !blob.isEmpty else {
        throw Failure("expected the base64 key blob on stdin")
    }
    return blob
}

func emit(_ fields: [String: Data]) throws {
    let out = try JSONSerialization.data(withJSONObject: fields.mapValues { $0.base64EncodedString() }, options: [.sortedKeys])
    FileHandle.standardOutput.write(out)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

func hexBytes(_ s: String) -> [UInt8]? {
    guard s.count % 2 == 0 else { return nil }
    var out: [UInt8] = []
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        guard let b = UInt8(s[i..<j], radix: 16) else { return nil }
        out.append(b)
        i = j
    }
    return out
}

func run(_ args: [String]) throws {
    guard let command = args.first else {
        throw Failure("usage: boundgate-sekey available | create | public | sign <hex sha256>")
    }
    guard SecureEnclave.isAvailable else {
        throw Failure("this Mac has no Secure Enclave (needs Apple silicon or a T2 chip)")
    }
    switch command {
    case "available":
        return
    case "create":
        var cfError: Unmanaged<CFError>?
        // This device only, usable once the machine has been unlocked after
        // boot, no user presence.
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [.privateKeyUsage], &cfError) else {
            throw Failure("access control: \(String(describing: cfError?.takeRetainedValue()))")
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        try emit(["blob": key.dataRepresentation, "public": key.publicKey.x963Representation])
    case "public":
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: try readBlob())
        try emit(["public": key.publicKey.x963Representation])
    case "sign":
        guard args.count == 2, let digest = hexBytes(args[1]), digest.count == PrehashedSHA256.byteCount else {
            throw Failure("sign needs one argument: a SHA-256 digest as 64 hex digits")
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: try readBlob())
        let signature = try key.signature(for: PrehashedSHA256(bytes: digest))
        try emit(["signature": signature.derRepresentation])
    default:
        throw Failure("unknown command \(command)")
    }
}

do {
    try run(Array(CommandLine.arguments.dropFirst()))
} catch {
    FileHandle.standardError.write(Data("boundgate-sekey: \(error)\n".utf8))
    exit(1)
}
