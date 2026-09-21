import Foundation
import Security

/// The device key: ECDSA P-256 in the Secure Enclave, kept in the keychain
/// group the app and its packet tunnel share. The app creates it; the tunnel
/// only uses it. It can sign after the first unlock, without user presence:
/// the tunnel reconnects while the phone is locked in a pocket.
///
/// The simulator has no Secure Enclave; there the key is a software key and
/// says so (kind softkey, not hardware-bound), like the Mac daemon's softkey.
final class DeviceKey: @unchecked Sendable {
    let key: SecKey
    let kind: String
    let hardwareBound: Bool

    private static let tag = Data("boundgate.device-key".utf8)

    private init(key: SecKey, kind: String, hardwareBound: Bool) {
        self.key = key; self.kind = kind; self.hardwareBound = hardwareBound
    }

    #if targetEnvironment(simulator)
    private static let token: CFString? = nil
    private static let kindName = "softkey"
    #else
    private static let token: CFString? = kSecAttrTokenIDSecureEnclave
    private static let kindName = "secure-enclave"
    #endif

    /// The existing key, or a new one when create is set (the app, never the tunnel).
    static func load(create: Bool) throws -> DeviceKey {
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag: tag,
            kSecAttrAccessGroup: AppConfig.keychainGroup,
            kSecReturnRef: true,
        ]
        var ref: CFTypeRef?
        let st = SecItemCopyMatching(query as CFDictionary, &ref)
        if st == errSecSuccess, let ref {
            return DeviceKey(key: ref as! SecKey, kind: kindName, hardwareBound: token != nil)
        }
        guard st == errSecItemNotFound else { throw keychainError(st) }
        guard create else { throw CoreError("this device has no key yet: open the BoundGate app first") }

        var cfErr: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                                           token != nil ? .privateKeyUsage : [], &cfErr) else {
            throw CoreError("device key: \(cfErr!.takeRetainedValue())")
        }
        var attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrAccessGroup: AppConfig.keychainGroup,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: true, kSecAttrApplicationTag: tag, kSecAttrAccessControl: access] as [CFString: Any],
        ]
        if let token { attrs[kSecAttrTokenID] = token }
        guard let k = SecKeyCreateRandomKey(attrs as CFDictionary, &cfErr) else {
            throw CoreError("device key: \(cfErr!.takeRetainedValue())")
        }
        return DeviceKey(key: k, kind: kindName, hardwareBound: token != nil)
    }

    /// Deletes the key: the next start is a new identity that enrolls again.
    static func delete() {
        let query: [CFString: Any] = [kSecClass: kSecClassKey, kSecAttrApplicationTag: tag, kSecAttrAccessGroup: AppConfig.keychainGroup]
        SecItemDelete(query as CFDictionary)
    }

    /// DER SubjectPublicKeyInfo: the fixed P-256 header and the X9.63 point.
    func publicKeyDER() throws -> Data {
        guard let pub = SecKeyCopyPublicKey(key) else { throw CoreError("device key: no public key") }
        var cfErr: Unmanaged<CFError>?
        guard let point = SecKeyCopyExternalRepresentation(pub, &cfErr) as Data? else {
            throw CoreError("device key: \(cfErr!.takeRetainedValue())")
        }
        guard point.count == 65 else { throw CoreError("device key: not an uncompressed P-256 point") }
        let header: [UInt8] = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                               0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]
        return Data(header) + point
    }

    /// Signs a SHA-256 digest; ASN.1 DER signature.
    func sign(digest: Data) throws -> Data {
        guard digest.count == 32 else { throw CoreError("device key: not a SHA-256 digest") }
        var cfErr: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureDigestX962SHA256, digest as CFData, &cfErr) as Data? else {
            throw CoreError("device key: \(cfErr!.takeRetainedValue())")
        }
        return sig
    }
}

private func keychainError(_ st: OSStatus) -> CoreError {
    if st == errSecMissingEntitlement {
        return CoreError("device key: this build is not signed with the shared keychain group (\(AppConfig.keychainGroup)); sign it with the team's provisioning profile")
    }
    let text = (SecCopyErrorMessageString(st, nil) as String?) ?? "keychain error"
    return CoreError("device key: \(text) (\(st))")
}
