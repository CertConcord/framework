import Foundation
import Security
import CryptoKit
import LocalAuthentication

public enum HolderKeyError: Error { case invalidAlias, unavailable, operation(OSStatus), encoding }
public final class AppleSecureEnclave {
    private func tag(_ alias: String) throws -> Data {
        guard alias.range(of: "^certconcord-[A-Za-z0-9_-]{8,100}$", options: .regularExpression) != nil else { throw HolderKeyError.invalidAlias }
        return Data(("org.certconcord.holder." + alias).utf8)
    }
    public init() {}
    public func generate(alias: String) throws -> [String: String] {
        guard !alias.hasPrefix("certconcord-managed-") else { throw HolderKeyError.invalidAlias }
        guard SecureEnclave.isAvailable else { throw HolderKeyError.unavailable }
        let lookup: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: try tag(alias), kSecReturnAttributes as String: true, kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail]
        var existing: CFTypeRef?
        let lookupStatus = SecItemCopyMatching(lookup as CFDictionary, &existing)
        guard lookupStatus == errSecItemNotFound else { throw HolderKeyError.operation(lookupStatus == errSecSuccess ? errSecDuplicateItem : lookupStatus) }
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &error) else { throw error!.takeRetainedValue() }
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits as String: 256, kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave, kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true, kSecAttrApplicationTag as String: try tag(alias), kSecAttrAccessControl as String: control]]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else { throw error!.takeRetainedValue() }
        return try jwk(key: key)
    }
    private func managedIdentity(fingerprint: String, reason: String) throws -> SecKey {
        guard fingerprint.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else { throw HolderKeyError.invalidAlias }
        let context = LAContext(); context.localizedReason = reason
        let query: [String: Any] = [kSecClass as String: kSecClassIdentity, kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnRef as String: true, kSecUseAuthenticationContext as String: context]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let identities = result as? [SecIdentity] else { throw HolderKeyError.operation(status) }
        for identity in identities {
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate = certificate else { continue }
            let hash = SHA256.hash(data: SecCertificateCopyData(certificate) as Data).map { String(format: "%02x", $0) }.joined()
            if hash == fingerprint {
                var key: SecKey?
                let keyStatus = SecIdentityCopyPrivateKey(identity, &key)
                guard keyStatus == errSecSuccess, let key = key else { throw HolderKeyError.operation(keyStatus) }
                guard SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256) else { throw HolderKeyError.unavailable }
                return key
            }
        }
        throw HolderKeyError.unavailable
    }
    private func load(alias: String, reason: String) throws -> SecKey {
        if alias.hasPrefix("certconcord-managed-") { return try managedIdentity(fingerprint: String(alias.dropFirst(12)), reason: reason) }
        let context = LAContext(); context.localizedReason = reason
        let query: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: try tag(alias), kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecReturnRef as String: true, kSecUseAuthenticationContext as String: context]
        var result: CFTypeRef?; let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let result = result else { throw HolderKeyError.operation(status) }
        return result as! SecKey
    }
    private func jwk(key: SecKey) throws -> [String: String] {
        var error: Unmanaged<CFError>?
        guard let pub = SecKeyCopyPublicKey(key), let raw = SecKeyCopyExternalRepresentation(pub, &error) as Data?, raw.count == 65, raw[0] == 4 else { throw HolderKeyError.encoding }
        return ["kty": "EC", "crv": "P-256", "x": Self.base64url(raw.subdata(in: 1..<33)), "y": Self.base64url(raw.subdata(in: 33..<65))]
    }
    public func publicKey(alias: String) throws -> [String: String] { return try jwk(key: load(alias: alias, reason: "Read the credential holder public key")) }
    public func sign(alias: String, message: Data, reason: String) throws -> Data {
        guard message.count <= 8 * 1024 * 1024, !reason.isEmpty else { throw HolderKeyError.encoding }
        let key = try load(alias: alias, reason: reason); var error: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error) as Data? else { throw error!.takeRetainedValue() }
        return try P256.Signing.ECDSASignature(derRepresentation: der).rawRepresentation
    }
    public static func base64url(_ data: Data) -> String { data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
}
