import Foundation

// Local stdin/stdout protocol; no network listener and no exported private key.
do {
    let input = FileHandle.standardInput.readDataToEndOfFile()
    guard input.count <= 12 * 1024 * 1024, let request = try JSONSerialization.jsonObject(with: input) as? [String: Any], let action = request["action"] as? String, let alias = request["alias"] as? String else { throw HolderKeyError.encoding }
    let provider = AppleSecureEnclave(); var result: [String: Any]
    switch action {
    case "generate": result = ["jwk": try provider.generate(alias: alias), "custody": "SECURE_ENCLAVE", "localUV": true]
    case "public": result = ["jwk": try provider.publicKey(alias: alias)]
    case "sign":
        guard let encoded = request["tbs"] as? String, let reason = request["reason"] as? String else { throw HolderKeyError.encoding }
        let normalized = encoded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard let message = Data(base64Encoded: normalized + String(repeating: "=", count: (4 - normalized.count % 4) % 4)) else { throw HolderKeyError.encoding }
        result = ["signature": AppleSecureEnclave.base64url(try provider.sign(alias: alias, message: message, reason: reason))]
    default: throw HolderKeyError.encoding
    }
    FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]))
} catch { FileHandle.standardError.write(Data("NATIVE_KEY_OPERATION_FAILED\n".utf8)); exit(1) }
