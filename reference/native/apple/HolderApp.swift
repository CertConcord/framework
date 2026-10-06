import SwiftUI
import Foundation

@main
struct HolderApp: App {
    var body: some Scene { WindowGroup { HolderView() } }
}
struct HolderView: View {
    @State private var alias = "certconcord-holder-example01"
    @State private var message = ""
    @State private var output = ""
    private let provider = AppleSecureEnclave()
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Secure Enclave holder key")) {
                    TextField("Key alias", text: $alias).autocapitalization(.none)
                    Button("Create holder key") { execute { try provider.generate(alias: alias) } }
                    Button("Read public key") { execute { try provider.publicKey(alias: alias) } }
                }
                Section(header: Text("Protocol adapter test input")) {
                    Text("Paste the base64url encoded COSE or JWT signing input. Application-generated keys require system user presence. Managed keys follow their installed access policy. This screen does not establish a trusted document display.")
                    TextEditor(text: $message).frame(minHeight: 120)
                    Button("Authenticate and sign") {
                        execute {
                            let normalized = message.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
                            guard let bytes = Data(base64Encoded: normalized + String(repeating: "=", count: (4-normalized.count % 4) % 4)) else { throw HolderKeyError.encoding }
                            return ["signature": AppleSecureEnclave.base64url(try provider.sign(alias: alias, message: bytes, reason: "Approve use of the RRA credential holder key"))]
                        }
                    }
                }
                Section(header: Text("Public result")) { Text(output).font(.system(.footnote, design: .monospaced)).textSelection(.enabled) }
            }.navigationTitle("RRA Holder Adapter")
        }
    }
    private func execute(_ operation: () throws -> [String: String]) {
        do { output = String(data: try JSONSerialization.data(withJSONObject: operation(), options: [.sortedKeys, .prettyPrinted]), encoding: .utf8) ?? "ENCODING_FAILED" }
        catch { output = "KEY_OPERATION_FAILED" }
    }
}
