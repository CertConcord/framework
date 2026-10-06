# Native key adapters — draft reference

Native adapters expose P-256 key generation, public-key retrieval and ES256 signing. INDEPENDENT_PQ uses this key for holder proof and a separate ML-DSA provider for documents. DEVICE_KEY uses the same approved P-256 key for a distinct document signature. Both profiles require the [DCP admission and authorization rules](../../spec/bindings/DCP-draft-02.md#22-key-attestation-admission).

## Enrollment contract

1. The RA reserves the authenticated subject, profile, policy and enrollment session. DeviceBindingRegistry creates a one-use challenge valid for at most 120 seconds.
2. The platform generates or certifies the proposed key using the challenge. The enrollment service validates the original platform evidence with key-attestation.mjs.
3. The RA signs DeviceRegistrationAuthorization containing the exact holder/document keys and assessed evidence hash. The holder signs DeviceRegistrationProof. The registry independently validates and consumes both.
4. PersonalMdocCA consumes a scoped RAR and active DeviceBinding before OpenID4VCI issuance. The credential authenticates the key mode and assessment. Activation checks the current binding and platform-authority status again.

JSON transport uses platformEvidenceToJSON/platformEvidenceFromJSON in device-enrollment.mjs. Certificate and TPM byte strings use unpadded base64url in this RRA interface; Android's separate OpenID android_keystore_attestation proof format retains its upstream base64 rules.

## Apple

Prerequisites: macOS with Xcode command-line tools, an available Secure Enclave and an unlocked user session. The provider uses Security, CryptoKit and LocalAuthentication.

```sh
mkdir -p .runtime/native
swiftc native/apple/AppleSecureEnclave.swift native/apple/main.swift -o .runtime/native/certconcord-holder
printf '%s' '{"action":"generate","alias":"certconcord-example01"}' | .runtime/native/certconcord-holder
printf '%s' '{"action":"public","alias":"certconcord-example01"}' | .runtime/native/certconcord-holder
printf '%s' '{"action":"sign","alias":"certconcord-example01","tbs":"aGVsbG8","reason":"Approve this synthetic key test"}' | .runtime/native/certconcord-holder
```

Aliases match certconcord- followed by 8–100 ASCII letters, digits, underscores or hyphens. Generation rejects existing aliases. Application-generated keys use ThisDeviceOnly accessibility and user-presence access control. Signatures are ES256 P1363. Local key generation alone does not satisfy the remote hardware-admission policy.

For hardware-attested enrollment, use the Apple managed ACME flow:

- Configure ACMEService with appleACMEAttestation, a dedicated default profile, an authenticated device-inventory reservation and a create-challenge callback connected to DeviceBindingRegistry.
- Generate a configuration profile with appleManagedProfile. Its HTTPS directory, attested serial/UDID ClientIdentifier, HardwareBound=true, Attest=true, P-256 signing usage and non-extractable key settings are fixed before managed delivery. App access remains restricted.
- Validate the Apple Enterprise Attestation chain, freshness token, device properties, exact identifier and final CSR key. The server retains the evidence for RA enrollment. The resulting management certificate grants no personal signing authority by itself.
- Refer to the app-authorized identity as certconcord-managed- followed by the lowercase SHA-256 of the complete enrollment certificate. AppleSecureEnclave resolves that fingerprint through SecIdentity and refuses an inaccessible identity or unsupported signing operation.

AppleNativeProvider in native-driver.mjs requires an absolute executable path and SHA-256 pin, plus registered public-key pins. holderSigner(provider, keyRef) supplies the asynchronous OpenID holder boundary. Managed-key local UV remains UNASSESSED unless separately established by the activation profile. App Attest is not evidence for an unrelated SecKey.

Build the iOS application:

```sh
xcodebuild -project native/apple/CertConcordHolder.xcodeproj -target CertConcordHolder -configuration Debug -sdk iphonesimulator CODE_SIGNING_ALLOWED=NO build
```

A device installation uses the deployment's signing team, app identity and authorized keychain access. The app accepts the local JSON operations above. OS wallet integration additionally configures provider entitlements, associated domains and an authenticated protocol bridge. Simulator execution cannot satisfy the hardware-admission profile.

### System-mediated mdoc presentment

IdentityDocumentServices provides the system registration and presentment interface for eligible document-provider apps. The [Apple integration contract](../../docs/apple-identity.md) defines its relation to this key provider, platform document-type entitlements, reader/issuer trust identifiers, parsed/raw request verification and separate document approval. The application bridge connects the selected credential and permitted holder operation to this provider; registration metadata cannot establish key custody or signing authority.

## Android

Prerequisites: JDK 17, Gradle 8.11.1, Android SDK Platform 35/build tools, and an Android 11+ device with an enrolled strong biometric. StrongBox selection is explicit; an unavailable StrongBox produces an error.

```sh
gradle --project-dir native/android assembleDebug
adb install native/android/app/build/outputs/apk/debug/app-debug.apk
```

Obtain the enrollment service's challenge before generating the key:

```json
{
  "action": "generate",
  "alias": "certconcord-example01",
  "challenge": "BASE64URL_TEXT_OF_THE_SERVER_CHALLENGE",
  "strongBox": true
}
```

The app passes the exact challenge text as UTF-8 bytes to setAttestationChallenge; it does not base64-decode that text. The response contains jwk, the base64url DER attestation array, and a separate local hardware report. Convert the chain to the RRA evidence shape {format:"android-key",x5c:response.attestation} before calling platformEvidenceFromJSON.

The verifier pins authorized Android attestation roots and current revocation material, including the governed root rotation policy. It validates generated signing-key properties, TEE/StrongBox level, the application package and signing digests, locked verified boot, patch floors and the declared per-use authentication policy. Changing biometric enrollment invalidates applicable keys.

Public and sign requests use the Apple request shapes. Each signature uses BiometricPrompt with a CryptoObject and returns P1363 bytes. The application has no network permission or exported signing service; the wallet owns the authenticated issuer/verifier exchange and exact-operation review.

## Windows

windows-tpm.mjs uses Koffi with ncrypt.dll and Microsoft Platform Crypto Provider. A ready TPM and user permission are required. Construct WindowsTPMProvider, generate a new certconcord- alias or register an existing alias with its SPKI pin, and invoke capabilities/sign through the authorized gateway.

attest(keyRef,{akName,akID,challenge}) issues TPM2_ReadPublic and TPM2_Certify through TBS using a separately enrolled AK. The server's AK record includes its public key, qualified Name, restricted-signing and fixed-key properties, validity, current status and a commitment to independent EK credential-activation or audited enrollment evidence. A submitted key name or self-signed AK cannot populate this registry.

The selected CNG adapter uses password-free TPM_RS_PW sessions and rejects keys requiring a different authorization procedure. TPM errors are returned without fallback. Windows Hello, measured boot and local user verification require their own evidence.

For independent command/response interoperability on Linux:

```sh
node tpm-simulator-check.mjs
```

The command requires swtpm and tpm2-tools. It creates a new isolated software TPM, generates a restricted AK and signing key, submits the same raw ReadPublic/Certify commands, verifies the returned evidence and rejects substitutions. It never connects to a physical TPM.

## PKCS #11

pkcs11.mjs supports the declared PKCS #11 v3.2 EC/ML-DSA mechanisms. Configure the vendor library, slot, PIN provider and immutable key ID/SPKI. CKA_ALWAYS_AUTHENTICATE requires context-specific authentication. An unavailable algorithm produces a capability error.

```sh
PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so node hardware-check.mjs
```

This command requires SoftHSM 2, creates a new isolated token store under .runtime, generates a non-extractable EC key, invokes C_Sign and verifies its result. It does not initialize an existing token. Hardware-assurance policy requires the separate real-device enrollment evidence.

## Wallet and document composition

OpenIDWallet accepts holderPublicKey and an asynchronous holderSigner returning P1363. Native apps bridge this contract only after authenticating the caller/session and freezing the exact message. SigningGateway accepts the same provider under DEVICE_KEY after explicit profile admission; its document interface returns DER ECDSA, and signer-mdoc.mjs converts to COSE's P1363 wire representation.

A public arbitrary-message signing endpoint is prohibited. Credential purpose, DeviceBinding, status, SIM/QTB/ACB, one-use permits and current provider authorization apply to every operation. A platform exposing only DeviceAuthentication or DeviceMAC cannot be advertised as a general document signer.
