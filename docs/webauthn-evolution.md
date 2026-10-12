# WebAuthn editions and document trust

## Reference selection

The RRA WebAuthn baseline is the [Level 3 Recommendation of 25 August 2026](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/). The [Level 4 First Public Working Draft of 15 September 2026](https://www.w3.org/TR/2026/WD-webauthn-4-20260915/) is a separately pinned reference. Its publication status does not determine whether an individual mechanism is useful; the selected mechanism, bytes, authority boundary and verification rules determine its integration.

Level 4 section 18.1 identifies three substantive additions or changes relative to that Level 3 baseline. PRF, backup flags, related origins, conditional mediation, JSON serialization, client capability queries and credential signal methods already appear in Level 3. They are not Level 4 additions. Browser and authenticator support must be established for each requested capability; a specification edition is not a runtime capability advertisement.

| Level 4 change                                                     | RRA consequence                                                                              | Implementation boundary                                                                                                                                                          |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Authenticator extension outputs must exclude cleartext PRF results | PRF confidentiality applies to signed authenticator data as well as client extension results | `browser.mjs` rejects actual returned PRF values embedded as cleartext bytes before public assertion or registration serialization.                                              |
| `remoteClientDataJSON` for remote-desktop clients                  | The proxy becomes a trusted participant in origin and RP-ID handling                         | The local enrollment drivers reject this input. A distinct deployment profile is required for a proxy; the existing verifier does not claim to detect all remote mediation.      |
| Virtual Authenticator counter controls                             | Test absent counters, counter changes and rollback independently                             | `interop.test.mjs` exercises zero-to-zero, zero-to-positive, monotonic progress and rollback using signed assertions. These are protocol tests, not browser WebDriver execution. |

The adopted requirements are connected to [DSCP sections 18 and 32](../spec/bindings/DSCP-draft-03.md) and [PRF-KPP section 35](../spec/bindings/PRF-KPP-draft-03.md). [COMMON](../spec/bindings/COMMON-draft-03.md) controls adapter selection and historical interpretation.

## PRF confidentiality across the signed boundary

A WebAuthn assertion signs `authenticatorData || SHA-256(clientDataJSON)`. Authenticator extension outputs, when present, are part of `authenticatorData`. A serializer cannot remove a secret from that signed structure while preserving the signature. The Level 4 requirement closes this distinction between omitting `getClientExtensionResults().prf.results` and ensuring that the signed structure is itself safe to send.

RRA's public serializers select public response fields explicitly and do not use a general `PublicKeyCredential.toJSON()` export. When PRF results are available, they also compare the returned first and second 32-byte results against the original authenticator data or attestation object and reject a cleartext occurrence. The original bytes remain untouched. The check covers the returned byte values; it is not a proof about a malicious client's other encodings, logs, extensions or network activity. The platform must independently satisfy the confidentiality contract.

The CTAP `hmac-secret` encrypted output and the client's decrypted PRF result are distinct values. An encrypted output is not removed merely because it participates in PRF processing. This preserves interoperable signature verification while keeping wrapper keys local. PRF availability still establishes neither hardware custody for an exportable ML-DSA key nor fresh authorization for a document operation.

## Remote desktop delegation

The draft's `remoteClientDataJSON` enables a web remote-desktop client to relay a remote host's WebAuthn ceremony to a local authenticator. The local calling origin and the remote RP origin can differ. The local client uses supplied client-data bytes and delegates the relevant RP-ID/origin checks to the remote client.

The draft gives this capability a default-denied permission and a Permissions Policy default allowlist of `none`. Permission is per origin; a wildcard grant is excluded. The client preserves the original JSON string instead of reconstructing it. The extension has no authenticator extension output; the client reports a boolean indicating that it acted on the request. That boolean is not a signed attestation of the proxy or remote session.

For a document operation, the relevant RRA trust boundaries are:

1. The remote signing application fixes the SIM, actual cryptographic input, expected RP, challenge, subject and operation.
2. A separately admitted proxy authenticates the remote session and transports the exact original client-data bytes. Proxy admission and remote-channel integrity are independent of document-key custody.
3. The RP verifies the assertion against its original transaction and exact allowed origin. Delegation does not authorize replacing that origin with the proxy's hostname or relaxing RP checks.
4. The activation service evaluates the ordinary DSCP authority and lifecycle rules before issuing a permit. The document-signing provider executes only the separately authorized operation.

The local RRA browser drivers do not opt into this delegation and reject `remoteClientDataJSON` in raw-key enrollment options. This is a client configuration boundary, not an assertion-level guarantee of physical locality: a valid assertion alone cannot establish whether a suitably permitted proxy participated. A deployment requiring proven local execution needs additional platform and channel evidence. The remote-desktop mechanism remains a separately selectable integration direction; it is not registered as an executable RRA proxy adapter.

The pinned draft's authentication processing text refers to `pkOptions.rp.id`, whereas `PublicKeyCredentialRequestOptions` uses `rpId`. An implementation must resolve that mapping against the precise client API and interoperating implementation, without treating the discrepancy as permission to omit an RP ID. The original reference bytes remain in the source lock.

## Four different meanings of remote or raw signing

| Mechanism                      | Cryptographic object or operation                                                                                | Required additional authority                                                                              |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Ordinary WebAuthn assertion    | Authentication key signs authenticator and client data                                                           | DSCP binds the challenge to exact operation intent and validates subject/key authority.                    |
| Level 4 `remoteClientDataJSON` | The same assertion structure through a remote-desktop proxy                                                      | Explicit proxy permission, admitted remote context and unchanged RP verification.                          |
| WebKit Remote CryptoKeys       | A WebCrypto handle invokes a platform-supplied key provider                                                      | Exact key admission, certified purpose, protected provider authorization and verified result.              |
| PSCP raw-signing extension     | Separate document key signs selected message or split input; parent assertion authenticates the extension result | Attested parent/child binding, CSR possession, RA issuance, prior permit, dual proof and lifecycle checks. |

Level 4 does not standardize `previewSign`, `previewSign5`, ARKG or general document-signature certificate issuance. The [raw-signing proposal](https://github.com/w3c/webauthn/pull/2078), [Yubico version 4](https://yubicolabs.github.io/webauthn-sign-extension/4/), locked version 5 snapshot and [WebKit explainer](https://github.com/WebKit/explainers/tree/6ce73fa4f91bbe7fb1990b6c1e7276c8dbd12609/remote-cryptokeys) retain their own source identifiers. [PSCP](../spec/bindings/PSCP-draft-03.md) supplies the missing certification, operation and evidence composition, while the independent ML-DSA path remains available.

## Counters and assurance

The draft's new counter controls concern the Virtual Authenticator automation interface. They do not introduce a physical monotonic-counter guarantee. RRA accepts zero when both the stored and returned counters are zero; once a counter is observed, the selected strict activation profile rejects a non-increasing value. Durable parent-counter updates and operation replay prevention remain separate requirements.

Backup eligibility/state, user verification, model attestation, exact key binding and trusted document display also remain independent. A synchronized Passkey may authorize an independent document key under policy; it cannot inherit PSCP's device-bound parent and child-key assurance. A valid UV flag is not evidence that protected hardware displayed the document being signed.

## Verification obligations

The selected implementation verifies credential identity, challenge, exact origin, RP hash, signature, UP/UV, backup consistency and counter policy. It preserves original signed bytes, keeps PRF material local and rejects unknown raw-signing versions. Tests cover the confidential serialization boundary and local-driver delegation boundary alongside complete PSCP enrollment and document evidence.

A client capability response, virtual authenticator, successful software fixture or published draft does not establish target-device behavior. Operational evaluation identifies the actual browser, operating system, authenticator, firmware, extension version and attestation policy. New wire behavior receives a separate adapter and retained historical reader under COMMON; existing signatures are not reinterpreted by changing a source URL.
