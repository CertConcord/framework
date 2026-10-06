# CertConcord Implementation Guide

This guide describes the repository's executable examples, module interfaces and verification tools. The [profile catalog](../spec/profiles.md) identifies the applicable specifications; the [adapter catalog](adapters.md) identifies each implementation's supported wire and capability profile.

These examples implement the `certconcord-governed-draft-02` composition and its selected extensions. [FRAMEWORK draft 02](../spec/bindings/FRAMEWORK-draft-02.md) defines how other governance models, issuance mechanisms, protocol editions and wallets can be specified. Runtime support follows the concrete modules and admitted capabilities; a different composition requires its own executable bindings and assessment. The framework's extension model does not cause existing verifiers to accept unknown formats or mechanisms.

The wallet integration follows the selected CertConcord holder contracts; EUDI is an optional ecosystem configuration. Future implementations may adopt another holder architecture or a successor to MTC with incompatible formats and APIs. Continued support for these examples' interfaces is not a condition for that architectural advance.

## Requirements and installation

Use Node.js 24.15 or later within the supported range in [package.json](../reference/package.json), with native ML-DSA and ML-KEM support. Install the pinned dependencies from the repository directory:

```sh
npm ci
```

Generated example state, keys and local databases are stored under the ignored `.runtime/` directory. Examples generate synthetic identities and software keys for their own trust domain.

The independently packaged [verification SDK](../reference/sdk/README.md) exposes `createVerifier` and `profiles` for protocol experiments and interoperability tests. It bundles the same experimental parsers used by the reference implementation, even though it excludes their direct public API. It is not a recommended production verification boundary. Production implementations SHOULD use mature, independently evaluated parser and crypto stacks and MUST retain CertConcord's additional semantic checks, as specified in [SEP section 2](../spec/bindings/SEP-draft-02.md#2-parser-and-execution-boundaries). [Storage](storage.md), [security assurance](assurance.md) and [measurement methods](benchmarks.md) describe the remaining runtime and evidence boundaries.

## Personal mdoc signing example

```sh
npm run demo
```

`foundation-demo.mjs` composes the identity, issuer, wallet, signing and verification modules. It performs the following exchange:

1. Present a synthetic custom identity mdoc to the registration authority and validate it under the selected issuer and typed identity-source policy.
2. Approve the subject and document key, establish the holder binding and issue a personal signer mdoc with its PQ seal and issuance quorum.
3. Deliver the credential through an HTTP OpenID4VCI exchange.
4. Present the credential through OpenID4VP with Qualification Transaction Binding to the requested document operation.
5. Consume a one-use permit, create an ML-DSA COSE document signature and verify its Evidence Closure Package.

The command prints a summary of the credential, document-key mode, algorithm and verification assertions. Its policy accepts the configured activation attestor and reports the execution receipt's declared time. To require trusted time, select a policy and verification plan that validate the necessary timestamp or archive evidence.

### Select a different issuance or signing path

| Command                                                                  | Exchange                                                                                                                                 |
| ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `node foundation-demo.mjs --identity=mdl`                                | Admit the ISO mDL type and namespace under the configured identity policy.                                                               |
| `node foundation-demo.mjs --identity=photoid`                            | Request typed common and Photo ID attributes across two namespaces.                                                                      |
| `node foundation-demo.mjs --identity=pid`                                | Select the EUDI PID ARF 1.4.0 rulebook and its certificate-purpose profile.                                                              |
| `node foundation-demo.mjs --identity=custom`                             | Admit the configured custom identity and membership namespaces; this is the default.                                                     |
| `node foundation-demo.mjs --identity=pid --passkey`                      | Activate the issued ML-DSA document key with a transaction-bound WebAuthn assertion.                                                     |
| `node foundation-demo.mjs --direct`                                      | The identity issuer directly issues a combined identity/signing credential.                                                              |
| `node foundation-demo.mjs --device-key`                                  | The explicit `DEVICE_KEY` profile uses P-256 for holder proof and the separate ES256 document signature.                                 |
| `node foundation-demo.mjs --annex-c`                                     | ISO 18013-7 Annex C carries the holder presentation and RRA transaction binding.                                                         |
| `node foundation-demo.mjs --device-key --direct --annex-c`               | Combines direct issuance, DeviceKey document signing and Annex C presentation.                                                           |
| `node foundation-demo.mjs --identity=pid --raw-passkey --arkg`           | Qualifies a PID, issues a signer mdoc for an ARKG-derived Passkey signing key, then verifies its COSE signature and dual-proof evidence. |
| `node foundation-demo.mjs --identity=photoid --raw-passkey --v4 --split` | Uses version 4 split signing through the same RA/OpenID/mdoc flow.                                                                       |

Options can be combined. For example, `--identity=pid --direct --device-key --passkey` selects a combined PID/signing mdoc, the explicit ES256 document profile and WebAuthn activation. The `--passkey` examples use the software authenticator fixture in `example-authenticator.mjs`; browser integrations use actual credentials as described below.

The example mirror journals run in one process. Deploying an independent mirror quorum requires separate operators and failure domains as defined in DTI and COMMON. Platform key admission and native signing are described in the [native provider guide](../reference/native/README.md).

### Browser interface

```sh
npm start
```

Open `http://127.0.0.1:8787` and select **Run example**. The page invokes the same personal mdoc signing exchange and displays its result. Each run generates its own sample identity, document and software keys. `PORT` selects another local port; the server binds to `127.0.0.1` and requires a matching origin and per-process request token.

## MTC certificate and CMS signing example

```sh
npm run demo:mtc
node demo.mjs --passkey
node demo.mjs --authorization-code --annex-c
```

`demo.mjs` composes RA approval, MTC certificate issuance, document authorization, ML-DSA CMS signing and evidence verification. `--passkey` selects HUMAN_WEBAUTHN document activation. The other activation path uses an auxiliary qualification credential and native-holder proof; `--authorization-code --annex-c` selects the authorization-code issuance flow and Annex C presentation. The document certificate and container follow the MTC and CMS adapters in every case.

## Passkey-associated certificate example

```sh
npm run demo:passkey
npm run demo:passkey -- --v4 --split --mtc
npm run demo:passkey -- --arkg
```

`passkey-demo.mjs` executes PSCP admission, genuine PKCS #10 possession, scoped RA approval, X.509 or MTC issuance, WebAuthn activation, raw signing, CMS construction and dual-proof verification. `--v4` selects the version 4 extension; the default selects the pinned version 5 snapshot. `--split` selects the prehash operation, and `--arkg` selects public derivation followed by individual key certification. These two algorithm options are mutually exclusive. `--mtc` adds MTC inclusion with the separately specified CertConcord operator policy and quorum. These raw-signing paths are optional experiments; ordinary `--passkey` activation of a separate key needs none of these proposals.

The mdoc equivalent uses `foundation-demo.mjs --raw-passkey`, with the same version and algorithm options, any configured identity type and optional direct issuance. It issues a native signer mdoc through OpenID4VCI and verifies a separate COSE document signature. Its evidence package contains no personal X.509 certificate. The fixture's parent, document and attestation private keys are ephemeral software keys; platform deployment replaces the fixture with an actual supported authenticator and trusted attestation policy. See [the Passkey signing guide](passkey-signing.md).

## Passkey, WebAuthn and PRF integration

The browser interfaces are exported from [browser.mjs](../reference/browser.mjs). Use a secure context and the RP ID/origins registered for the application. Registration and transaction challenges originate at the authorization service and are consumed under the COMMON state-machine rules.

| Interface                                                     | Purpose and integration rule                                                                                                                             |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `publicRegistration(credential)`                              | Serialize the public response from `navigator.credentials.create` for server-side registration verification and enrollment.                              |
| `publicAssertion(credential)`                                 | Serialize the public response from `navigator.credentials.get`; extension secrets are excluded.                                                          |
| `evaluatePRF({credentialID, rpID, challenge, first, second})` | Evaluate the selected credential's PRF inputs using `evalByCredential` and required UV; returns a public assertion and local secret outputs.             |
| `prfInput(header)`                                            | Construct the exact PRF-KPP input for the selected domain, subject, credential, purpose and epoch.                                                       |
| `wrapRoot(prf, root, header)` / `unwrapRoot(prf, wrapper)`    | Protect a local random root with WebCrypto HKDF and authenticated AES-GCM; ciphertext and authenticated public metadata may be stored remotely.          |
| `createRawSigningKey(options, profile)`                       | Generate the separate signing key during registration using the explicitly selected version 4 or 5 wire.                                                 |
| `generateRawSigningKey(options, profile)`                     | Generate a key during a version 5 assertion from one already admitted parent credential.                                                                 |
| `rawSign(request)`                                            | Sign exact message or prehash bytes through the selected extension, including required ARKG arguments; return public parent assertion and raw signature. |
| `getRemoteSigningKey(params)` / `remoteCryptoSign(request)`   | Call the locked WebKit proposal and verify its P1363 signature under the admitted SPKI; the platform supplies the protected provider.                    |

For HUMAN_WEBAUTHN signing, freeze the SIM and exact document input, obtain the corresponding activation challenge, and request a fresh assertion with the selected credential. The service calls `authorizeHumanActivation` in [webauthn.mjs](../reference/webauthn.mjs) with the current registered credential and authority binding. Successful verification and one-use consumption produce the permit checked by `SigningGateway`. The same authorization path applies to MTC/CMS and signer-mdoc/COSE documents.

PRF evaluation has a separate purpose: derive a local wrapper key from the actual authenticator output. Send only its public assertion through the authenticated server channel; keep PRF outputs, unwrapped roots and capability private keys local. Apply the complete PRF-KPP wrapper and rotation rules before persisting or changing a protector. Unlocking a software signing vault does not bypass the document's activation or provider controls. Native non-exportable keys remain in their platform provider.

PSCP uses `PasskeySigningRegistry.begin`, `stage` and `finish` to bind enrollment, attestation and CSR possession. Trusted RA and issuer instances resolve that registry themselves. `activate` or `activateMdoc` validates the issued representation against the immutable admission. `PasskeySigningService.begin` accepts a permit already issued by the activation authority and reserves the raw operation; `complete` checks the parent/raw proofs and current authority before committing the result and receipt. It must share the registry's transactional journal. Its authenticated `authorize` callback and certificate/mdoc/status resolvers come from the trust service, never from the requesting browser.

`change` consumes an RA-signed lifecycle command. `publishPasskeyCRL` merges affected certificate serials with the complete issuer inventory and retained revocations. `PersonalMdocCA.publishPasskeyStatus` publishes the corresponding native credential status changes. Hosts publish these signed outputs through their configured endpoints and retain their history. Local authorization stops immediately on the binding or parent change, even while publication is pending. UNKNOWN_EXECUTION retains the operation lock; a valid original response can reconcile it without a second signing request while its authorization remains valid.

## Identity rulebook configuration

[identity-profiles.mjs](../reference/identity-profiles.mjs) provides admission presets for `mdl`, `photoid`, `pid` and `custom`. A configured profile declares exact namespace/element paths and value types, its certificate-purpose profile and status policy. The presets describe the disclosed admission subset; an issuer applies its complete issuance schema separately.

Claims may be requested as `[namespace, element]` pairs. A legacy string selects an element in the configured primary namespace. Both `PresentationVerifier` and `AnnexCVerifier` group requests by namespace, validate the exact returned disclosure and retain the profile commitment. The RA receives `namespaces` with the original namespace separation; the primary-namespace `claims` view is retained for existing callers. A changed profile invalidates an outstanding request before consumption.

An issuer registry additionally supplies authorized roots/DS certificates and a status validator. A custom schema does not create identity assurance by itself. See [DCP section 11](../spec/bindings/DCP-draft-02.md#11-external-identity-admission) for admission policy and [EUDI architecture](eudi-architecture.md) for the PID and wallet mapping.

## Integration interfaces

The examples show how to construct the modules with explicit trust registries, policies and authority callbacks. Integrators provide authenticated sessions, approved identity decisions, current issuer/key status and restricted access to signing providers.

| Responsibility                                 | Entry point                                                                                                                                                                                      |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| External identity intake                       | `IdentityAdmission` and `identityCRLValidator` in [identity.mjs](../reference/identity.mjs)                                                                                                      |
| Typed identity admission rules                 | `identityProfiles`, `identityClaimPaths` and `validateIdentityClaims` in [identity-profiles.mjs](../reference/identity-profiles.mjs)                                                             |
| Personal signing-credential issuance           | `PersonalMdocCA` in [signer-mdoc.mjs](../reference/signer-mdoc.mjs)                                                                                                                              |
| Native credential transparency                 | `CredentialLog` in [credential-log.mjs](../reference/credential-log.mjs)                                                                                                                         |
| Holder/document-key registration               | `DeviceBindingRegistry` in [bridge.mjs](../reference/bridge.mjs) and the enrollment interfaces in [device-enrollment.mjs](../reference/device-enrollment.mjs)                                    |
| Passkey signing-key admission and lifecycle    | `PasskeySigningRegistry`, `publishPasskeyCRL` in [passkey-credentials.mjs](../reference/passkey-credentials.mjs) and attestation verification in [raw-signing.mjs](../reference/raw-signing.mjs) |
| Passkey preauthorized signing and verification | `PasskeySigningService`, `verifyPasskeyOperation` in [passkey-credentials.mjs](../reference/passkey-credentials.mjs)                                                                             |
| Credential issuance and wallet exchange        | OpenID issuer interfaces in [openid.mjs](../reference/openid.mjs) and `OpenIDWallet` in [wallet.mjs](../reference/wallet.mjs)                                                                    |
| Presentation validation                        | `PresentationVerifier` in [openid.mjs](../reference/openid.mjs) or `AnnexCVerifier` in [annex-verifier.mjs](../reference/annex-verifier.mjs)                                                     |
| Durable operation state and signing dispatch   | `Journal` and `SigningGateway` in [state.mjs](../reference/state.mjs)                                                                                                                            |
| Native document verification                   | `verifyMdocSignaturePackage` in [signer-mdoc.mjs](../reference/signer-mdoc.mjs)                                                                                                                  |

`CredentialIssuer` is the lower-level OpenID protocol engine. A personal signing-credential integration uses `PersonalMdocCA` to enforce scoped RA approval, the device/document-key relationship, signing purpose, credential seal and transparency requirements. `RRACredentialIssuer` provides the auxiliary qualification credential profile.

For a native holder, supply `holderPublicKey` and an asynchronous `holderSigner` to `OpenIDWallet`. The helper `holderSigner(provider, keyRef)` in [native-driver.mjs](../reference/native-driver.mjs) adapts the provider's signature representation and verifies the returned signature against the pinned key. The caller/session must be authenticated before invoking a key operation. An unavailable hardware capability returns an error without substituting a software key under the same assurance claim.

The local journal uses SQLite transactions. Another persistence implementation must preserve atomic authorization consumption, monotonic trust state, immutable results and the remote-provider reconciliation rules. [SECURITY.md](../SECURITY.md) describes these integration boundaries.

## Verification tools

Run the protocol tests and source-integrity checks:

```sh
npm test
npm run check
```

`npm test` uses Node's test runner. Test inputs include generated cryptographic keys, deterministic vectors, authenticated local HTTP exchanges, independent encoders/verifiers and failure cases.

| Area                                  | Test modules and inputs                                                                                                                                                                                                                          |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Encoding and cryptographic separation | `core.test.mjs`, `protocols.test.mjs`: exact bytes, malformed encodings, key/purpose substitution and authenticated-encryption failures                                                                                                          |
| Root state and mirror policy          | `protocols.test.mjs`, `transparency.test.mjs`, `lifecycle.test.mjs`: stale/fork decisions, quorum, consistency and revocation intervals                                                                                                          |
| Enrollment and status                 | `authority.test.mjs`, `enrollment-network.test.mjs`: signed CSR/RAR, one-use KEM possession, ACME/CMP HTTP, CRL and OCSP                                                                                                                         |
| Hardware key admission                | `key-attestation.test.mjs`, `device-enrollment.test.mjs`, `tpm-wire.test.mjs`: exact SPKI, challenge/session binding, platform policy and managed ACME CSR binding                                                                               |
| Holder and credential binding         | `adapters-network.test.mjs`, `mdoc.test.mjs`: wrong domain/holder/epoch, caller-created claims, revoked binding and issuer/device digest tampering                                                                                               |
| OpenID and Annex C                    | `interop.test.mjs`, `mdoc.test.mjs`, `evidence.test.mjs`: nonce/audience/DPoP, selective disclosure, origin/transcript encryption, session completion and transaction binding                                                                    |
| Signing authorization                 | `protocols.test.mjs`, `lifecycle.test.mjs`: exact message/key binding, one-use nonces, atomic batches, enrolled capability and unknown execution                                                                                                 |
| Containers and archive                | `containers.test.mjs`, `independent.test.mjs`, `openssl.test.mjs`: PDF ByteRange, CMS/JWS, timestamp imprint/nonce/EKU, ERS and XMLERS renewal                                                                                                   |
| Provider protocols                    | `authority.test.mjs`, `adapters-network.test.mjs`, `kms.test.mjs`: Remote CryptoKey, CSC and KMS authorization and result integrity                                                                                                              |
| Complete mdoc signing flow            | `foundation.test.mjs`, `foundation-security.test.mjs`: external identity and direct issuance, signer mdoc, PQ seal/log, OpenID delivery, ML-DSA/ES256 signatures and evidence verification                                                       |
| X.509/MTC composition                 | `evidence.test.mjs`: RA approval, MTC, OpenID delivery/presentation, signing permit, CMS and evidence verification                                                                                                                               |
| Passkey signing credentials           | `passkey.test.mjs`: v4/v5 pure/split/ARKG, upstream ARKG vectors, parent/child attestation, CSR admission, MTC/CMS and native mdoc/COSE composition, lifecycle and unknown outcomes; `openssl.test.mjs`: independent EC CSR and CMS verification |

### Independent cryptography and provider checks

The OpenSSL tests require OpenSSL 3.5 or later in `PATH`, or an executable path in `OPENSSL_BIN`. Set `CERTCONCORD_REQUIRE_OPENSSL=1` to require that dependency: a missing executable then fails the test. The [CI workflow](../.github/workflows/ci.yml) builds the pinned OpenSSL version and enables this requirement.

```sh
node hardware-check.mjs
node tpm-simulator-check.mjs
```

`hardware-check.mjs` requires SoftHSM 2 and its library. It creates an isolated token store, calls the PKCS #11 key-generation and signing interfaces and independently verifies the result. `PKCS11_LIBRARY` selects the library path. `tpm-simulator-check.mjs` requires Linux, `swtpm` and `tpm2-tools`; it validates the TPM ReadPublic/Certify exchange against a new software TPM, including key, Name and challenge substitution cases.

Apple and Android builds, physical key operations, attestation enrollment and app-to-wallet integration are documented in [native/README.md](../reference/native/README.md). Protocol tests, native builds and device evaluations provide evidence for different requirements in [CONFORMANCE.md](../spec/bindings/CONFORMANCE-draft-02.md).

## Source and profile integrity

[source-lock.json](../reference/source-lock.json) records upstream URLs, revisions and SHA-256 digests. [adapter-lock.json](../reference/adapter-lock.json) identifies selected wire profiles, modules and tests. [draft-manifest.json](../draft-manifest.json) hashes the published source files.

After an intentional source change, regenerate the manifest and verify it from the repository root:

```sh
npm run draft:manifest
npm run check
```

The check validates published-file hashes, source registry/lock agreement, source-digest syntax, dependency pins, adapter/source references, local documentation links and publication exclusions. It does not download upstream sources or verify their current remote contents.

The [upstream baseline](upstream-baseline.md) records compatibility findings. After reviewing and selecting exact upstream URLs in `reference/sources.mjs`, refresh only the intended records:

```sh
node reference/sources.mjs --refresh c2spCosignature arkgDraft coseSplitSigning
```

Omitting source IDs refreshes the complete registry. The command preserves unselected records, derives the package version locally and replaces the module-relative lock only after every selected retrieval succeeds. Each refreshed record has its own `retrievedAt`; the top-level value is the fallback retrieval time for older records. The manifest is regenerated after reviewing the resulting diff. Changed wire semantics require compatibility review and, where necessary, a new adapter identifier and historical reader; a source refresh alone does not change accepted protocol bytes.
