# CertConcord Passkey Signing Credential Profile — draft 02

> Candidate binding for CertConcord draft 02. This is a working draft, not a final standard. Its requirements apply only when this binding is selected. The [draft architecture](../architecture.md) defines framework scope; the [profile catalog](../profiles.md) records applicability. The draft 02 namespace and wire domain identify experimental formats. Object schema numbers describe field layouts and do not indicate a stable edition.

Status: draft 02. Normative language: English. COMMON-draft-02, DTI-draft-02, DSCP-draft-02, DCP-draft-02 and PRF-KPP-draft-02 apply. Object schema version 1 describes the field layout; the draft 02 domain and profile identifiers govern wire interpretation.

## 1. Purpose and authority

PSCP defines personal signing credentials whose document key is associated with a registered WebAuthn credential. The RA qualifies the subject and approves the exact document public key. The CA issues an MTC/X.509 certificate or a signer mdoc. The WebAuthn authentication key, document key, attestation key, issuer key and PRF material have separate roles.

`CERTCONCORD-PERSON-PASSKEY-SIGN-v1` permits a P-256 document signature after the key-admission and operation-evidence procedures below. It does not change the default independent ML-DSA profile. Policy MUST select the profile explicitly at enrollment, issuance, intent, activation and verification. An ECDSA document signature retains classical algorithm assurance even when an ML-DSA CA, credential seal or archive protects its evidence.

All DTI authority restrictions apply. External identity evidence can be mDL, Photo ID, EUDI PID or an approved custom credential. Evidence admission does not import the external identity issuer into the signing CA's trust chain. A government or other authorized issuer MAY issue this signing profile directly under its own governed identity and signing policy.

## 2. Three Passkey roles

| Role                    | Cryptographic operation                                                                             | Credential and verification                                                                                              |
| ----------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Transaction activation  | The ordinary credential key signs authenticatorData concatenated with SHA-256(clientDataJSON)       | DSCP verifies the ACB challenge and issues a permit for a separately admitted key, including ML-DSA or an HSM key.       |
| Direct document signing | An associated signing key signs the exact container input through a versioned raw-signing extension | PSCP binds child-key attestation, possession, RA approval, certification, the permit and the enclosing parent assertion. |
| Local secret protection | PRF supplies key-derivation material for a purpose-separated vault                                  | PRF-KPP authenticates wrapping metadata and recovery state. A vault unlock does not replace an operation permit.         |

A CA MAY certify an ordinary WebAuthn public key in a separately specified authentication credential. Such certification does not change the message that WebAuthn signs. An ordinary assertion MUST NOT be inserted as a CMS or COSE document signature. A challenge containing a document hash remains assertion evidence and is verified as such.

## 3. Version and algorithm selection

The following wire selections are distinct. Implementations MUST NOT retry another version automatically after failure.

| RRA version identifier    | Extension identifier | Generation ceremonies                 | Upstream revision                                        |
| ------------------------- | -------------------- | ------------------------------------- | -------------------------------------------------------- |
| `previewSign-4`           | `previewSign`        | Registration only                     | Published version 4, 2025-08-26                          |
| `previewSign5-2026-09-09` | `previewSign5`       | Registration or a permitted assertion | Version 5 snapshot 2026-09-09T13:45 at the locked commit |

The W3C PR 2078 `sign` proposal is a separate source revision and is not a wire alias for either selection. Upstream development status does not remove these profiles; `source-lock.json` and `adapter-lock.json` define their exact compatibility boundary.

| Operation algorithm             | Input sent as extension `tbs`                                             | Verification key and signature                     |
| ------------------------------- | ------------------------------------------------------------------------- | -------------------------------------------------- |
| `-9`, ESP256                    | Original container message                                                | P-256, ECDSA with SHA-256                          |
| `-300`, ESP256 split            | SHA-256 of the original container message                                 | P-256, ECDSA with SHA-256 of the original message  |
| `-65539`, selected ARKG preview | SHA-256 of the original container message, plus the pinned ARKG arguments | The individually admitted derived P-256 public key |

The selected adapters receive DER ECDSA signatures. COSE serialization converts them to 64-byte P1363 form; CMS retains DER. Verifiers MUST reject double hashing, changed container bytes, invalid DER and incorrect public keys. The original message, not the already hashed extension input, is supplied to a verifier that performs SHA-256 internally. Operation algorithm identifiers and public-key COSE `alg` identifiers MUST be evaluated separately.

The selected split semantics follow [Split Signing Algorithms for COSE, revision 01](https://datatracker.ietf.org/doc/html/draft-ietf-cose-split-signing-algs-01), including the distinction between a signing operation and the algorithm used to verify its output. The preview value `-300` MUST NOT be represented as an assigned IANA value for ESP256-split or used as the verification algorithm of a resulting signature. ARKG's P-256 derivation and `COSE_Sign_Args` parameters are tied to [ARKG revision 11](https://datatracker.ietf.org/doc/html/draft-bradleylundberg-cfrg-arkg-11) and the locked vendor preview. Their experimental numeric values do not establish final registry assignments. The selected adapters implement only the operations in the table.

## 4. Enrollment context

`PasskeyKeyEnrollment` contains schemaVersion, requestID, TrustDomainID, policyHash, SubjectID, DER subject name, profileID, RP ID, origin, selected version, acceptable operation algorithms, issuedAt and expiresAt. Its lifetime MUST NOT exceed 120 seconds. RequestID and SubjectID are 32-byte values. The WebAuthn generation challenge is `H("PasskeyKeyEnrollment", context)`.

An existing qualified identity evidence hash MAY be included. Otherwise SubjectID identifies the RA's proposed subject record; creating that record confers no identity assurance. The identity presentation can follow CSR possession and bind that exact CSR. Final RA approval MUST bind the independently accepted identity evidence, SubjectID, CSR hash, SPKI hash and Passkey binding hash. This ordering avoids requiring an identity-presentation hash that itself depends on an unfinished CSR.

Enrollment records are authoritative server state. A client MUST NOT supply its own accepted parent registration, trusted authenticator model, status decision or key-assurance level. Registration input requires UV. Assertion-generation input requires UV and exactly one selected, previously admitted parent credential in this adapter.

## 5. Parent and child-key admission

The registration driver requests `residentKey=required`, `requireResidentKey=true` and required user verification. Discoverability is an interaction property; unsigned `credProps` output is not hardware-custody evidence. Admission still verifies the signed parent and child evidence below, and signing selects the exact registered parent ID.

The raw-signing profile requires a device-bound parent credential: BE and BS are clear. Synced Passkeys remain usable for the separate DSCP activation and PRF-KPP profiles. Sync eligibility for the parent MUST NOT be interpreted as portability of an associated signing key.

Admission MUST verify the original parent ceremony's challenge, RP hash, exact origin, type, UP, UV, signature, counter and signed extension output. Registration admission requires packed certificate-backed attestation; `none` and self-attestation are not hardware admission. The parent and child registration attestations MUST resolve to the same trusted attesting SPKI and root in this selected profile. For generation during an assertion, the parent registration MUST come from the server's admitted registration inventory.

The child attestation MUST have a trusted packed x5c statement, P-256 attestation key and `alg=-7`. Its signature covers the original child authenticatorData concatenated with SHA-256 of the original parent clientDataJSON. Admission MUST verify:

1. RP hash, parent flags with AT and ED set, and a zero child sign counter.
2. The expected AAGUID; registration parent and child AAGUIDs match.
3. The handle in attestedCredentialData, including a valid zero-length handle. Nonempty parent credential IDs and child handles have different constraints.
4. The original encoded child COSE public key. Client `publicKey` and `keyHandle` outputs must equal the attested values byte for byte.
5. A signed child extension map containing integer key `4` with value `5`: fixed UP and required UV for every use.
6. The chosen operation algorithm at integer key `3` in the signed parent extension output. The unsigned client copy must agree with it and the requested allowlist.

The selected validator requires a bounded certificate chain, explicit roots, certificate validity, signatures, CA/path-length and key-usage constraints, recognized critical extensions, and current status evidence. A noncritical attestation-certificate AAGUID extension, when present, MUST match. The installed model policy binds AAGUID, root hash, allowed versions and algorithms, non-exportability, custody, approval status and expiry. A vendor name or a successful signature is insufficient.

The authenticated child key is not otherwise coupled to the parent credential by the child attestation format. The possession step in section 6 supplies that missing relationship. Neither an unsigned client extension result nor attestation of a different key can replace it.

## 6. Exact CSR possession and binding

The server freezes a real PKCS #10 CertificationRequestInfo using the admitted document SPKI and approved subject. The possession context contains enrollmentHash, documentKeyID, csrInfoHash, parentCredentialIDHash, keyHandleHash, selected version and algorithm, and additionalArgsHash. The parent challenge is `H("PasskeyKeyPossession", context)`; the raw signing input is the CertificationRequestInfo under section 3's operation semantics.

The verifier MUST verify both the parent assertion and the document-key signature. Integer key `6` in the signed parent extension output MUST equal the returned raw signature. The resulting CSR MUST independently verify under its own SPKI. The ordinary authentication key MUST NOT sign the CSR on behalf of the document key.

The durable `PasskeySigningBinding` commits to the proposed subject and trust domain, policy and profile, CSR, exact SPKI, parent ID and SPKI hashes, RP/origin, version/algorithm, handle and argument hashes, attestation and generation evidence, possession evidence, authenticator-model policy, key assurance and lifetime. The child document SPKI MUST differ from the parent and attestation SPKIs. The binding cannot be activated until the separately authenticated RA and CA have approved and certified it.

## 7. RA and CA consumption

The RA MUST retrieve the admitted binding from its trusted registry, evaluate identity and eligibility, and issue a normal DTI RegistrationAuthorization with additional keyBindingID and keyBindingHash fields. The CA MUST independently resolve that binding, check exact CSR/SPKI, subject, identity evidence, profile, policy and current admission state, and verify the signed RAR. A client-supplied admission object is not a substitute for that resolution.

The same RAR request is idempotent. Conflicting input under an existing request ID fails. MTC cosigning does not bypass the admission recheck before certification. Binding activation verifies the issued representation and its RA commitment; repeating activation with another representation fails. Once ACTIVE, admission permits only retries referring to the original RAR request and cannot authorize a fresh issuance request. Renewal or representation replacement uses a new enrollment and authorization.

## 8. Credential representations

For MTC/X.509, `CERTCONCORD-PERSON-PASSKEY-SIGN-v1` requires P-256, CA=false, digitalSignature and the document-signing EKU. The maximum lifetime is 90 days and MUST NOT exceed the binding's admission lifetime. The critical `id-pe-certconcordPasskeyBinding` extension contains a DER OCTET STRING holding `H("PasskeySigningBinding", binding)`. Its assigned UUID OID is in `registry.json`. Unaware certificate verifiers reject this critical semantic requirement. Issuance-time key assurance and the RAR commitment use the existing DTI extensions. MTC still requires its normal log, inclusion, cosignature and policy validation.

For signer mdoc, `document_key_mode=PASSKEY_KEY` and `profile_id=CERTCONCORD-PERSON-PASSKEY-SIGN-v1`. The issuer-signed signing namespace includes `passkey_binding` and `passkey_binding_hash` in addition to DCP's signing SPKI, subject, purpose, policy and RA commitment. The native holder DeviceKey remains independently admitted and differs from the document key. The binding's RP restriction applies to signing; presentation of the mdoc to another verifier does not grant that verifier raw-key access.

DCP's holder qualification, OpenID4VCI issuance, credential status, independent issuance log and PQ credential seal remain mandatory for the mdoc branch. They do not replace Passkey key admission. Holder assurance and document-key assurance MUST be reported separately. An ordinary identity mdoc cannot acquire this profile merely by being presented.

## 9. Authorization before signing

The selected operation profile is `PREAUTHORIZED_EVIDENCE`:

1. Freeze the document, container input, SIM and ActivationContext.
2. Obtain a fresh ordinary WebAuthn assertion over `H("ActivationContext", activation)`. Verify it, current binding and policy; consume its nonce and counter transactionally.
3. Issue the signed OperationPermit before the raw-signing request. The permit lifetime is at most 30 seconds and does not exceed the ActivationContext.
4. Recheck the permit, certified representation, current key/credential status, exact TBS and purpose. Reserve the operation durably and lock the binding against another unresolved operation.
5. Request the raw signature with challenge `H("PasskeyRawOperation", {schemaVersion:1, permitHash:SHA-512(permit), bindingHash:H("PasskeySigningBinding", binding)})`.
6. Verify the returned raw signature and enclosing parent assertion. Recheck live authority, consume the counter and store the signature, proof and signed receipt atomically before unlocking the binding.

These are two distinct authenticator operations. An implementation MUST NOT promise a single prompt or describe verification performed after the raw-signing call as prior authorization. A local atomic authorization profile would require a separate protected-broker contract; it is not an alias for this profile.

The extension itself does not parse the RRA permit. This profile enforces acceptance of the complete authorized evidence package. It MUST NOT claim that an ordinary browser script prevents all possible private-key use, that generic CMS mathematics proves the permit was enforced inside the device, or that UV proves a trusted visual display. Its baseline SAL is SAL1. Higher activation or trusted-display claims require additional defined evidence.

## 10. Durable execution and reconciliation

An operation ID binds the permit hash, binding ID and exact TBS. Reserving an existing unresolved operation MUST NOT cause another raw-signing invocation. Another pending operation on the same binding is refused. A duplicate completed response returns the original signature and receipt; different response bytes under that operation ID fail.

Lost, malformed or invalid responses leave UNKNOWN_EXECUTION. A subsequently received valid original response MAY reconcile the reservation while its authorization is still valid, without another signer call. An expired permit cannot be renewed by resending the same raw operation. An unresolved key must remain unavailable until an independently supported reconciliation procedure establishes its outcome or the binding is retired. Deleting a local lock is not evidence that signing did not occur.

## 11. Dual proof and evidence closure

The verification dependency is acyclic:

`document -> container TBS + SIM -> activation -> permit -> raw-operation challenge -> raw signature -> parent assertion -> execution receipt -> evidence package`.

The challenge MUST NOT contain the final raw signature or the final package hash. The parent assertion authenticates the returned raw signature through the signed extension output. The receipt commits to that proof, binding, operation, permit, activation, TBS, signature and dispatch/execution times and declares `enforcement=PREAUTHORIZED_EVIDENCE`.

A verifier requires external trust for the credential issuer, activation authority, receipt authority and live or historical status policy. It verifies the certified binding, exact public key, original assertion bytes, RP/origin, challenge, UP/UV, raw signature, permit and all receipt commitments. An untrusted caller cannot supply its own affirmative status or trust decision.

CMS uses the selected ECDSA-with-SHA-256 suite, SHA-256 content digest and SHA-512 ESS certificate commitment. COSE signs the real Signature1 structure and preserves the existing RRA context, SIM, policy and credential headers. `certconcord-ecp-mdoc-passkey-v1` adds a mandatory `PasskeyRawEvidence` object containing the parent assertion and registered public-key evidence. `certconcord-ecp-cms-passkey-v1` adds that same raw-evidence object and a `PasskeySigningBinding` object; the latter must match the certificate's critical commitment and the SIM's SubjectID. Both plans apply the normal document, policy, issuer, status, permit and receipt checks before accepting the raw proof. Removing required evidence or switching to an ordinary evidence plan invalidates the result. A certificate with the critical PSCP extension MUST NOT be accepted under `certconcord-ecp-cms-attested-v1`, even when a caller changes the declared business profile or adapter ID.

Execution time remains a receipt assertion. DSCP timestamp, archive-renewal and historical status rules determine trusted time separately. A PQ seal over classical signing evidence MUST NOT be reported as a PQ document signature.

## 12. ARKG-derived signing keys

The selected preview uses operation `-65539`, seed COSE key type `-65537`, and seed/derivation algorithm `-65700`. The seed's blinding and KEM public keys are separate P-256 points. The seed structure is not a certificate SPKI. A derived P-256 key is certified individually.

Public derivation follows the locked ARKG-P256 source and its independent test vectors. The caller supplies 32 random bytes of IKM. The context is the 64-byte hash of the enrollment hash, parent credential ID hash and seed public-key hash under domain `PasskeyARKGContext`. It is therefore scoped to this enrollment. The algorithm produces an 81-byte ticket; the additional arguments are CBOR `{3:-65539, -3:-65700, -2:context, -1:ticket}`.

The parent credential ID, seed key handle and derivation ticket MUST remain distinct. The server recomputes the derived public key and requires a document-key CSR signature using the ticket before RA certification. Public derivation alone does not authorize an issuer, establish identity, prove private-key possession or permit unbounded certificate issuance. This profile does not enable unattended batch certification of future derived keys. Each additional key follows the same bounded enrollment and RA approval procedure.

## 13. Lifecycle, loss and recovery

Enrollment states are PENDING, POSSESSION_REQUIRED, ADMITTED and ACTIVE. A signed `PasskeyBindingChange` from the configured RA binds the trust domain, policy, exact binding ID, current state revision, status, reason and a maximum 120-second authorization interval. It can suspend or revoke a binding. REVOKED is terminal. Suspension can be escalated to revocation; replacement requires new evidence and certification.

Parent compromise or loss MAY cascade to all its child bindings. The local authority gate MUST stop those operations immediately, before asynchronous external status publication completes. The signed command and affected inventory remain durable. Parent revocation is terminal and MUST NOT be replaced by a later child's suspension. MTC/X.509 status publication merges the affected serials with the complete issuer CRL inventory; it MUST preserve unrelated revocations, the earliest recorded revocation time, the earliest recorded invalidityDate and monotonically increasing CRL numbers. A permanent revocation MUST NOT be downgraded to certificateHold. Mdoc publication sets the corresponding issued credential's status bit. Publication failures remain pending and MUST NOT restore signing authority.

The issuance inventory MUST retain the original binding, certificate or mdoc, RAR, exact proof bytes and status history. A newly approved Passkey, a recovered application account or a name/email match MUST NOT inherit the lost key's identity or signing authority. Recovery requalifies the same subject under RA policy, admits a new key, issues a new credential and links the succession history. Past signatures retain their original keys and validation times.

## 14. WebKit Remote CryptoKeys

The locked WebKit proposal defines `crypto.subtle.getRemoteKey(params, ["sign"])` and subsequent `subtle.sign` use. Its adapter is separate from RRA's existing HTTPS RemoteCryptoKey service. The browser driver requires the exact available API, a nonextractable handle, sign-only usage, the selected keyId when supplied, and a signature that verifies under the previously admitted SPKI. The P-256 adapter uses WebCrypto's ECDSA/SHA-256 message semantics and P1363 output.

The proposal does not define an RRA enrollment, attestation or permit transport to the platform. A deployment using that provider MUST obtain exact-key admission through its configured platform evidence and MUST connect its protected provider to the normal DSCP permit boundary. A nonextractable CryptoKey alone does not establish key location or custody. Browser absence produces REMOTE_CRYPTOKEY_UNAVAILABLE; it MUST NOT fall back to a generated software key. The API adapter does not implement or impersonate a browser vendor's platform broker.

## 15. Display, privacy and retention

The application displays the frozen SIM and provides access to the exact document before activation. Authenticated display metadata may supplement the SIM, but a title, screenshot or display receipt MUST NOT replace the container digest and exact TBS. The baseline authenticator prompt is not a trusted transaction display.

Key handles, parent IDs, attestation evidence and ARKG tickets are operationally sensitive correlation material. They stay in the access-controlled enrollment/provider exchange and private evidence store. Public certificates expose the binding commitment; they do not publish raw parent IDs or handles. Mdoc issuers and wallets apply selective disclosure to the signing namespace. RP-scoped keys and pseudonymous SubjectIDs SHOULD minimize cross-site correlation. PRF outputs and vault secrets MUST never enter the CA exchange.

## 16. Required failure behavior

Absent capability, extension error, version confusion, untrusted attestation, missing fixed UV, nonadmitted parent, algorithm mismatch, key substitution, invalid CSR possession, expired context, replay, wrong RA/profile, credential or parent revocation, missing raw evidence, changed document and failed receipt verification MUST fail closed. Error reports SHOULD identify the failed boundary without disclosing secret key material, credential-existence details to unauthorized callers or private identity evidence.

## 17. Implementation and evaluation

`raw-signing.mjs` implements admission and proof verification. `passkey-credentials.mjs` implements enrollment, issuer bindings, lifecycle, preauthorized dispatch and offline operation verification. `arkg.mjs` implements public derivation. `browser.mjs` supplies the selected platform calls. The existing RA, CA/MTC, identity, signer-mdoc, CMS and evidence modules consume these contracts.

Evaluation includes upstream ARKG vectors, independent PKCS #10/CMS verification, real cryptographic dual proofs, negative inputs, counters, replay, durable state and signed status changes. Software authenticator fixtures evaluate the protocol. Physical authenticator, browser/SDK and platform acceptance records MUST identify the actual versions, attestation roots/models and observed successful operations before those deployments claim device support.

## 18. Proposed permit-aware platform semantics

[EBP draft 02 section 8](EBP-draft-02.md#8-proposed-platform-interfaces) proposes permit-bound authenticator operations and Remote CryptoKey operation contexts. Those interfaces would add authenticated provider policy, protected freshness/single-use enforcement and returned execution evidence to the present APIs. They are RRA proposals; current previewSign/previewSign5 and generic Remote CryptoKey calls retain their pinned semantics. Existing PREAUTHORIZED_EVIDENCE remains supported. Enabling a broker-only EBP plan MUST NOT omit the parent assertion or claim the authenticator enforces an RRA permit.
