# CertConcord Digital Signature Certificate Profile — draft 03

> Candidate binding for CertConcord draft 03. This is a working draft, not a final standard. Its requirements apply only when this binding is selected. The [draft architecture](../architecture.md) defines framework scope; the [profile catalog](../profiles.md) records applicability. The draft 03 namespace and wire domain identify experimental formats. Object schema numbers describe field layouts and do not indicate a stable edition.

Status: draft 03. Normative language: English. COMMON-draft-03 and DTI-draft-03 apply.

## 1. Purpose

DSCP binds a qualified signing subject, a purpose-specific key, an exact document scope and a fresh authorization to a verifiable signature. Its protected-provider model includes local software, native device facilities, smart cards, PKCS #11, remote HSMs, CSC, Remote CryptoKey and the pinned WebAuthn raw-signing proposal. Each implementation declares only the capabilities it actually provides.

## 2. Subject and key roles

Personal intentional signatures, personal passive provenance signatures, organization seals and workload signatures use separate keys and authority. A website account, application administrator or ordinary mdoc qualification cannot authorize every role. A subject may hold multiple independent keys; deletion or revocation of one must not silently select another.

## 3. Dependency profile

The native personal credential is the DCP signer mdoc, certifying the document key and explicit INDEPENDENT_PQ, DEVICE_KEY or PASSKEY_KEY mode under DCP sections 2.2–2.3. Its COSE document adapter and PQ seal are defined in DCP sections 12–13; PSCP adds the Passkey key-admission and raw-evidence requirements. An accepted government or other issuer may issue this profile directly, including within a governed combined identity/signing mdoc. Ordinary identity presentation has no implicit document-signing semantics.

CMS/CAdES, PAdES and JAdES each have a fixed adapter. The signer freezes their real input, not a generic application hash substituted for every format. Draft APIs are preserved through declared versions, supported algorithms and negative capability results. Container compatibility does not imply that all viewers support the chosen post-quantum algorithms.

## 4. Provider interface

Providers expose GenerateKey, GetCapabilities, GetAttestation, Sign and GetOperationResult semantics. Capabilities identify keyRef, immutable key version/SPKI, algorithm, input kind, custody, exportability, local UV, attestation and uncertain-result behavior. Generation failures cannot fall back to a software key while retaining a hardware claim.

## 5. Provider authorization boundary

Every conforming Sign invocation is authorized through COMMON ACB. The gateway checks the signed permit against the actual provider key and exact message and reserves the operation durably. A claim of exclusive execution enforcement requires exclusive gateway access to hardware that lacks native permit validation. An unrestricted alternate HSM API invalidates that claim. PSCP separately defines PREAUTHORIZED_EVIDENCE for client-accessible raw keys: the permit precedes signing and the verifier requires the complete dual-proof package. That profile makes no exclusive-execution claim.

## 6. WebAuthn raw-signing adapter

[PSCP-draft-03](PSCP-draft-03.md) defines the full admission, issuance, authorization, lifecycle and evidence contract. The selected adapters distinguish published previewSign version 4 and the locked previewSign5 snapshot, including their generation ceremonies and error outputs. A raw document signature and the parent's signed extension output are both verified. Message-signing, split/prehash and ARKG-derived key inputs retain distinct semantics. Unsupported capability or version produces an error, with no automatic fallback.

The independent document key is certified under CERTCONCORD-PERSON-PASSKEY-SIGN-v1 after attestation and real CSR possession. The first ordinary WebAuthn operation obtains a permit; a second operation returns the raw signature and its parent assertion. A single get() result cannot retroactively establish prior server authorization. The WebKit getRemoteKey adapter remains distinct from the RRA HTTPS RemoteCryptoKey service and requires its own admitted-key and protected-provider composition under PSCP section 14.

## 7. Native device keys

Secure Enclave and Android Keystore adapters use P-256 signing keys with their declared user-authentication policy. Windows CNG/TPM and smart-card providers expose their actual capabilities. DCP DeviceBinding certifies the native holder and document-key relationship. DEVICE_KEY reuses the attested P-256 key only under CERTCONCORD-PERSON-DEVICE-SIGN-v1; the wallet signs a separate document COSE structure after a fresh COMMON permit. Their local UV or hardware properties require appropriate evidence; a valid P-256 signature alone proves neither.

## 8. Remote providers

Remote CryptoKey uses explicit RRA protocol version 1 and exact-message signing. The [CSC 2.2 selection](../../docs/csc.md) uses synchronous ES256 signHash, explicit authorization and a digest-bound SAD. The exact original container input is retained while SHA-256 is sent in `hashes`, with `hashAlgorithmOID`; authentication factors use `authData`. This selection cannot perform pure ML-DSA message signing. PKCS #11 chooses mechanisms explicitly, including versioned ML-DSA parameters where supported. Google KMS keys are pinned by full immutable key-version name and SPKI. Every response is locally signature-verified before acceptance.

## 9. Key generation and enrollment

Key generation precedes final RA approval of that exact SPKI. The subject proves possession and approves the intended profile. The RA assesses identity, key provenance, policy and recovery graph, then signs the RAR. The CA consumes the approval and binds its commitment into the certificate/evidence. A key cannot be swapped after approval by changing a provider alias.

## 10. Profile table

| Profile                    | KeyUsage          | EKU                 | Maximum default validity          |
| -------------------------- | ----------------- | ------------------- | --------------------------------- |
| CERTCONCORD-PERSON-SIGN-v1         | digitalSignature  | certconcordDocumentSigning  | 90 days                           |
| CERTCONCORD-PERSON-PASSKEY-SIGN-v1 | digitalSignature  | certconcordDocumentSigning  | 90 days; bounded by key admission |
| CERTCONCORD-PERSON-COMMIT-v1       | contentCommitment | certconcordDocumentSigning  | 90 days                           |
| CERTCONCORD-ORG-SEAL-v1            | contentCommitment | certconcordOrganizationSeal | 90 days                           |
| CERTCONCORD-SERVICE-SIGN-v1        | digitalSignature  | certconcordServiceSigning   | 30 days                           |
| CERTCONCORD-EVIDENCE-SIGN-v1       | digitalSignature  | certconcordEvidenceSigning  | 30 days                           |

The primary algorithms are pure ML-DSA-65/87. Compatibility suites require a distinct declared adapter/policy and cannot retain a post-quantum claim. Encryption and TSA profiles are not document signing profiles. All X.509 leaves have CA=false and profile-bounded validity. Personal mdoc uses profile_id and allowed_purposes for these role semantics, with the signing SPKI in the issuer-signed namespace and the shorter DCP validity. KeyUsage/EKU are X.509 fields, not invented standard MSO fields.

### 10.1 Native personal mdoc profiles

CERTCONCORD-PERSON-SIGN-v1 uses INDEPENDENT_PQ and ML-DSA-65/87. CERTCONCORD-PERSON-DEVICE-SIGN-v1 uses DEVICE_KEY and ES256; its certified document SPKI MUST equal the MSO DeviceKey SPKI. Both require DOCUMENT_SIGN purpose, live DCP admission, SIM/QTB/ACB and the complete document ECP. The DeviceKey profile is an mdoc profile, not an additional X.509 EKU.

CERTCONCORD-PERSON-PASSKEY-SIGN-v1 adds PASSKEY_KEY: an independently attested P-256 signing key associated with a device-bound Passkey and distinct from the native DeviceKey. PSCP defines its dual-proof permit and evidence contract. Profile selection MUST be explicit at RA approval, issuance, consent, permit and verification. A verifier requiring post-quantum document signatures MUST reject DEVICE_KEY and PASSKEY_KEY. Every mode requires an independently signed document container.

## 11. Certificate subject

For the X.509 representation, the subject name and any pseudonym follow the RA identity policy. A reviewed identity-to-key relationship is distinct from the application display name. Certificates minimize personal data. Historical names remain interpretable through retained evidence; changing a current account profile must not rewrite an old certificate or SIM.

## 12. Key assurance

Key assurance states the assessed provider, key generation, export boundary, attestation policy and recovery policy. Assessment is bound to the exact key, not merely a provider brand. The certificate records issuance-time evidence; current key status and operation activation are checked separately.

## 13. Intent profile

PERSON-SIGN supports explicit per-operation session or stronger authorization. PERSON-COMMIT requires the policy's higher activation level and endorsement. ORG-SEAL requires organizational authority and policy-bound human or workload activation. A passive provenance signature records an authenticated source action and must not be displayed as the person's informed acceptance of document contents.

## 14. Signing Intent Manifest

The SIM schema and one-document scope are defined in COMMON. Its document digest, key, original certificate representation, subject, profile, purpose, origin, policy and transaction ID are immutable. A display name cannot substitute for a document digest. A SIM is not a signature; it becomes evidence only through its cryptographic bindings and authority checks.

## 15. Endorsement

When required, an OrganizationalEndorsement binds simHash, organizationID, profileID, issuedAt and expiresAt under an authorized endorsement certificate. It is a distinct signed control, not a CMS countersignature. A local orchestrator may perform the role only when explicitly authorized by policy. Absence of a required endorsement blocks signing.

## 16. Exact signing input

CMS freezes DER signedAttrs containing contentType, messageDigest, signingCertificateV2 and the mandatory RRA context/SIM/policy attributes. PAdES freezes the PDF ByteRange and then its detached CMS attributes. JAdES freezes the JWS protected header and encoded or unencoded payload exactly as its adapter requires. The resulting message is hashed into ActivationContext.

## 17. No circular commitments

A SIM cannot contain the final signature, a digest of a PDF that embeds that same digest, or an ECP manifest containing its own final container. Activation proofs and execution receipts occur after TBS freezing and therefore remain external or in later evidence layers. Container builders MUST preserve this dependency order.

## 18. Activation proof

WebAuthn activation verifies the exact context challenge, origin, RP ID, UP/required UV, credential registration, current authority, signature and one-use nonce. DCP qualification follows QTB and is bound to the same context. Workload proofs identify a registered workload, allowed purpose and fresh transaction. A successful login is not a reusable operation permit.

HUMAN_WEBAUTHN is available for both MTC/certificate-based signatures and personal signer-mdoc signatures. The registered Passkey's authority MUST resolve to the same SubjectID and document KeyID as the SIM. The authorization service MUST validate the frozen ActivationContext, current binding and required UV before consuming the proof and creating the permit. A credential's backup state or registration attestation does not by itself establish the document key's custody. When the selected signing credential is an mdoc, its issuer/purpose, seal, issuance and current binding/status requirements still apply even if document activation uses WebAuthn.

The WebAuthn authentication key, a PSCP document key and a PRF-unlocked vault key have distinct roles. An assertion signs WebAuthn's authenticator/client-data structure; it authorizes the separately frozen document input through ACB. A raw-signing extension or another DSCP provider creates the document signature. PRF unlock grants access to local protected material and MUST NOT replace the operation's authorization proof.

For HUMAN_MDOC, the authorization service MUST apply DTI section 4.1 and DCP section 8. The credential, current DeviceBinding and SIM MUST resolve to the same SubjectID and document KeyID under the same TrustDomainID and policyHash. Holder key, binding epoch, allowed qualification, browser session and activation_hash MUST match. The verifier result and activation nonce are consumed in one transaction before a permit is issued. A transaction rollback MUST restore both consumptions. Rechecking live authorization before dispatch is mandatory even after successful presentation.

OpenID4VP transaction_data supplies the activation commitment. Annex C supplies the same commitment through authenticated RRA request information and the device-signed RRA namespace; the ISO transport does not acquire an OpenID transaction_data field. Qualification without this additional transaction binding MUST NOT produce a signature permit. HUMAN_MDOC has maximum SAL1 in the 1.0 adapter; a deployment requiring SAL2 selects and verifies the separate WebAuthn activation path in addition to its qualification evidence.

## 19. Optional PRF capability

A separately generated capability signing key may be encrypted in a dedicated PRF-protected vault. Enrollment binds its public key to subject, parent credential, document KeyID and policy. It signs D("CapabilityActivation", {schemaVersion, activationHash, operationID, audience, expiresAt}) in addition to the required WebAuthn proof. It is not the document key. Shared browser/passkey compromise prevents assuming it is an independent factor.

## 20. OperationPermit

The authorized activation service signs a short-lived permit containing the complete context and activation evidence commitment. Providers check the permitted proofMode and assurance against policy. Expiry, purpose, audience, key and message are checked immediately before dispatch. An authentic permit for another message is invalid for the current invocation.

## 21. Execution state

Operation IDs are unique and persist through restarts. A completed identical retry returns the exact stored signature and receipt. Different inputs under that ID are rejected. Uncertain provider execution remains UNKNOWN_EXECUTION until reconciled. Releasing a database lock does not prove the hardware did not sign.

## 22. Execution receipt

The receipt binds activation, permit, exact key/message, signature hash, provider and execution time. It is verified under a policy-authorized receipt key. It identifies whether enforcement occurred at a gateway or inside a device. A receipt cannot prove trustworthy visual display unless the corresponding trusted-display evidence is separately present.

## 23. CMS/CAdES

Signed attributes contain one value per required attribute and use canonical DER SET ordering. ESSCertIDv2 binds the complete original certificate representation, including its MTC proof. External classical timestamp CMS has a separately declared verification profile. Unknown critical RRA semantics prevent RRA conformance even when generic CMS mathematics succeeds.

## 24. PAdES

The PDF adapter adds an incremental revision without rewriting prior bytes. ByteRange covers exactly the signed revision outside the signature Contents gap; lengths, offsets, actual Contents and signed EOF are checked. Existing AcroForm properties and signatures are preserved. Later additions are classified against signed revision objects and applicable DocMDP/FieldMDP policy. Unsupported transforms or content changes do not receive an approved-modification result.

## 25. JAdES

Protected RRA headers are certconcord_ctx, certconcord_sim, certconcord_policy and certconcord_cert, with the specified values and mandatory critical handling. sigT is a declared signing time, not trusted time. Detached and RFC 7797 unencoded payload modes are explicit. `b64=false` requires critical processing. Verification checks the exact x5c representation and certificate commitments as well as the signature.

## 26. Time and status

The signature time, TSA proof-of-existence interval, certificate validity, credential/device status and compromise interval are evaluated separately. A currently revoked certificate may have a valid earlier signature when policy and evidence establish that conclusion. Conversely, a compromiseStart preceding the operation may invalidate a signature made before public revocation.

## 27. Evidence modes

DIRECT_ACTIVATION preserves original proof, registration and authorization evidence. ATTESTED_ACTIVATION relies on an explicitly trusted validation authority and its committed statement. A verifier cannot treat missing direct evidence as attested evidence merely because a server generated a receipt. Both modes retain exact TBS and signature commitments.

## 28. Remote fallback

A different provider may be selected only through a newly assessed key/custody path and fresh user authorization. Existing private-key continuity is not assumed. A browser missing a draft API may offer a registered remote path, but cannot silently redirect an already approved local-device operation.

## 29. Key and credential lifecycle

Enrollment, suspension, revocation, deletion, renewal and replacement are distinct events. Deleting a passkey disables its authorization mapping before new operations can begin. Adding another passkey requires a new key mapping or a separately authorized migration. Historical verification retains the original registration and key references.

## 30. Recovery

Signing recovery obeys the RCG. Account restoration and encryption escrow cannot create signing authority. A lost non-exportable signing key requires replacement issuance and appropriate revocation, while retaining old validation evidence. Migration of an exportable software key is allowed only under a declared custody transition and new assurance assessment.

## 31. Validation result

The result distinguishes a bad signature, wrong purpose, untrusted certificate, stale status, absent activation, insufficient assurance, changed content and unsupported adapter. A generic green signature icon is not an adequate RRA result. Consumers receive the covered document scope and the exact policy/time context.

## 32. Authorization privacy

PRF outputs, capability private keys, biometric material and arbitrary client extension data are excluded from server assertion serialization and public evidence. Only whitelisted public WebAuthn fields leave the client. Private identity or document data is fetched only after independent access authorization.

The selected WebAuthn baseline is Level 3 Recommendation, 2026-08-25. The [Level 4 draft assessment](../../docs/webauthn-evolution.md) pins the 2026-09-15 First Public Working Draft separately. Its PRF confidentiality requirement also applies to signed authenticator extension outputs. A serializer MUST NOT redact signed bytes to conceal an exposed secret; it MUST reject the result before transmission. PSCP raw-signing extensions retain their own version locks and MUST NOT be advertised as a Level 4 document-signing facility.

The local activation profile requires the configured RP ID and exact origin, absent or false `crossOrigin`, and no `topOrigin`. Its drivers MUST NOT request `remoteClientDataJSON`. A remote-desktop profile requires separately governed proxy authority, authenticated remote-session context and the exact original client-data bytes; neither a caller-supplied origin nor the unsigned extension result establishes that authority. Ordinary RP verification cannot infer or exclude remote mediation from a valid assertion alone. Implementations MUST NOT claim a cryptographically proven local topology from these checks.

## 33. Error and resource handling

Malformed ASN.1/CBOR/JSON/PDF, duplicate fields, ambiguous algorithms, oversized payloads and unsupported critical fields fail before signing. Provider failures cannot be converted to a success receipt. Diagnostics exclude secrets and private document content. Result retrieval is authorized to the owning trust subject/application scope.

## 34. Conformance tests

Acceptance includes wrong-key/message/certificate substitution, cross-profile use, intent/TBS mutation, nonce and permit replay, concurrent dispatch, lost-result recovery, altered PDF revisions, unrecognized critical headers and recovery escalation. Native devices additionally require real key generation, per-use authentication where claimed, attestation evaluation and export-boundary tests.

## 35. Interface invariants

Container adapters and providers MUST preserve the exact authorization chain across interface and version changes. A change MUST NOT reduce the required assurance level or convert a qualification credential into unrestricted signing authority.

Inputs crossing asynchronous authorization or provider interfaces MUST be retained as immutable snapshots. A policy authorizer returns boolean true for approval; false, absence, other values or exceptions deny the call. Authorization and expiry are rechecked after asynchronous policy work and before releasing a completed result. A post-dispatch failure retains the uncertain outcome rather than authorizing another invocation.

## 36. Governed execution binding

[EBP draft 03](EBP-draft-03.md) is an explicitly selected RRA execution profile. Its signed provider/key admission, monotonic epochs, key-scoped unresolved-operation lock and original-byte request commitment extend the SIM/ACB/permit chain. Its mandatory CMS and mdoc ECP plans preserve normal document signature, issuer and lifecycle validation. BROKER_ENFORCED describes the admitted broker boundary; it does not imply authenticator permit processing or a trusted display. PSCP retains its separate dual-proof plan until an explicit composition is selected.
