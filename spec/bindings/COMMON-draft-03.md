# CertConcord Common Bindings — draft 03

> Candidate binding for CertConcord draft 03. This is a working draft, not a final standard. Its requirements apply only when this binding is selected. The [draft architecture](../architecture.md) defines framework scope; the [profile catalog](../profiles.md) records applicability. The draft 03 namespace and wire domain identify experimental formats. Object schema numbers describe field layouts and do not indicate a stable edition.

Status: draft 03. Normative language: English.

## 1. Authority and scope

CertConcord integrates credential, authentication, cryptographic and document standards under explicit trust, authorization, lifecycle and evidence rules. Original specifications and successor mechanisms can introduce different architectures through separately defined bindings. [FRAMEWORK draft 03](FRAMEWORK-draft-03.md) defines the mechanism-independent architecture and evolution contract. The COMMON, DTI, DSCP, PRF-KPP and DCP draft 03 bindings form the concrete `certconcord-governed-draft-03` composition; [PSCP draft 03](PSCP-draft-03.md) specializes that composition for Passkey-associated signing credentials. A service claiming this composition MUST implement its applicable requirements and every enabled profile's requirements. This document's RRA wire encodings and authority objects are mandatory within that composition; they are not universal formats for every future CertConcord composition. Profile transitions MUST preserve historical evidence bytes and their original interpretation.

Root Registration Authority (RRA) identifies one governance role selected by this composition; Merkle Tree Certificates (MTC) identifies one credential-issuance and transparency mechanism. Other compositions MAY replace either through explicit governance and mechanism bindings under FRAMEWORK. CertConcord domain-separation strings, OIDs, profiles and schema identifiers retain their specified semantics. Implementations MUST preserve signed bytes and interpret evidence under its original profile.

A successor MAY adopt a better issuance/transparency architecture with incompatible formats and interfaces and retire MTC support. This edition's compatibility and byte-preservation rules govern its declared objects and the naming transition; they do not impose backward compatibility on future architectures. Wallet and holder contracts are defined independently of EUDI. EUDI-specific component, trust and certification requirements apply only to an explicitly selected ecosystem integration.

MUST, MUST NOT, SHOULD, SHOULD NOT and MAY have their BCP 14 meanings. Upstream algorithm and wire requirements take precedence for upstream objects; this document defines RRA bindings; domain profiles specialize them. A conflict MUST produce PROFILE_CONFLICT, rather than an undocumented reinterpretation. An enabled optional adapter has mandatory security requirements. An unavailable capability MUST produce UNSUPPORTED_CAPABILITY. It MUST NOT silently select another algorithm, custody model, protocol version or assurance level.

Draft edition, reference package version, object schema, business profile and upstream adapter revision are separate identifiers. `draft-03` identifies this specification edition and domain-array version 3. RegistrationAuthorization, retained authority manifests, evidence packages and verification plans use schema version 2; unchanged object layouts retain their declared schema number. Every selected plan has an explicit draft-03 identifier. This is a breaking research revision: prior experimental wire domains and nested packages are unsupported by this runtime. There are no deployed clients or retained production objects requiring a legacy runtime. Original historical bytes MUST NOT be silently rewritten. Independent components retain their own selected revisions.

An external ecosystem has authority only within an explicitly selected deployment profile. Its architecture, legislation, certification labels or trust lists MUST NOT implicitly replace the RRA trust-domain manifest or grant new roles. An ecosystem selection MUST identify the applicable rulebook, protocol adapters, credential-purpose rules, external trust sources and assessment requirements independently. A reference to an architectural release does not pin separately maintained specifications or authorize following their moving branches.

## 2. Encoding and identifiers

RRA objects use RFC 8949 section 4.2.1 core deterministic CBOR. Map keys are declared ASCII strings, sorted by lexicographic comparison of their complete encoded bytes. Length-first ordering is not used. Integers use their shortest encoding; unsigned integers range through 2^64-1. Negative integers are permitted only in an explicitly defined field. Text is NFC UTF-8. Duplicate map keys, floats, indefinite lengths, unregistered tags, trailing bytes and unknown security fields MUST be rejected. An absent optional field is distinct from null.

```
D(label, value) = DCBOR(["CertConcord", 3, label, value])
H(label, value) = SHA-512(D(label, value))
```

Labels are case-sensitive. Raw DER, PDF, WebAuthn clientDataJSON/authenticatorData, COSE protected bytes and upstream JSON signing inputs MUST NOT be reserialized for verification. ISO mdoc CBOR is a separate domain: integer labels and tags 0, 18 and 24 are supported according to their ISO/COSE meanings. Its embedded byte strings retain their original bytes.

| Identifier                                       | Definition                                                                                                  |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| TrustDomainID, SubjectID                         | Independent random 32-byte values; not hashes of personal information                                       |
| TransactionID, OperationID, ContextID, BindingID | Independent 32-byte CSPRNG outputs                                                                          |
| CredentialIDHash                                 | SHA-256 of the WebAuthn credential ID bytes                                                                 |
| KeyID                                            | SHA-512 of DER SubjectPublicKeyInfo                                                                         |
| CertificateID                                    | X509/MTC: H("CertificateTBS", original DER TBSCertificate); MDOC: H("MdocIssuerAuth", ISO-CBOR(issuerAuth)) |
| CertificateRepresentationHash                    | SHA-512 of the complete original DER Certificate, or original IssuerSigned for credentialType=MDOC          |
| Evidence LeafID                                  | H("EvidenceLeaf", {type, payload: exact payload bytes})                                                     |

The verification plan maps each required type to exactly one 64-byte LeafID. There are no dependency edges or nested plan leaves. Time fields are UTC Unix whole seconds. Signed protocols use binary identifiers; JSON API views use unpadded base64url and decimal strings for integers outside JavaScript's safe integer range. Such views are not alternate signing encodings.

The reference limits are: RRA CBOR/DER 16 MiB, ISO CBOR 8 MiB, nesting 32, 100,000 decoded items, ECP aggregate 64 MiB, HTTP body 8 MiB unless an adapter specifies a smaller limit, and PDF 64 MiB. Deployments MUST advertise smaller effective limits and enforce them before expensive cryptography or decompression. Large vault contents have a separate chunked profile.

## 3. Cryptographic and dependency policy

The trust plane uses pure ML-DSA-87; INDEPENDENT_PQ document signatures use pure ML-DSA-65 or ML-DSA-87; the explicitly selected DEVICE_KEY and PASSKEY_KEY document profiles use ES256; document encryption uses ML-KEM-768 or ML-KEM-1024 with the RFC 9629/9936 CMS construction. ML-DSA context is empty. AlgorithmIdentifier parameters are absent where those RFCs require absence. A provider accepting only precomputed digests cannot be substituted for a pure ML-DSA message signer. PSCP separately binds its pure-message or split-input operation identifier while preserving the certified ECDSA/SHA-256 signature suite.

MTC uses the SHA-256 Merkle construction fixed in draft-ietf-plants-merkle-tree-certs-06. RRA application commitments use SHA-512. AES-256-GCM and HKDF-SHA-256 are the primary protection algorithms. RFC 3394 KW and RFC 5649 KWP require the metadata authentication defined in PRF-KPP. RFC 9964 provides registered ML-DSA JOSE/COSE identifiers; a CMS OID is not a JOSE algorithm name.

The native mdoc holder plane uses P-256/ES256. An RA-authorized DeviceBinding fixes whether the document key is independent ML-DSA or the same attested P-256 key under CERTCONCORD-PERSON-DEVICE-SIGN-v1. Secure Enclave, Android Keystore and Windows TPM APIs MUST NOT be represented as native ML-DSA implementations unless that specific device and algorithm are demonstrated. The classical holder signature has its own cryptographic lifetime and does not acquire post-quantum security merely by being recorded in a post-quantum envelope.

Every adapter lock MUST identify the specification URI, immutable revision, content SHA-256, adapter/version, wire version, algorithms, capabilities, input semantics, limits and downgrade policy. `source-lock.json` records source snapshots; the release manifest separately hashes the published files. Moving branch URLs alone do not constitute a dependency lock. Experimental components are retained with explicit identifiers and test obligations. Their replacement requires a new adapter and preserved historical readers.

## 4. OIDs and signed controls

`registry.json` is the unique RRA OID registry. UUID-derived 2.25 OIDs follow X.667 and may contain an arc larger than uint64. They are RRA assignments, not IETF or IANA endorsements. DER implementations MUST preserve every arc exactly.

MTC draft-06 identifiers remain `1.3.6.1.4.1.44363.47.0` for mtcProof, `.47.3` for trustAnchorID and `.47.4` for mtcCertificationAuthority-SHA256. MTCProof is TLS presentation syntax, not ASN.1. The issuer trustAnchorID value is a RELATIVE-OID as specified by that adapter. CA namespaces require actual administrative ownership; an example enterprise arc is not an allocation.

Signed RRA controls use CMS SignedData with id-data content containing D(label, payload), SHA-512, an authorized ML-DSA control key and signingCertificateV2 binding the full original certificate. Controls do not recursively require document signing intent. RTM bootstrap signatures may instead use directly pinned root SPKIs. Control labels include RootTrustManifest, RegistrationAuthorization, OrganizationalEndorsement, OperationPermit, ExecutionReceipt, DeviceRegistrationAuthorization and DeviceBindingRevocation.

| RRA field                             | Encoding and meaning                                                     |
| ------------------------------------- | ------------------------------------------------------------------------ |
| SignatureContext signed attribute     | DER OCTET STRING containing D("SignatureContext", context)               |
| SigningIntent signed attribute        | DER OCTET STRING containing H("SIM", SIM)                                |
| SignaturePolicy signed attribute      | DER OCTET STRING containing H("SignaturePolicy", policy)                 |
| ActivationEvidence unsigned attribute | Reference to a previously frozen evidence layer; never signing authority |
| AuthorizationID extension             | Inner DER OCTET STRING containing H("RegistrationAuthorization", RAR)    |
| KeyAssurance extension                | Inner DER OCTET STRING containing D("KeyAssurance", assessment)          |

Each CMS attribute has one SET OF value. The two X.509 extensions retain the standard outer extnValue OCTET STRING as well as their specified inner OCTET STRING. RRA verifiers MUST interpret their semantics even when a generic PKIX verifier ignores their non-critical encoding. Document SignatureContext contains schemaVersion, trustDomainID, profileID, container and adapterID.

RegistrationAuthorization uses schema version 2 and MUST sign exactly one `issuanceScope = {trustDomainID, issuerID, issuerKeyID, representation}`. Its domain is 32 bytes; issuerKeyID is the 64-byte commitment to the actual issuing public key; representation is exactly `X509`, `MTC` or `MDOC`. The existing signed profile selects purpose. Every issuer MUST check all scope fields, exact approved subject/key/policy and the issuance interval before consuming the decision. The selected issuer certificate MUST identify the key actually used. An unscoped decision, another issuer or representation, or a changed request cannot reuse the grant. Identical successful retries return the durable original result; uncertainty cannot authorize another issuance.

Cryptographic pins identify authorities but MUST NOT confer unlimited roles. Online admission and offline verification MUST resolve each required authority by identity, role, scope, operation `stateTime` and evidence `knowledgeTime`. Appointments require explicit admission and validity intervals, scope and authenticated status; certificate appointments also enforce the original certificate lifetime. A RAW_KEY appointment requires its own external lifecycle. RA, issuer, status publisher, activation attestor, receipt provider, organizational authority, TSA, recovery authority and the required transparency participants each require their selected role. A known key compromise applies across appointments, roles and certificates wrapping that key. Unknown or stale authority knowledge cannot establish acceptance; an already established violation remains INVALID. [Authority validation](../../docs/authority-validation.md) defines these boundaries.

## 5. Independent assurance dimensions

An AssuranceVector contains identity, key, activation, custody, recovery and evidenceMode. None is inferred from another.

CERTCONCORD-IAL1 means a declared identity; CERTCONCORD-IAL2 means verified evidence under a named identity policy; CERTCONCORD-IAL3 additionally requires enhanced review and applicable organizational authority. These are RRA definitions, not NIST assurance certifications. Workloads use SERVICE_IDENTITY. Evidence sources, reviewer separation, retention and reverification periods MUST be explicit.

KAL1 permits software or exportable private keys. KAL2 requires verified evidence of isolation and a documented administrator/export boundary. KAL3 additionally requires applicable independent module/lifecycle assurance. DCP key admission produces HARDWARE_KEY_VERIFIED only after exact-key attestation verification; UNATTESTED remains KAL1. Holder KAL and document KAL are separately recorded. DEVICE_KEY shares the assessed key boundary, while INDEPENDENT_PQ requires a separate custody assessment for any document KAL above KAL1. PASSKEY_KEY requires PSCP's child-key or ARKG-seed attestation, approved model policy and possession proof independently of the parent and mdoc holder. An API name, local hardware report, non-extractable flag, or hardware-protected passkey does not establish the KAL of a different document key.

SAL1 requires explicit fresh authorization bound to an operation. SAL2 additionally requires fresh validated user verification and enforced single-use authorization within the declared provider boundary. SAL3 additionally requires an independent trusted display/confirmation channel binding the actual content and signing identity. Ordinary browser text and a biometric prompt do not establish SAL3. A mdoc device signature proves holder-key use; it does not by itself prove fresh local UV or informed document consent.

## 6. Operation authorization

The existing bindings abbreviate these checks as ACB. They are application bindings carried by existing signature and authentication formats, not a new signature primitive.

The dependency order is immutable:

```
document scope -> SIM -> required endorsement -> exact container TBS
-> ActivationContext -> fresh authorization proof -> OperationPermit
-> durable DISPATCHED record -> provider signature -> ExecutionReceipt -> ECP
```

SIM contains schemaVersion, trustDomainID, transactionID, subjectID, profileID, keyID, certificateID, certificateRepresentationHash, container, adapterID, documents, purpose, origin, policyHash, issuedAt, expiresAt, nonce and displayText; organizationID is optional. `documents` contains exactly one item with documentID, mediaType, digestAlgorithm="SHA-512", digest, scope and displayName. Scope is CMS_CONTENT, PDF_BYTE_RANGE, JWS_PAYLOAD or COSE_PAYLOAD. Native personal mdoc operations additionally require credentialType="MDOC"; X.509/MTC compatibility operations omit it. Identifier field names are retained with the representation semantics defined above. Multiple independent signatures require separate operations; a composite document may have one content commitment. Display text records the declared display, not proof of a trustworthy display.

ActivationContext contains schemaVersion, trustDomainID, transactionID, operationID, simHash, tbsHash, tbsKind, keyID, certificateID, certificateRepresentationHash, policyHash, origin, rpID, audience, serverNonce, issuedAt and expiresAt. Optional batchHash identifies a separately validated complete batch. tbsKind is CMS_SIGNED_ATTRS_DER, JWS_SIGNING_INPUT or ADAPTER_MESSAGE. `tbsHash = SHA-512(exact provider message)`. CMS uses the DER SET OF signed attributes, not the implicit [0] transport tag.

Default lifetime is at most 120 seconds. The authority validates all shared SIM/context fields, current subject/key/device authorization, profile/policy, document scope, audience and server nonce. A WebAuthn challenge is H("ActivationContext", context). Its verification includes exact client bytes, challenge, origin, RP ID hash, UP/required UV, credential ownership, cross-origin policy, signature, expiry and replay protection. Counters are checked according to credential backup behavior and deployment policy; they cannot replace nonce consumption.

OperationPermit contains schemaVersion, the complete ActivationContext, activationEvidenceHash, proofMode, issuedAt and expiresAt. proofMode distinguishes HUMAN_WEBAUTHN, HUMAN_MDOC, HUMAN_SESSION and WORKLOAD. A permit expires no later than its context and normally within 30 seconds. A provider MUST verify the authority, audience, exact key/message and permitted mode, then durably reserve the OperationID before dispatch. Authentication to a provider is insufficient without that permission check.

The durable states are PREPARED, AUTHORIZED, DISPATCHED and COMPLETED, with REJECTED, EXPIRED and UNKNOWN_EXECUTION outcomes. Reusing an OperationID with different bytes is an error. Replaying a completed identical request returns the stored result. A crash or lost response after dispatch MUST NOT automatically cause another signature. A result query may reconcile the operation; otherwise it remains UNKNOWN_EXECUTION and any retry requires a newly authorized OperationID.

ExecutionReceipt contains schemaVersion, operationID, activationHash, permitHash, keyID, tbsHash, signatureHash, executedAt and provider. Its authority and key scope are policy-bound. It records the gateway's or device's statement according to evidenceMode; it cannot retroactively create user consent.

Batch authorization commits to an ordered, duplicate-free complete list of contexts with common domain, transaction, origin, RP ID, audience, policy and lifetime. The acyclic construction is `BatchHash=H("ActivationBatch", {schemaVersion:1, contexts})`, where each input context omits batchHash. Each final context then adds that BatchHash. The WebAuthn challenge is BatchHash. Every item retains its own OperationID and server nonce. Verifiers MUST possess the full batch, reconstruct it, verify the selected item's exact index and prohibit additions. All item nonces are consumed atomically before issuing the permits. Per-item completion and uncertainty remain independent. The 1.0 batch adapter uses one registered credential/document-key binding, validates each SIM, and permits at most 100 items (or a smaller policy limit). A batch may be enabled only through an adapter enforcing these requirements.

## 7. Trust state continuity

RootTrustManifest contains a trustDomainID, serial, issuedAt, notBefore, notAfter and authenticated authority/policy selections. The retained schema-2 history additionally requires a contiguous serial starting at zero, previousHash, coverageUntil and explicit authority appointments. Its publication proof binds both the manifest and root signatures. Offline root thresholds authorize manifests; online application accounts do not. A successor root policy MUST satisfy both prior and successor quorums on the same transition. External root and algorithm lifetimes, authenticated publication bounds and knowledge coverage constrain historical selection. The executable safe-integer range is narrower than uint64. [Retained validation](../../docs/historical-validation.md) defines the selected contract and separates validation time from historical knowledge time.

LIVE validation atomically stores the highest accepted serial and digest. Lower serials are stale; the same serial with another digest is a trust fork. HISTORICAL validation accepts an explicit stateTime and knowledgeTime and MUST NOT lower or overwrite LIVE state. Historical validation uses retained old policy/keys while considering later-published compromise evidence available by knowledgeTime.

Root and membership transitions require old and new authorizations over one transition commitment. Old authority cannot be discarded before continuity is established. Emergency replacement requires an independently pinned recovery quorum; an online administrator cannot declare a new root trusted. A transition referencing a new policy core avoids a hash cycle by storing the authorization envelope separately.

The reference TrustStore implements fixed bootstrap pins and LIVE/HISTORICAL watermark checks only. It has no root-rotation API. The separate retained-history resolver authenticates old and new root quorums, and ArchivePublicationStore persists the complete validated ERS head and governance/custodian history atomically. Reconstructing a TrustStore with different pins is external provisioning, not a verified transition. Emergency replacement, replicated operation and rollback-resistant backups remain deployment obligations beyond this selected retained-history implementation.

## 8. Quorum and transparency

These are CertConcord composition requirements. The selected IETF MTC draft supplies certificate, subtree and cosigner encodings and their verification semantics; separately selected C2SP specifications supply transparency transport and witness formats. RRA authority, operator admission, the chosen quorum, retention and document-operation rules belong to CertConcord. Their combination is not an IETF MTC conformance claim.

The CA signature and independent mirror signatures have separate roles. MQ23 requires the CA and two of three independent mirror operators; it does not guarantee prevention of two conflicting accepted views with one Byzantine mirror. For n operators, threshold q and f Byzantine operators, intersection-based fork prevention requires `2q - n > f`; availability requires `q <= n - f`. MQ34 satisfies both for one fault.

Operator independence and distinct keys MUST be assessed, not counted from duplicate endpoints. Shared operators cannot inflate a quorum. Policy commits to membership, threshold, algorithm, CAID, epoch, freshness and required additional statements. A mirror signature asserts verified durable possession of log entries; a witness signature asserts consistency. Witnesses MUST NOT be silently counted as mirrors. New membership needs joint transition evidence.

The composition MUST resolve the actual valid signers contributing to the selected quorum: MTC cosigners use `COSIGNER`; native issuance uses `TRANSPARENCY_LOG` for the log and `MIRROR` for mirror members. Static membership alone is insufficient. An additional unusable member MUST NOT defeat an otherwise sufficient authorized quorum. These lifecycle checks belong to this composition and do not add an RRA dependency to the independent wire components.

## 9. Evidence Closure Package (ECP)

An ECP is `{schemaVersion: 2, plan, objects}`. The single unsigned plan contains schemaVersion 2, an exact selected profile identifier and a type-to-LeafID map. Every leaf is `{id, type, payload}` with exact binary payload bytes. Types and IDs MUST be unique; every supplied leaf MUST be referenced exactly once under the same type, with no unused or nested objects. The relying party supplies policy, authority, state and knowledge-time inputs independently. The plan selects validation; it cannot authorize an object or replace a document signature.

Every selected CMS and native mdoc document plan retains the independent RegistrationAuthorization, original document/container and credential bytes, status, unsigned SIM, signature policy, prior OperationPermit and subsequent ExecutionReceipt. Independent organizational grants and required timestamp/archive proofs remain separate evidence. ActivationContext is obtained only from the authenticated permit and MUST NOT appear as a standalone leaf or conflicting builder input. SIM remains unsigned data committed by the document signature. Direct activation evidence additionally retains registration and device/credential authorization history. Attested activation is valid only under explicitly admitted attestor authority.

Missing mandatory leaves or the plan yield INDETERMINATE; bad available commitments and established signature/binding failures yield INVALID. Recognized unsupported revisions or critical capabilities yield UNSUPPORTED. Available commitments MUST be checked before an incomplete or unsupported interpretation hides their failure. Prior graph layouts, dependency fields, duplicate IDs/types, extra fields, nested plans and unreferenced leaves are rejected. Personal identity evidence and raw PRF outputs are excluded from public packages. An ECP does not authorize downloading the underlying document.

An evidence manifest MUST NOT contain its own final container representation. Use a sidecar, a previous frozen layer, or a subsequent timestamp. Time renewal binds previous time evidence; hash renewal also binds the original protected data. Renew before the old primitive or evidence authority ceases to support the required claim. Re-timestamping an already broken hash cannot repair the historical statement.

## 10. Recovery capability analysis

The recovery graph models capabilities, not merely organizational approvals. Nodes represent secrets, device access, provider authority or policy states. An edge defines distinct prerequisite nodes, a threshold and the capability obtained. The transitive closure of account administrators, KRA operators, compromised devices and recovery credentials MUST be evaluated.

This analysis is local policy modeling, not a signed protocol object or a cryptographic proof of deployment separation. Every protected signing target MUST be explicitly present in the graph; empty, duplicate or unknown targets MUST fail validation. A graph cannot establish the absence of an unmodeled provider credential or administrative path. Existing RCG error identifiers retain their wire meaning.

Account access roots, signing roots and encryption recovery roots are independently generated. An account recovery path MUST NOT reach an intentional signing secret or provider authorization. Encryption escrow is explicitly labeled and restricted to approved encryption material. If all required signing capabilities are lost, the result is new key enrollment and old-key revocation, not reconstruction of an unavailable private key. The UI and evidence MUST distinguish identity continuity from key continuity.

## 11. Results, time and incidents

Validation returns separate cryptographic, trust, identity, authorization, time, status, content-coverage and evidence-closure results. Overall results are VALID, INVALID, INDETERMINATE or UNSUPPORTED with specific reasons. UNKNOWN or STALE status is never GOOD. A failed signature differs from absent activation evidence.

The selected CRL, OCSP, Status List and experimental status adapters use the same four outcomes. Missing or not-yet-published evidence is INDETERMINATE; recognized unimplemented critical semantics is UNSUPPORTED. Available cryptographic and binding failures are INVALID. An authenticated applicable revocation known by knowledgeTime remains INVALID even when the statement is stale. Freshness cannot hide a failed signature, and an unrelated expired JWT does not become an indeterminate status result.

Every incident statement identifies scope, publisher authority, publication time, effective time, reason, nextUpdate and optional compromiseStart. Scope may be one certificate, a serial/index interval, an issuance log, a CAID, a device binding or a governance key. Later compromise can invalidate an earlier operation when its effective compromise interval reaches that operation. Publication alone is not the compromise start. Historical proof of existence has an upper bound including timestamp accuracy; an untrusted signingTime is not trusted time.

## 12. Security and evolution

Operation authorization, trust watermarks, evidence packaging, recovery analysis, PRF epochs and qualification-to-operation binding are CertConcord composition rules. Existing abbreviations identify those rules; they do not identify independently proven security primitives. The [composition review](../../docs/composition-review.md) distinguishes standard representations, retained additional semantics, reductions and unresolved proof obligations.

An implementation MUST preserve the boundary between a mathematically valid object and an authorized action. It MUST reject ambiguous parsing, algorithm confusion, cross-purpose keys, unbounded inputs, untrusted URL fetches, stale authority and replay. Protocol callbacks in the reference implementation are trusted policy integration points; exposing them as unauthenticated public approvals violates this specification.
