# CertConcord Conformance Requirements — draft 03

> Candidate binding for CertConcord draft 03. This is a working draft, not a final standard. Its requirements apply only when this binding is selected. The [draft architecture](../architecture.md) defines framework scope; the [profile catalog](../profiles.md) records applicability. The draft 03 namespace and wire domain identify experimental formats. Object schema numbers describe field layouts and do not indicate a stable edition.

This document defines how to scope, evaluate and report conformance to the `certconcord-governed-draft-03` composition under [FRAMEWORK draft 03](FRAMEWORK-draft-03.md). It applies the requirements of [COMMON](COMMON-draft-03.md), [DTI](DTI-draft-03.md), [DSCP](DSCP-draft-03.md), [DCP](DCP-draft-03.md), [PRF-KPP](PRF-KPP-draft-03.md) and the enabled [PSCP](PSCP-draft-03.md) profile to the roles and capabilities an implementation provides. Normative terms have the BCP 14 meanings defined in COMMON.

CertConcord permits other governance, issuance, transparency, wallet and protocol bindings. An alternative composition MUST identify its framework edition, normative specification and requirement-to-evidence mapping before claiming evaluated conformance. It MUST NOT claim this composition by removing required RRA or MTC checks. MTC is required only for scopes that select its branch. The profile identifier here describes a conformance unit; it does not change earlier signed-object identifiers or retrospectively expand an assessment.

## 1. Scope of a conformance statement

A conformance statement MUST identify the evaluated implementation, version, configuration and environment. It MUST name the framework edition, composition profile, implemented roles, credential profiles, enabled adapters and exact upstream revisions. A statement for a single component covers that component's applicable requirements. A statement for a complete `certconcord-governed-draft-03` deployment additionally covers the composition and mandatory services in [DTI section 50](DTI-draft-03.md#50-mandatory-composition-services).

The statement MUST record:

- The specification edition, source revision or draft-manifest digest, and enabled adapter identifiers.
- The signing and encryption algorithms, credential representations and document formats evaluated.
- The trust-policy and Root Trust Manifest identifiers and hashes, with the accepted authority roles and trust anchors.
- The holder and document-key custody boundaries, assessed Key Assurance Levels and supported Signature Activation Levels.
- The status sources and freshness rules, time-evidence requirements and supported evidence-verification plans.
- The deployment environment, provider configuration and evidence supporting each applicable requirement.

Credentials, signed objects and historical evidence retain their original schema and adapter identifiers. A newer implementation version MUST NOT silently reinterpret an older signed object.

## 2. Requirements by role

All roles apply COMMON's encoding, identifier, authority, algorithm, error and resource-limit rules. The following table identifies additional responsibilities; the referenced specifications contain their detailed requirements.

| Role or capability                          | Required behavior                                                                                                                                       | Specification                       |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| Trust governance                            | Offline root authority, authenticated policy changes, role appointments, continuity and incident handling                                               | DTI; COMMON                         |
| Registration authority                      | Approved identity process, purpose-specific evidence trust, exact subject/key/profile approval, possession checks and replay protection                 | DTI; DCP                            |
| Personal signing-credential issuer          | Scoped RA approval, current DeviceBinding and required key admission, explicit signing purpose and key mode, PQ seal, issuance quorum and status        | DCP; DTI                            |
| Wallet and native holder                    | Holder-key possession, credential validation, selected issuance/presentation transcript, origin/session binding and authorized key use                  | DCP                                 |
| Signing service and provider                | Exact Signing Intent Manifest and input, current authority, activation binding, one-use dispatch, immutable result and uncertain-outcome handling       | DSCP; COMMON                        |
| WebAuthn registration and activation        | Credential registration and lifecycle, exact transaction challenge, RP/origin, required user verification and subject/document-key authority            | DSCP; PRF-KPP; COMMON               |
| Passkey signing-key admission and execution | Parent and child attestation, approved model and fixed UV, exact CSR possession, RA/issuer binding, preissued permit, dual proof and cascading status   | PSCP; DSCP; DTI; DCP                |
| Verifier                                    | External trust inputs, separate assertion results, current or historical status evaluation, exact content coverage and semantic evidence validation     | COMMON; DSCP; DCP                   |
| MTC issuer or mirror                        | Exact certificate commitments, durable allocation and retention, independent quorum, consistency and lifecycle checks                                   | DTI; selected MTC adapter           |
| PRF, vault or recovery service              | Purpose-separated derivation, authenticated wrappers, epoch continuity and prevention of signing-authority recovery through account or encryption roots | PRF-KPP; COMMON                     |
| Timestamp or archive integration            | Authorized time source, exact imprint and policy binding, evidence preservation and applicable renewal checks                                           | DTI; DSCP; selected archive adapter |

A complete deployment MUST maintain the authority and lifecycle checks across component boundaries. For example, an active credential at issuance does not excuse a missing binding/status check at signing-provider dispatch. Accepting a government identity credential as evidence does not confer signing-issuer authority on that credential or its issuer.

## 3. Profile and adapter selection

An optional adapter's requirements become mandatory when that adapter is enabled. The conformance statement MUST identify its selected wire profile and tested feature set from the [adapter registry](../../reference/adapter-lock.json). Unsupported inputs MUST produce an explicit capability or profile error; they MUST NOT trigger an automatic change of algorithm, key custody, protocol version or assurance level.

Identity admission MUST identify its permitted issuers and versioned rulebooks, including exact document types, namespace/claim paths, claim types, certificate-purpose profiles and status rules. mDL, photo ID, EUDI PID and custom mdoc profiles are evaluated under those rules. A schema match alone does not establish identity assurance or signing-issuer authority.

For personal document signing, the issued key mode and verifier policy MUST agree:

- `INDEPENDENT_PQ` certifies a separate ML-DSA document key. Holder-key and document-key assurance are assessed independently.
- `DEVICE_KEY` certifies the attested P-256 holder key for a separate ES256 document-signing operation. DeviceAuthentication or an ordinary mDL presentation alone is insufficient.
- `PASSKEY_KEY` certifies an independently admitted P-256 signing key associated with a device-bound WebAuthn credential. It requires the PSCP binding, raw signature and parent assertion, preauthorized-evidence receipt and its declared verification plan. The signing key differs from the WebAuthn authentication key and native mdoc holder key. ARKG seed attestation precedes individual derived-key possession and certification.

PSCP implementations MUST identify the selected extension version, generation ceremony and operation algorithm. A version 4 input cannot be relabeled as version 5; a message cannot be substituted for a prehash input. Generation during an assertion uses a parent already admitted by the server. The hardware profile requires trusted attestation and model policy for the exact signing key or seed, fixed per-use UV and device-bound parent state. Registration without attestation or an exportable key cannot inherit this profile.

The `PREAUTHORIZED_EVIDENCE` profile requires activation to precede the raw-signing request and requires the verifier to check both proofs. It establishes acceptance of authorized evidence; it does not establish that the authenticator itself parsed the RRA permit or that browser code exclusively controls all key use. A deployment claiming a protected execution gate MUST identify and evaluate that additional provider boundary. WebKit's API adapter also requires separately admitted keys and a protected provider integration; a nonextractable handle alone is insufficient.

Hardware assurance MUST be established for the exact proposed key before hardware-profile issuance. The assessment MUST validate the platform evidence, challenge, application/device policy, trust source and applicable status. Local key labels, non-exportable flags and evidence about another key cannot satisfy this requirement. [DCP section 2.2](DCP-draft-03.md#22-key-attestation-admission) defines the platform admission rules.

Key Assurance Level (KAL) and Signature Activation Level (SAL) MUST remain separate. Fresh user verification and trusted display are evaluated when required by the claimed SAL. A holder proof, platform API or successful biometric prompt MUST NOT be used to assert an unverified higher level. [COMMON section 5](COMMON-draft-03.md#5-independent-assurance-dimensions) defines these levels.

## 4. Verification results

A verifier MUST report cryptographic validity, issuer trust, identity qualification, authorization, time, status, content coverage and evidence closure separately. Its overall result follows [COMMON section 11](COMMON-draft-03.md#11-results-time-and-incidents):

| Result          | Meaning                                                                       |
| --------------- | ----------------------------------------------------------------------------- |
| `VALID`         | All requirements of the identified verification policy are satisfied.         |
| `INVALID`       | A required cryptographic, authority, scope or other policy check fails.       |
| `INDETERMINATE` | Required evidence is absent, stale or insufficient to establish the decision. |
| `UNSUPPORTED`   | The implementation cannot evaluate a required capability, format or profile.  |

An adapter's `VALID_UNDER_POLICY` result identifies success under the stated policy. `ATTESTED_VALID` identifies an authorization assertion accepted from an explicitly trusted activation attestor. `DECLARED_EXECUTION_TIME` identifies a time asserted by an execution receipt. These values MUST retain their scope when converted into application results.

In particular, a receipt's declared time MUST NOT become a trusted timestamp, missing status MUST NOT become `GOOD`, and a closed graph of evidence hashes MUST NOT substitute for validation of the objects' authority and relationships. A policy requiring trusted time remains `INDETERMINATE` until applicable timestamp or archive evidence has been validated. Evidence-verification plans and their external trust inputs MUST be identified in the result.

## 5. Evaluation methods

Evaluation MUST exercise the applicable successful flows, failure paths and state transitions. Each enabled deployment path MUST be tested against an independent peer or implementation where available. Test records MUST identify their input profiles, expected results, observed results and environment.

| Boundary                       | Required evaluation                                                                                                                                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Authority and identity         | Unapproved issuer or RA, stale identity evidence, wrong subject, wrong purpose, substituted key and revoked binding                                                                                          |
| Encoding and cryptography      | Independent vectors, exact signed bytes, malformed or ambiguous encodings, unsupported algorithms and modified signatures                                                                                    |
| Presentation and consent       | Wrong holder, origin, audience or session; altered document/intent; expired request; cancelled or replayed authorization                                                                                     |
| Issuance and transparency      | Duplicate operator/key, insufficient quorum, conflicting views, rollback, partial mirror upload and conflicting issuance retry                                                                               |
| Provider execution             | Concurrent permit consumption, bypass route, crash after dispatch, lost provider response and reconciliation without an unauthorized second signature                                                        |
| Status and historical evidence | Expired or stale status, changed policy, missing dependency, time-source mismatch, compromised authority and preserved original evidence                                                                     |
| Lifecycle and recovery         | Key replacement, device loss, revocation, wrapper rotation and attempts to reconstruct signing authority through recovery paths                                                                              |
| Passkey-associated signatures  | Parent/child attestation substitution, missing fixed UV, false client approval, wrong generation version, raw/parent proof mismatch, ARKG vector mismatch, representation substitution and parent revocation |

Operational claims require evidence from the relevant operational boundary. Offline-root custody is evaluated through its ceremony and access controls; mirror independence through operators and failure domains; key custody through the applicable platform/HSM evidence and export boundary. A software-token or simulator result establishes behavior in that environment. Hardware-custody claims require the corresponding device evidence.

Wallet evaluation MUST include the required app identities, entitlements, associated domains, browser mediation and authenticated application bridge. Where user verification or trusted confirmation is claimed, the evaluation MUST exercise that path on the target platform, including cancellation and applicable biometric-enrollment changes. Remote providers MUST be evaluated for exclusive credentials, current authorization, result verification and uncertain-outcome reconciliation.

The repository's test modules and commands are described in the [implementation guide](../../docs/implementation.md#verification-tools). They supply reproducible protocol and interoperability checks that can be associated with the applicable requirements above.

## 6. Changes and continued conformance

[SEP draft 03](SEP-draft-03.md) adds parser isolation, persistence, privacy measurement, supply-chain evidence and external assessment requirements. [ASSURANCE.md](../../docs/assurance.md) identifies the review boundaries and pinned test environments. An assessment statement distinguishes local checks, externally executed suites, independent review and certification, and binds every result to its original artifacts.

A change to an enabled adapter, authority registry, policy, key boundary or execution path MUST be evaluated against the affected requirements before extending the conformance statement to that configuration. Dependency updates retain explicit versions; trust sources are updated through their governed procedures.

The optional [EBP draft 03](EBP-draft-03.md) class evaluates exact provider admission, immutable asynchronous inputs, explicit policy denial, time rechecks, epoch rollback/forks, persistent unresolved operations and mandatory CMS/mdoc evidence. Its BROKER_ENFORCED result does not establish hardware permit processing, trusted display or support for the proposed platform extensions.

Profile transitions MUST follow the [migration requirements](../../docs/evolution.md), preserving historical signatures, consumed authorizations, issuance indices and trust-state watermarks. Unresolved failures MUST remain visible in the evaluation record and verification results.

## Designated marks and implementation rights

A technical conformance statement does not grant a designated mark. Use of the CertConcord conformance-mark family MUST satisfy the separate [mark policy](../../docs/conformance-marks.md), including passing evidence for every applicable requirement and an active scoped grant. A mark or assessment MUST NOT imply a Root Trust Manifest appointment, upstream certification or unassessed assurance. Implementation rights remain governed by the applicable copyright and patent instruments independently of mark authorization.
