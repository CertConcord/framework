# Document evidence and encrypted delivery — draft 03

Status: candidate application binding. This binding composes the shared certificate trust core with the document application. It introduces no new cryptographic primitive and makes no stable conformance claim.

## 1. Selection and trust

The signed SignaturePolicy selects `documentEvidence = {profile: "certconcord-document-evidence-draft-03", organizationAuthorization: boolean}` and an explicit boolean `requireTrustedTime`. The two verification plans are `certconcord-ecp-cms-document-draft-03` and `certconcord-ecp-mdoc-document-draft-03`. Their underlying signature, intent, activation, receipt and credential rules are those of the corresponding attested CMS or mdoc candidate in [DSCP](DSCP-draft-03.md) and [DCP](DCP-draft-03.md).

A verifier MUST obtain the policy and authority inputs from its relying-party configuration. A package MUST NOT install its own RA, issuer, organizational authority, TSA or status authority. The single schema-2 plan and every selected leaf MUST be checked before interpreting success. An old plan cannot satisfy a policy that selects this binding. Raw Passkey signing-key and experimental execution-binding plans have no composition with this binding in this edition; their selection MUST be rejected rather than downgraded. Ordinary WebAuthn activation of a separate document key is supported.

Every CMS and native mdoc plan retains the independent `RegistrationAuthorization`. An organizational seal additionally requires `OrganizationAuthorization` and `OrganizationAuthorizationStatus`. A policy requiring trusted time additionally requires `DocumentTimestamp`. Native mdoc binds the RA decision through its certified claim and seal; it requires no personal X.509 certificate. Organizational mdoc is outside this binding's implemented scope.

Leaf payloads are binary and use `H("EvidenceLeaf", {type, payload})`. The plan's object map MUST name exactly the types selected by the policy. The authenticated OperationPermit is the only source of ActivationContext; standalone copies and nested plans are rejected. SIM is unsigned data committed by the document signature. Unknown fields in the document-evidence selection and organizational authorization are rejected. Encodings are declared in [schemas.cddl](../../reference/schemas.cddl); the [reference verifier](../../reference/document-evidence.mjs) implements the additional predicates below.

## 2. Certified subject binding

For both representations, the verifier MUST authenticate RegistrationAuthorization with the configured RA certificate, resolve its RA role at issuance under the selected knowledge time, and verify that:

1. The CMS certificate's authorization extension or native mdoc's certified registration commitment equals `H("RegistrationAuthorization", body)` using the COMMON domain-separated deterministic encoding.
2. The authorization's subject ID, profile, policy hash and public-key hash match the signed intent and credential. Public-key hashing uses the exact SPKI DER.
3. The signed schema-2 issuanceScope matches the expected trust domain, issuer identity, actual issuer key and representation. Purpose is fixed by the signed profile; one decision cannot admit multiple issuers.
4. Credential issuance is within the original RA authorization interval, which is positive and no longer than 300 seconds, and precedes the declared execution time.

The authorization's expiry limits issuance, not the lifetime of an already issued certificate. Continued use depends on certificate validity and status. The issuer remains accountable for accepting the authorization within its issuance window. This object does not expose the underlying identity documents or grant the identity source authority over document signatures.

## 3. Organizational authority and execution

An organizational seal selects `CERTCONCORD-ORG-SEAL-v1`, the purpose `ORGANIZATION_SEAL`, and `organizationAuthorization: true`. The SIM contains a fresh 32-byte `organizationAuthorizationID`. The relying party maps the certified organizational subject ID to a permitted organizational authority certificate and status authority certificate.

The authority signs a COMMON control envelope labeled `OrganizationAuthorization`. Its body binds the authorization ID, trust domain, organization, actor ID/type, document key, certificate, purpose, policy hash, activation hash and validity interval. The activation hash transitively binds the exact document, intent, transaction and provider input. Its interval MUST fit inside the activation interval. `actorType=WORKLOAD` requires WORKLOAD activation; `actorType=PERSON` requires one of the selected human activation modes. The authority is responsible for authenticating that actor and evaluating its institutional entitlement before signing.

The operation permit MUST commit to the SHA-512 hash of that exact signed authorization in `activationEvidenceHash`. The existing gateway enforces one-use execution and binds its receipt to the permit, operation, key, input and resulting signature. The verifier checks both links. A personal certificate, an actor label or a workload permit alone cannot establish organizational authority.

The independently authenticated `OrganizationAuthorizationStatus` commits to the authorization's ID and signed-envelope hash, trust domain and `ORGANIZATION_AUTHORIZATION` scope. Its status is evaluated at the same state and knowledge times as the document. A revocation effective by the selected state time invalidates authorization, including a later-published compromise interval that reaches that time.

This is a direct authority-to-operation delegation model. It does not claim hierarchical delegation, an independently verified employment relationship, qualified seal status or hardware-enforced organizational custody. Changing the authority mapping is a relying-party policy change, not a package field.

## 4. Trusted proof of existence

`DocumentTimestamp` carries a DER RFC 3161 TimeStampToken. Its message imprint is SHA-512 over the COMMON domain-separated `DocumentTimeProof` object:

```text
{schemaVersion: 1, format: "CMS" | "MDOC",
 objects: [{type: text, payloadHash: SHA-512(exact payload bytes)}, ...]}
```

The object list contains every selected leaf type except `DocumentTimestamp`, `CertificateStatus`, `CredentialStatusList` and `OrganizationAuthorizationStatus`. The unsigned plan is outside the leaf array. The list is sorted by ascending ASCII type name; duplicate types are prohibited. All presently selected type names are ASCII. Excluding status allows authenticated status refresh without replacing the original time proof. Including the RA decision, receipt, permit and organizational authorization prevents their substitution under an earlier proof. No timestamp hashes itself.

The verifier MUST authenticate the token under an externally configured TSA certificate, issuer and policy OID, verify the message imprint, require explicit nonnegative accuracy, and obtain an affirmative TSA status decision at the proof bound using the specified knowledge time. The complete TSA accuracy interval MUST fit within its certificate validity interval. An absent accuracy value does not mean zero. The upper bound is `genTime + accuracy`; it MUST NOT exceed knowledge time.

The proof establishes existence of the committed bytes no later than that upper bound. It does not prove the exact time of signing, physical consent, delivery or document rendering. The execution receipt remains an authority's declaration.

The upper bound MUST be at or after the declared execution time and inside the SIM, activation and permit intervals. The verifier MUST re-evaluate signing-certificate or native-credential validity, certificate status and organizational authorization at this upper bound. Declaring an earlier execution time cannot evade compromise effective by the proof bound. Revocation effective strictly after the bound may permit historical validation only when the status evidence and all other selected requirements remain satisfied at knowledge time.

Required issuance-proof participants are checked at declared issuance and at the first trusted proof upper bound. The same member must be authorized at both points to contribute its operator's vote. This conservative selection does not treat a self-declared issuance time as proof that a signature predates compromise. Normal participant retirement before the first trusted preservation can also prevent acceptance; admitting that case requires a separately specified earlier authenticated anchor, which this binding does not implement.

CMS status intervals use `publishedAt <= knowledgeTime < nextUpdate`. A known revocation applicable at state time takes precedence over freshness failure. A stale statement cannot establish GOOD, including an otherwise later-effective revocation. Native mdoc retains its explicitly selected status-list rules. Offline validation requires externally configured authority/status decisions or locally retained authenticated material sufficient for those decisions; a package cannot supply an arbitrary GOOD callback.

This binding requires prompt timestamp acquisition within the operation window. It does not supply indefinite archive validity: later verification still needs admissible status and trust information. RFC 4998/RFC 6283 evidence-record renewal remains a separate selected archive mechanism. TSA clock calibration and operation are external assurance requirements, not properties of the synthetic example.

## 5. Certified recipient admission

`certconcord-document-encryption-draft-03` uses the same RA, issuer, transparency and status roles. A sender MUST validate each recipient under its independently configured subject ID, policy, issuer/MTC trust and current certificate status before encryption. The selected certificate profile is `CERTCONCORD-DOC-ENC-v1`; a signing or seal certificate cannot substitute for it.

The enrollment path uses a signed-statement CSR under an accepted signing certificate and additionally performs a fresh KEM challenge. The RA consumes the challenge once, checks its subject, public key, audience and expiry, and commits the resulting evidence hash in `kemPossessionEvidenceHash` in RegistrationAuthorization. The issuer verifies the CSR and RA authorization. Both the issuer and RA require an explicit possession-certificate validation policy. A signed statement alone is insufficient for this application binding.

The sender verifies the certificate's RA commitment and public-key/subject/policy/profile bindings, and requires the KEM possession evidence commitment. The RA attests that the direct proof was checked; the public package does not disclose the challenge response or identity material. KEM proof of possession establishes neither non-exportability nor deletion of other copies.

The selected CMS suite uses ML-KEM-768 or ML-KEM-1024, HKDF-SHA256, AES-256 key wrap and AES-256-GCM. CMS KEMRecipientInfo follows [RFC 9629](https://www.rfc-editor.org/rfc/rfc9629.html), and the signed-statement CSR follows [RFC 9883](https://www.rfc-editor.org/rfc/rfc9883.html). For a certificate recipient, RecipientIdentifier is the certificate's actual SubjectKeyIdentifier, not the framework's differently sized key ID. These identifiers MUST NOT be interchanged.

This selection uses a 32-byte KEK, a 12-byte GCM nonce and an explicitly encoded 16-byte GCM tag length. The sender generates a fresh 32-byte UKM; the receiver also accepts the standards-defined absent-UKM encoding. In both cases the KDF context contains the exact selected wrap algorithm, KEK length and optional UKM. ASN.1 tag substitution and conflicting parameters are rejected before returning plaintext.

## 6. Delivery, integrity and recovery

The encrypted delivery has an outer header containing schema version, profile, suite, trust-domain ID and a fresh delivery ID, plus CMS AuthEnvelopedData. The protected plaintext repeats that header and adds creation time, the exact recipient bindings, document hash and document bytes. Each recipient binding contains subject ID, certificate ID, representation hash and key ID. Duplicate recipient keys are rejected. The reference limits documents to 16 MiB and recipients to 100.

The recipient MUST obtain the expected trust domain and delivery ID from its application context, authenticate/decrypt the CMS content, and check the repeated header, its exact recipient binding and the document hash before returning bytes. Application replay policy MUST track expected delivery IDs; the decryptor does not maintain delivery state. Decryption errors MUST not release unauthenticated plaintext.

Confidential delivery does not authenticate the sender. A sender-authenticated workflow encrypts the complete signature evidence package and verifies that package after decryption. The enclosed creation time is not trusted time. All recipients can recover the shared content key and document; this is not recipient isolation or a sender-authenticated envelope. Certificate expiry or revocation prevents new encryption under policy but cannot erase previously distributed decryption capability. Recovery of an old encryption key is explicitly permitted for retained documents; it cannot restore trust in an invalid signature.

The recoverable object is an encrypted PKCS#8 encryption key under an encryption-only vault root. A recovery request binds trust domain, subject, root, replacement KEM key, purpose, request ID and expiry. The replacement key is admitted through the same certificate and possession flow before use. Two distinct configured operators authorize the exact snapshotted request. Both approvers and the result signer require current `RECOVERY_AUTHORITY` admission scoped to that domain and `ENCRYPTION_VAULT_WRAP`; certificate equality is insufficient. The recovery service returns the vault root encrypted to the bound replacement key and a signed receipt committing to request and ciphertext. The recipient validates both receipt commitments, opens the root envelope, authenticates the vault's object/root IDs and reconstructs the old encryption key locally.

The recovery graph MUST exclude signing authority. Duplicate operators, changed targets, replay conflicts and a signing-recovery purpose are rejected. Request, authorization, graph and expiry checks run again after asynchronous root loading; callback mutation cannot redirect an approved operation. Loaded root bytes are cleared on success and failure. Completed identical requests return their durable result within the execution API window; a separate result lookup can retrieve completion after expiry without executing recovery. Uncertain execution requires reconciliation. Compromise of the old decryption key remains a confidentiality compromise; rewrapping cannot undo it. External recovery operators, vault custody, device key import and secure erasure require separate deployment assessment.

## 7. Results and evidence

Successful verification reports `TRUSTED_PROOF_OF_EXISTENCE`, its upper bound, TSA generation time/accuracy, certified subject-binding mode and, for seals, `AUTHORITY_ATTESTED_OPERATION`. It does not report an independently established signing instant or hardware custody. Missing committed objects, stale/unknown CMS or organizational status, and missing required timestamp accuracy prevent VALID. Conflicting commitments, wrong authorities/bindings, applicable revocation and failed cryptography are INVALID. Unrecognized plan/schema revisions are UNSUPPORTED at the SDK boundary.

Executable evidence is in [document-evidence.test.mjs](../../reference/document-evidence.test.mjs) and [openssl.test.mjs](../../reference/openssl.test.mjs). The [document flow](../../reference/document-demo.mjs) signs an organizational document, timestamps the evidence, admits two encryption keys through MTC issuance, encrypts the package, verifies it after decryption, and restores access through two-operator encryption-key recovery. These are synthetic reference flows, not a second independently developed implementation of this binding.

## 8. Offline distribution and preservation requirements

The [selected preservation contract](../../docs/document-preservation.md) composes a detached RFC 4998 record with the unchanged CMS or native mdoc evidence package. A preservation claim MUST distinguish the original proof bound, the latest renewal, the evaluation time, historical knowledge time and current admissibility. It MUST validate renewal timing against externally admitted TSA and algorithm lifetimes. Mathematical integrity alone MUST NOT be reported as completed preservation or current document validity.

An MTC document intended for offline distribution SHOULD select a standalone certificate before the signature binds its representation. A landmark-relative selection MUST specify authenticated distribution and retention of every required landmark dependency. Packaged checkpoints and certificates MUST NOT establish their own trust. The original representation bound by SIM and container MUST remain available; a later standalone encoding cannot replace it inside existing signed commitments.

An offline verification claim MUST identify the selected profile, independently configured authority/policy inputs, state time, knowledge time and locally available dependency closure. Offline operation does not waive status freshness, purpose, intent, organizational authority or trusted-time requirements. Missing required evidence MUST prevent VALID. A result from an earlier knowledge time MUST NOT be presented as a fresh validation result.

Certificate issuance transparency MUST NOT be reported as a log of every document-signing operation. A deployment claiming independent semantic monitoring MUST declare operator control boundaries, observation coverage and the separately governed register against which authorized subject, key-purpose and algorithm choices are evaluated. Witnessing, mirroring and semantic monitoring are distinct roles.

A deployment claiming document preservation MUST declare a validation horizon, dependency custodians, renewal policy and an authenticated archive succession process. Required evidence MUST remain retrievable across issuer retirement for that horizon. Retention MUST NOT be truncated solely to the leaf certificate's validity period. Preservation MUST include the original bytes and the trust/status/time dependencies of every required proof, with restricted access to qualification records. It MUST NOT require signing-key recovery.

The selected detached RFC 4998 path includes an authenticated retained-authority resolver, dual-quorum root succession, explicit algorithm deadlines, and atomic publication of renewal and governance/custodian history. Original bytes remain unchanged; historical authorization and current admissibility are separate decisions. Missing knowledge coverage is INDETERMINATE; backdating, late renewal and known applicable compromise cannot manufacture acceptance. [Retained validation](../../docs/historical-validation.md) states the external trust and publication-validator contract. Replication, emergency recovery, operational custody and container-specific LT/LTA augmentation remain outside this implementation. The [MTC document analysis](../../docs/mtc-document-validation.md) defines the format mappings and role obligations. An ECP timestamp or generic evidence record MUST NOT alone be labeled PAdES/CAdES/JAdES B-T, B-LT or B-LTA. Each such claim requires its own selected container profile and conformance evidence.
