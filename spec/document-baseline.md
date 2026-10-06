# Document trust baseline — draft 02

This is the first application targeted for a complete, independently implementable specification. It is a scope and completion contract; it does not assert that every requirement below is already complete in the reference implementation.

The immediate research objective is MTC/PQC for long-term document certificates: qualification and issuance, authorized signing, trusted time, status retention, offline verification and timely evidence renewal after issuer retirement. TLS handshake deployment is not the acceptance target. The [preservation path](../docs/document-preservation.md) provides the first bounded lifecycle example. Other document representations and application tracks share the same trust core.

## End-to-end flow

1. Configure the trust domain, admitted authorities, identity sources, policies, suites and status services.
2. Qualify the person or organization and establish possession and permitted custody of the document key.
3. Issue a purpose-bound certificate in a selected representation, record accountable issuance and deliver it to the holder.
4. Freeze the exact operation input and intent. Obtain the authorization required for that person, organization or workload.
5. Produce the signature or encryption result through the selected key provider; preserve the evidence connecting authorization to execution.
6. Assemble the required credential, issuer, status, transparency, time and operation evidence.
7. Let an independently configured verifier evaluate that evidence and report the result and limits.
8. Support status changes, compromise, renewal and later verification under an explicit historical policy.

## Required scope

| ID        | Baseline requirement                                                                                                                                                                                                                                                                    | Selected technical detail                                                                                                    |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| CC-DOC-01 | Personal document signing MUST cover identity qualification through independent verification using at least one complete mdoc path and one complete Passkey-enabled path. The role of each credential and key MUST be explicit.                                                         | [mdoc](mdoc-certificates.md), [Passkey](passkey-credentials.md), DCP/PSCP/DSCP candidates                                    |
| CC-DOC-02 | Organizational signatures and seals MUST bind organizational authority, delegation, applicable human/workload controls, key purpose and revocation. A personal credential alone cannot assert organizational authority.                                                                 | [Document binding](bindings/DOCUMENT-draft-02.md): direct authority-to-operation delegation and independent evidence         |
| CC-DOC-03 | Document encryption MUST specify recipient qualification, key possession, exact algorithms and encapsulation, integrity, delivery, key lifecycle, decryption and recovery/failure semantics. Encryption is not equivalent to signing.                                                   | [Document binding](bindings/DOCUMENT-draft-02.md): certified KEM recipients, protected delivery and encryption-only recovery |
| CC-DOC-04 | Containers MUST bind the exact bytes interpreted by the verifier. Canonicalization, detached content, rendering limits, partial coverage and unsupported features MUST be explicit.                                                                                                     | DSCP, container adapters and parser isolation                                                                                |
| CC-DOC-05 | Status, required time evidence and historical validation MUST be evaluated against explicit authority, freshness and knowledge-time rules. Missing required trusted time MUST prevent a VALID result.                                                                                   | [Document binding](bindings/DOCUMENT-draft-02.md): proof-of-existence upper bound and status at knowledge time               |
| CC-DOC-06 | Independent verification MUST use published inputs, schemas and result rules, with positive and negative vectors sufficient to reproduce the claimed profile. Draft development supplies this implementable contract; independent implementation evidence is required before stability. | [Conformance record](conformance.md)                                                                                         |

## Completion gate

For CC-DOC-01, ordinary WebAuthn activation of a separately admitted document key satisfies the Passkey-enabled path. Raw-signing proposals, ARKG and EBP are optional experiments; their absence does not prevent baseline conformance and their presence does not substitute for the mandatory flow. Once a policy explicitly selects an experimental path, all of that path's checks remain required and failure cannot trigger an implicit fallback.

[MTC document validation and preservation](../docs/mtc-document-validation.md) extends the baseline across standalone distribution, offline dependencies, independent monitoring, format-specific time evidence and archive succession. Those obligations use the same subject/key/purpose and authority core. Container-level conformance and historical archive validation remain separate completion requirements.

The baseline reaches a reviewable complete draft when every row has a cohesive mandatory profile, role contracts, wire inputs and outputs, security/privacy assumptions, errors and negative vectors, plus at least one runnable full flow. A stable proposal additionally requires an independently developed implementation, recorded interoperability outcomes, review of the threat model and security findings, and explicit dispositions for unresolved questions.

A second complete implementation and an independent security assessment do not block draft research, consolidation or reference implementation. Current acceptance targets the lifecycle's stated semantics and failure cases. Unfinished protocol behavior remains a draft gap; unavailable external assessment does not prevent that behavior from being specified and tested.

A growing adapter catalog is not baseline completion. Platform demonstrations, government identity interoperability, external wallet availability and a production service are assessed separately. The [current conformance record](conformance.md) states the evidence and gaps without promoting experimental features to mandatory external dependencies.
