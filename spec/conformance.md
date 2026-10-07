# Conformance and stability gates — draft 03

No stable or complete-framework conformance claim is made by draft 03. The [machine-readable map](conformance.json) records every top-level requirement ID, representative test cases and limitations. It is a coverage index, not a completed independent assessment. Existing detailed [binding criteria](bindings/CONFORMANCE-draft-03.md) remain applicable when a candidate is selected.

An implementation's report MUST identify the source commit, core draft, application, selected bindings, algorithms, role, environment and relying-party policy. It MUST distinguish implemented behavior, local automated evidence, independent interoperability, platform assessment and unresolved requirements. A test file name alone does not establish that every requirement in a profile has been tested.

## Draft research acceptance

The immediate baseline is MTC/PQC for long-term documents: standalone issuance, an authorized signature, a trusted existence bound, retained status and authority inputs, offline verification, and timely preservation renewal across certificate expiry and issuer retirement. TLS deployment, a second complete implementation and an independent security assessment are not current research prerequisites. Those external assurance activities remain stability evidence.

Draft acceptance requires a bounded implementable contract, a runnable lifecycle and positive/negative vectors, including explicit results for missing evidence, late renewal and newly known compromise. The [preservation example](../docs/document-preservation.md) separates historical validation, preserved integrity and current admissibility. It does not claim a complete historical trust resolver or container-level LT/LTA implementation.

## Current evidence and gaps

- Candidate personal signing flows cover CMS/MTC, native signer mdoc, WebAuthn activation, proposed Passkey signing keys and execution binding. The tests use synthetic identities and software authenticators; deployed hardware capability is a separate claim.
- The SDK distinguishes invalid, missing and unsupported evidence at its implemented boundaries. Fine-grained reporting and every nested algorithm/capability boundary are not yet fully classified.
- The [document binding](bindings/DOCUMENT-draft-03.md) specifies and exercises direct organizational authority-to-operation authorization, certified KEM recipient admission, encrypted evidence delivery and two-operator encryption-key recovery. Hierarchical delegation, organizational mdoc and assessed custody remain open.
- CMS and native mdoc attested plans support required RFC 3161 evidence and conservative status evaluation at the proof-of-existence upper bound. Status refresh preserves the original time proof. TSA clock operations, archival status availability and time composition with raw Passkey/execution-binding plans remain separate gaps.
- Government identity admission and native signer mdoc have separate contracts. A synthetic combined government identity/signing fixture is present; external issuer and independent implementation evaluation remain unrecorded.
- External primitive/parser checks are useful evidence. A second independently developed implementation of the complete CertConcord document baseline has not been recorded.
- Ordinary WebAuthn completes the selected CMS and mdoc trusted-time plans without raw-signing or EBP evidence. Those proposals are optional and do not gate the document baseline.
- Fixed-root watermarks, scoped authority history, dual-quorum retained root transitions, recovery-target validation and atomic wrapper/archive failure traces are covered locally. Emergency root replacement, distributed operation and production parser evaluation remain unresolved assurance obligations; see the [composition review](../docs/composition-review.md).
- Security/privacy review, published threat-model dispositions, full requirement-to-vector coverage and an external assessment are required before a stability proposal. Existing fuzzing and unit tests do not replace them.
- RFC 4998 preservation checks original protection, TSA rotation and tree-hash lifetimes with explicit external policy. Complete synthetic CMS/native mdoc flows retain authenticated authority history and custodian succession, and separate preservation, historical authorization and current admissibility. Stale current status remains INDETERMINATE; later known compromise can invalidate current admissibility. These tests do not establish operational archive assurance or an ETSI LT/LTA level.

## Stable specification gate

A stable version can be proposed only after:

1. Every mandatory shared-core and document-baseline requirement has a complete normative contract, machine-readable structures, unambiguous algorithm selection and error behavior.
2. Every mandatory requirement maps to executable positive and negative vectors or an explicit assessed operational control; unmet requirements are resolved, not hidden by a release label.
3. A second independently developed implementation reproduces the mandatory flows and records interoperability and negative-case results.
4. Threat assumptions, privacy/linkability, downgrade protection, compromise/recovery, historical verification and key-custody claims receive documented review; blocking findings are resolved.
5. Required upstream drafts are pinned and their changes assessed; original constructs have a stated analysis and review status. Compatibility and deviations are accurate.
6. Attribution, contribution records, specification scope and actual patent commitments are reported without inventing signatories or grants.
7. Maintainers deliberately approve an immutable candidate and its supported scope. Local test success does not automatically promote a draft or create a release.

Other application tracks can reach their own milestones while sharing the same core. Incomplete S/MIME or standalone timestamp profiles do not redefine the document baseline, and document completion must not be advertised as those profiles' completion.
