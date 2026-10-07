# Draft versions and historical evidence

The current specification edition is draft 03. The reference software version is 0.3.0-draft.1. A stable specification release requires the conformance and review gates defined below.

Framework draft edition, application profile, mechanism binding, wire object schema, upstream standard and reference software version are separate identifiers. Each published snapshot identifies its commit and [content manifest](../draft-manifest.json). A branch name alone is not an immutable citation. The manifest is an integrity inventory, not an attestation of security, legal qualification or independent review.

The certconcord-prefixed wire values and OIDs identify experimental bindings. Their numeric components do not indicate CertConcord stability. Changes to protocol identifiers require a specified transition, new vectors and explicit verifier dispatch because these identifiers can form part of signed inputs.

Breaking successors are allowed. Every transition records changed semantics and assumptions, affected applications, new identifiers, coexistence or cutover rules, retained evidence bytes, authority/status history and the supported historical verification path. Archived verifiers may cover old profiles for a declared retention scope. No new runtime is required to support every historical design forever.

## Draft 03 cutover and component boundary

Draft 03 uses DCBOR(["CertConcord", 3, label, value]) and explicit draft-03 plan identifiers. RegistrationAuthorization signs one issuer/domain/key/representation scope. Evidence packages use one schema-2 verification plan plus hash-bound leaves; a separate ActivationContext leaf and nested dependency graphs are removed. The independent RA decision, unsigned SIM, prior permit, subsequent receipt and independent organizational grant remain. Old domains and layouts are rejected without a legacy fallback. Rewriting an old signature, credential, status token or archive does not migrate it.

This research cutover has no deployed clients or retained production evidence requiring a compatibility runtime. Any historical research bytes retain their original interpretation. An eventual deployment transition must retain the original verifier and immutable evidence for its declared archival scope. Object schema numbers describe field layouts; unchanged schemas, upstream MTC bytes and published algorithm identifiers keep their own meanings.

The independent mdoc-signing and ML-DSA cosignature components retain their separately reviewed draft-02 contracts. The selected C2SP subtree response is the exact raw signature in padded base64 plus LF, not the old note/key-hint/timestamp response. Log-signature validation remains mandatory. Shared components are pinned by immutable repository commits and SHA-256 file digests in components.lock.json; a framework edition change does not advance them automatically.

## Deployment transitions

A transition MUST identify the original and target profiles, affected subjects and keys, authority appointments, credential status, operation state and retained evidence. New authority requires the selected governance procedure. Existing objects MUST NOT acquire new purposes, custody claims or cryptographic semantics through a version-label change.

For the RRA composition, a cutover MUST preserve consumed permissions, unique operation identifiers, unresolved execution outcomes, immutable results, admission epochs and LIVE trust watermarks. A rollback can suspend new issuance or execution; it MUST NOT restore consumed authorizations, reuse log indices or erase an uncertain signing outcome. EBP remains an explicit policy and evidence-plan selection; adding a binding object to existing evidence does not establish earlier broker enforcement.

Storage conversion follows the [storage contract](storage.md) and [SEP](../spec/bindings/SEP-draft-03.md). Indexed log migration preserves entry order, idempotency identifiers, authenticated roots and original rows. Moving a live authority database requires a write barrier, complete state comparison and tested fencing of the previous writer. Database recovery cannot establish whether an external signing device completed an uncertain operation.

Historical verification, retention and retirement policies identify the supported evidence, applicable time and knowledge boundaries, and verifier availability. Retiring a runtime does not alter the meaning of retained signatures. Deleting a document and revoking a credential remain separate operations.

## Operational holder and key migration

This section applies when a deployment moves an existing credential or changes its admitted holder or provider. Copying a key-bound credential does not establish possession of its private key at another holder. A different holder or document key requires the applicable enrollment, attestation, approval and reissuance or authenticated rebinding procedure. A non-exportable key MUST NOT be represented as transferred when only public metadata or an encrypted credential was copied.

A holder transition MUST address prior authority, pending operations, consumed permissions, epoch and state continuity, and retention of historical evidence. Disclosure consent, signing consent and encryption recovery retain their own authority. A recovered account or new wallet registration MUST NOT silently renew a signing credential or increase its custody assurance.

Enabling a Passkey signing profile requires its exact-key admission, possession proof, issuer approval and status publication. Existing authentication credentials or PRF wrappers MUST NOT acquire document-signing authority through a database flag. Unsupported capabilities MUST NOT trigger an unapproved key, suite or profile fallback.

## Stable versions

A stable release requires the shared core and complete document baseline to satisfy the [stability gates](../spec/conformance.md). Draft artifact builds remain manually invoked CI artifacts. Packages stay private and no npm publishing or GitHub stable-release workflow is configured.
