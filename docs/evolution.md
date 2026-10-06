# Draft versions and historical evidence

The current specification edition is draft 02. The reference software version is 0.2.0-draft.1. A stable specification release requires the conformance and review gates defined below.

Framework draft edition, application profile, mechanism binding, wire object schema, upstream standard and reference software version are separate identifiers. Each published snapshot identifies its commit and [content manifest](../draft-manifest.json). A branch name alone is not an immutable citation. The manifest is an integrity inventory, not an attestation of security, legal qualification or independent review.

The certconcord-prefixed wire values and OIDs identify experimental bindings. Their numeric components do not indicate CertConcord stability. Changes to protocol identifiers require a specified transition, new vectors and explicit verifier dispatch because these identifiers can form part of signed inputs.

Breaking successors are allowed. Every transition records changed semantics and assumptions, affected applications, new identifiers, coexistence or cutover rules, retained evidence bytes, authority/status history and the supported historical verification path. Archived verifiers may cover old profiles for a declared retention scope. No new runtime is required to support every historical design forever.

## Draft 02 namespace and component boundary

Draft 02 uses DCBOR(["CertConcord", 2, label, value]), newly named application profiles, protected headers, credential namespaces, configuration keys and storage schema names. Previous draft evidence is not accepted through identifier substitution. Rewriting an old signature, credential, status token or archive does not migrate it.

This source baseline starts new deployments with newly generated evidence. An existing deployment needs its original verifier and immutable evidence retained under its own archival policy. The current verifier does not provide a legacy fallback. Object schema numbers still describe the selected field layout; upstream MTC bytes and published algorithm identifiers keep their upstream meanings.

The experimental ML-DSA-87 cosignature key hint is now defined by the independent cosignature draft and no longer depends on a framework CBOR object. Its new vectors govern that selection. Shared components are pinned by immutable repository commits and SHA-256 file digests in components.lock.json.

## Deployment transitions

A transition MUST identify the original and target profiles, affected subjects and keys, authority appointments, credential status, operation state and retained evidence. New authority requires the selected governance procedure. Existing objects MUST NOT acquire new purposes, custody claims or cryptographic semantics through a version-label change.

For the RRA composition, a cutover MUST preserve consumed permissions, unique operation identifiers, unresolved execution outcomes, immutable results, admission epochs and LIVE trust watermarks. A rollback can suspend new issuance or execution; it MUST NOT restore consumed authorizations, reuse log indices or erase an uncertain signing outcome. EBP remains an explicit policy and evidence-plan selection; adding a binding object to existing evidence does not establish earlier broker enforcement.

Storage conversion follows the [storage contract](storage.md) and [SEP](../spec/bindings/SEP-draft-02.md). Indexed log migration preserves entry order, idempotency identifiers, authenticated roots and original rows. Moving a live authority database requires a write barrier, complete state comparison and tested fencing of the previous writer. Database recovery cannot establish whether an external signing device completed an uncertain operation.

Historical verification, retention and retirement policies identify the supported evidence, applicable time and knowledge boundaries, and verifier availability. Retiring a runtime does not alter the meaning of retained signatures. Deleting a document and revoking a credential remain separate operations.

## Operational holder and key migration

This section applies when a deployment moves an existing credential or changes its admitted holder or provider. Copying a key-bound credential does not establish possession of its private key at another holder. A different holder or document key requires the applicable enrollment, attestation, approval and reissuance or authenticated rebinding procedure. A non-exportable key MUST NOT be represented as transferred when only public metadata or an encrypted credential was copied.

A holder transition MUST address prior authority, pending operations, consumed permissions, epoch and state continuity, and retention of historical evidence. Disclosure consent, signing consent and encryption recovery retain their own authority. A recovered account or new wallet registration MUST NOT silently renew a signing credential or increase its custody assurance.

Enabling a Passkey signing profile requires its exact-key admission, possession proof, issuer approval and status publication. Existing authentication credentials or PRF wrappers MUST NOT acquire document-signing authority through a database flag. Unsupported capabilities MUST NOT trigger an unapproved key, suite or profile fallback.

## Stable versions

A stable release requires the shared core and complete document baseline to satisfy the [stability gates](../spec/conformance.md). Draft artifact builds remain manually invoked CI artifacts. Packages stay private and no npm publishing or GitHub stable-release workflow is configured.
