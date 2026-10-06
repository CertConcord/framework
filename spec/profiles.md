# Profiles, sources and maturity — draft 02

Draft edition: draft-02. Reference package: 0.2.0-draft.1. Initial composition: certconcord-governed-draft-02. All project specifications in this repository are working drafts, including detailed bindings inherited from earlier research. An upstream standard's edition is independent of this draft's maturity.

| Material                                                                                           | Status and role                                                                                                                       |
| -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Architecture, trust core, mdoc/Passkey contracts, document baseline                                | Current framework draft and its first application scope                                                                               |
| [COMMON](bindings/COMMON-draft-02.md), [DTI](bindings/DTI-draft-02.md)                             | Detailed candidate bindings for shared objects and the RRA/RA/CA composition                                                          |
| [DSCP](bindings/DSCP-draft-02.md), [DCP](bindings/DCP-draft-02.md)                                 | Document signature/provider and native mdoc credential candidates                                                                     |
| [PRF-KPP](bindings/PRF-KPP-draft-02.md) | Optional local key-protection candidate; not required for ordinary WebAuthn activation |
| [PSCP](bindings/PSCP-draft-02.md) | Optional experimental Passkey-associated signing; proposal and device support are not baseline prerequisites |
| [SEP](bindings/SEP-draft-02.md)                                                                    | Candidate security engineering requirements                                                                                           |
| [EBP](bindings/EBP-draft-02.md)                                                                    | Published experimental execution-binding proposal                                                                                     |
| [Document evidence and delivery](bindings/DOCUMENT-draft-02.md)                                    | Candidate subject/organizational authorization, trusted-time and certified-encryption composition; attested CMS and native mdoc plans |
| [Framework composition detail](bindings/FRAMEWORK-draft-02.md)                                     | Detailed mechanism/evolution contract, subject to the current architecture                                                            |
| [Binding conformance](bindings/CONFORMANCE-draft-02.md)                                            | Detailed role/capability criteria; not a certificate or complete assessment                                                           |
| [Adapter selections](../reference/adapter-lock.json), [source pins](../reference/source-lock.json) | Exact implementation bindings and cited upstream bytes; a pin is not a statement that a draft is final or still the newest edition    |
| Platform and ecosystem guides                                                                      | Optional mappings; selecting one adds its own requirements without redefining the core                                                |

A binding is evaluated along separate axes: origin (existing standard, extension, original design), maturity (proposal, draft, reviewed candidate, stable), implementation coverage and independent evidence. Original work need not remain permanently experimental; external standardization does not automatically make an integration safe or complete.

The [upstream draft baseline](../docs/upstream-baseline.md) records reviewed current revisions, historical compatibility selections and the distinction between draft contributions and mature-standard adaptation.

Existing certconcord-prefixed strings, OIDs, schemaVersion values and domain separation labels remain exact experimental wire identifiers. They are not the project name or a declaration of stable release 1.0. Their replacement needs a new protocol revision and corresponding vectors. The framework draft and package version MUST NOT be used to infer a wire format by number alone.

The [security-claim matrix](../docs/security-claims.md) identifies the algorithm and authority assumptions of each implemented path. A selected post-quantum document key does not upgrade identity-source signatures, holder authentication, clock assurance or physical key custody.

The [composition review](../docs/composition-review.md) records where existing standard fields suffice, where CertConcord still adds application semantics, and which local objects and transitions are unnecessary. The IETF MTC draft, C2SP transport/witness specifications and CertConcord governance are distinct sources; no upstream specification defines their complete CertConcord composition.
