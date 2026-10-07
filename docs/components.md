# Independent components and framework integration

Each component repository owns its draft. The framework selects the immutable commit in [components.lock.json](../components.lock.json). The local snapshots are exact copies verified by the draft integrity check; they support offline review and are not separate editable specifications.

| Component               | Canonical source                                                                                                 | Framework role     |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------ |
| mtc-document-validation | [4634abae](https://github.com/CertConcord/mtc-document-validation/tree/4634abae861dfc4c08bc3424867cf8392628f87e) | selected-draft     |
| mdoc-signing            | [72bfc4e7](https://github.com/CertConcord/mdoc-signing/tree/72bfc4e75f465f174ee6bca00ac793641cb496f7)            | selected draft-02  |
| tlog-cosignature-ml-dsa | [bf1d353e](https://github.com/CertConcord/tlog-cosignature-ml-dsa/tree/bf1d353e6f034ed1bc3e12496d1ef65daf1a216d) | selected draft-02  |
| signing-context         | [a1e23354](https://github.com/CertConcord/signing-context/tree/a1e233542e927a878ceb8eacf78f4d443cb2f19a)         | proposed-amendment |
| passsign-evidence       | [38c8dbc9](https://github.com/CertConcord/passsign-evidence/tree/38c8dbc9ec95dcce4b55e209cd6b9dee9a00265a)       | proposed-amendment |

MTC Document Validation owns retained-evidence requirements and the lifetime checker used by the archive adapter. mdoc Signing Certificates now owns the executable CBOR codec, issuerAuth/MSO and item checks, certified key/purpose rules, authorization/status interfaces, detached COSE signature and full serialized vectors. Framework mdoc issuance and issuer-authentication delegate to that exact component while retaining the framework's certificate-profile admission checks. `cose.mjs` re-exports the component codec so all mdoc paths share the same tag/encoding domain.

The cosignature component owns the experimental ML-DSA-87 key hint, signing input, one-witness request and raw-signature response. The framework verifies Merkle consistency, durable witness/mirror state and the admitted log signature on published checkpoints. Selecting a single witness checkpoint for a subtree request is explicit; the server rejects old multi-signature requests and the client rejects old note-line responses. Signing Context and PassSign Evidence remain focused amendment proposals; referencing them does not implement an upstream API or PassSign protocol.

Independent components do not depend on the framework. The framework adds issuer/RA admission, shared trust state, purpose and qualification rules, signing intent, application authorization and end-to-end evidence validation. Mature standards and ecosystem adaptations remain in the framework and retain their exact upstream semantics.

The mdoc base selects protected RFC 9360 `x5t` and one application namespace/JWT status-list binding. The public WG10 second-edition working text's different MSO/COSE-CWT status mechanism is tracked for comparison, not silently enabled. Published ISO 2021 metadata, public working text, a complete reference contract and full ISO conformance are separate evidence categories. Original ISO text is not redistributed in component snapshots.

The framework's `verifyMdocStatusList` adapter accepts its existing `verifyStatusList` verifier as an explicit dependency, retains the admitted key and URI, and adds the selected positive `ttl` of at most 300 seconds. It authenticates and validates the complete token before considering freshness. Invalid evidence stays `INVALID`, established revocation stays `INVALID`, and a valid good token beyond its TTL becomes `STALE`/`INDETERMINATE`. Missing evidence cannot establish good status. Issuer authorization and historical coverage remain application decisions.

An update changes the selected commit, reviews the technical delta, refreshes the exact snapshots and runs affected semantic and integration tests. SHA-256 entries detect drift; they do not establish security assurance. Upstream adoption is distinct from publishing a proposal repository.
