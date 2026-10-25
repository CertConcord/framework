# Independent components and framework integration

Each component repository owns its draft. The framework selects the immutable commit in [components.lock.json](../components.lock.json). The local snapshots are exact copies verified by the draft integrity check; they support offline review and are not separate editable specifications.

| Component               | Canonical source                                                                                                 | Framework role     |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------ |
| mtc-document-validation | [e7569638](https://github.com/CertConcord/mtc-document-validation/tree/e7569638793e3800d55fa1ef9d5f45e87b546925) | selected-draft     |
| mdoc-signing            | [18c903b3](https://github.com/CertConcord/mdoc-signing/tree/18c903b3bcfe6ff9508527a8add61e33294c793d)            | selected draft-02  |
| tlog-cosignature-ml-dsa | [c5266dfe](https://github.com/CertConcord/tlog-cosignature-ml-dsa/tree/c5266dfe267e028b36b0e5aec14cf91193651ffa) | selected draft-02  |
| signing-context         | [a1e23354](https://github.com/CertConcord/signing-context/tree/a1e233542e927a878ceb8eacf78f4d443cb2f19a)         | proposed-amendment |
| passsign-evidence       | [38c8dbc9](https://github.com/CertConcord/passsign-evidence/tree/38c8dbc9ec95dcce4b55e209cd6b9dee9a00265a)       | proposed-amendment |

MTC Document Validation owns retained-evidence requirements and the lifetime checker used by the archive adapter. mdoc Signing Certificates owns the executable CBOR codec, issuerAuth/MSO and item checks, certified key/purpose rules, authorization/status interfaces, detached COSE signature and full serialized vectors. Framework mdoc issuance, issuer authentication and detached document signing and verification delegate to that exact component. The framework selects certificate profiles, key purposes and application headers, and converts DER ECDSA signatures at its provider boundary. `cose.mjs` re-exports the component codec so all mdoc paths share the same tag/encoding domain.

Both CBOR text decoders preserve a leading U+FEFF as a code point. The component matches text keys exactly, so a U+FEFF-prefixed name cannot stand in for a required field. The framework core separately retains its NFC text and ASCII-only map-key restrictions. [Fixed text encodings](../spec/external/mdoc-signing/vectors/cbor-text.json) cover these different profiles, malformed UTF-8 and duplicate keys.

Detached document signatures use the component's credential-first critical-header order, followed by application labels in canonical encoded-key order. The earlier framework order has no compatibility fallback. Cross-consumption tests cover P-256 and ML-DSA documents in both directions, including a mathematically valid signature with the rejected earlier order. This records consistency with one shared implementation, not interoperability between independently developed implementations.

The cosignature component owns the experimental ML-DSA-87 key hint, signing input, one-witness request and raw-signature response. The framework verifies Merkle consistency, durable witness/mirror state and the admitted log signature on published checkpoints. Selecting a single witness checkpoint for a subtree request is explicit; the server rejects old multi-signature requests and the client rejects old note-line responses. Signing Context and PassSign Evidence remain focused amendment proposals; referencing them does not implement an upstream API or PassSign protocol.

Independent components do not depend on the framework. The framework adds issuer/RA admission, shared trust state, purpose and qualification rules, signing intent, application authorization and end-to-end evidence validation. Mature standards and ecosystem adaptations remain in the framework and retain their exact upstream semantics.

The mdoc base selects protected RFC 9360 `x5t` and one application namespace/JWT status-list binding. The public WG10 second-edition working text's different MSO/COSE-CWT status mechanism is tracked for comparison, not silently enabled. Published ISO 2021 metadata, public working text, a complete reference contract and full ISO conformance are separate evidence categories. Original ISO text is not redistributed in component snapshots.

The framework's `verifyMdocStatusList` adapter accepts its existing `verifyStatusList` verifier as an explicit dependency, retains the admitted key and URI, and adds the selected positive `ttl` of at most 300 seconds. It authenticates and validates the complete token before considering freshness. Invalid evidence stays `INVALID`, established revocation stays `INVALID`, and a valid good token beyond its TTL becomes `STALE`/`INDETERMINATE`. Missing evidence cannot establish good status. Issuer authorization and historical coverage remain application decisions.

An update changes the selected commit, reviews the technical delta, refreshes the exact snapshots and runs affected semantic and integration tests. SHA-256 entries detect drift; they do not establish security assurance. Upstream adoption is distinct from publishing a proposal repository.
