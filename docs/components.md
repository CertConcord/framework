# Independent components and framework integration

Each component repository owns its draft. The framework selects the immutable commit in [components.lock.json](../components.lock.json). The local snapshots are exact copies verified by the draft integrity check; they support offline review and are not separate editable specifications.

| Component | Canonical source | Framework role |
| --- | --- | --- |
| mtc-document-validation | [4634abae](https://github.com/CertConcord/mtc-document-validation/tree/4634abae861dfc4c08bc3424867cf8392628f87e) | selected-draft |
| mdoc-signing | [1ccdf65d](https://github.com/CertConcord/mdoc-signing/tree/1ccdf65db01d63fd5e47f1d680d01db90fe969ab) | selected-draft |
| tlog-cosignature-ml-dsa | [26f4e60b](https://github.com/CertConcord/tlog-cosignature-ml-dsa/tree/26f4e60b100f25f1a4b3591da305a46897778bbd) | selected-draft |
| signing-context | [a1e23354](https://github.com/CertConcord/signing-context/tree/a1e233542e927a878ceb8eacf78f4d443cb2f19a) | proposed-amendment |
| passsign-evidence | [38c8dbc9](https://github.com/CertConcord/passsign-evidence/tree/38c8dbc9ec95dcce4b55e209cd6b9dee9a00265a) | proposed-amendment |

MTC Document Validation owns retained-evidence requirements and the lifetime checker used by the archive adapter. mdoc Signing Certificates owns the base credential/signature and key-relation contract. The cosignature draft owns the explicitly selected experimental ML-DSA-87 key hint and subtree encoding. Signing Context and PassSign Evidence remain focused amendment proposals; the current framework does not claim implementation of an upstream API or PassSign protocol by referencing them.

Independent components do not depend on the framework. The framework adds issuer/RA admission, shared trust state, purpose and qualification rules, signing intent, application authorization and end-to-end evidence validation. Mature standards and ecosystem adaptations remain in the framework and retain their exact upstream semantics.

An update changes the selected commit, reviews the technical delta, refreshes the exact snapshots and runs affected semantic and integration tests. SHA-256 entries detect drift; they do not establish security assurance. Upstream adoption is distinct from publishing a proposal repository.
