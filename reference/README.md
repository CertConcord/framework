# CertConcord reference implementation

Version 0.3.0-draft.1. This directory contains executable research and candidate bindings for [CertConcord draft 03](../README.md). It includes generated-key demonstrations and synthetic test data, not an operational CA or an independently certified product.

The custom parsers and bundled verifier demonstrate protocol semantics; they are not recommended production security boundaries. Production integrations SHOULD use mature, independently evaluated parser/crypto stacks and MUST preserve the [additional semantic checks](../spec/bindings/SEP-draft-03.md#2-parser-and-execution-boundaries). The [composition review](../docs/composition-review.md) describes retained mechanisms, removed local complexity and unresolved assurance boundaries.

Run the root npm commands described in the [project README](../README.md); npm workspace scripts execute here. Direct module commands in the implementation guides also assume this directory as their working directory.

| Area                                      | Entry points                                                                                                                |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Shared encodings, PKI and state           | core.mjs, pki.mjs, state.mjs, lifecycle.mjs                                                                                 |
| Issuance and transparency                 | enrollment.mjs, issuance.mjs, mtc.mjs, transparency.mjs, credential-log.mjs                                                 |
| Native signer mdoc and identity admission | signer-mdoc.mjs, mdoc.mjs, identity.mjs, identity-profiles.mjs                                                              |
| Passkey and execution proposals           | passkey-credentials.mjs, raw-signing.mjs, execution-binding.mjs                                                             |
| Complete candidate flows                  | demo.mjs (CMS/MTC), foundation-demo.mjs (mdoc), passkey-demo.mjs, document-demo.mjs (seal, encrypted delivery and recovery) |
| Document evidence and time                | document-evidence.mjs, document-encryption.mjs, timestamp.mjs; [candidate binding](../spec/bindings/DOCUMENT-draft-03.md)   |
| Document preservation                     | archive.mjs, archive-demo.mjs; [lifetime and result contract](../docs/document-preservation.md)                             |
| Independent verification                  | [SDK](sdk/README.md), evidence.mjs, signer-mdoc.mjs                                                                         |
| Optional infrastructure                   | native/, storage/, interop/, fuzz/, benchmarks/                                                                             |
| Licensing record validation               | [governance tools](governance/README.md)                                                                                    |

All root-level test files here run through npm test at the repository root. PostgreSQL, native platform and external hardware acceptance have their own environment requirements and CI jobs. The [conformance map](../spec/conformance.json) connects selected requirement IDs with concrete test names and records partial coverage.

Experimental wire identifiers have the semantics specified by their selected bindings. [Evolution](../docs/evolution.md) defines version and transition requirements. Detailed [implementation](../docs/implementation.md), [adapter](../docs/adapters.md) and [security](../SECURITY.md) guides describe current candidate behavior; [the architecture](../spec/architecture.md) controls project scope.
