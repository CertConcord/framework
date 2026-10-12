# Draft 03 acceptance scope

This working draft records a bounded document-verification contract. It does not make a stable or complete-framework conformance claim. The [requirement map](../spec/conformance.json) retains partial coverage and the [conformance record](../spec/conformance.md) separates executable draft evidence from independent implementation and operational assessment.

| Selected boundary | Executable evidence |
| --- | --- |
| Four result classes, stable identity and reasons, and only evaluated dimensions | `reference/sdk-conformance.test.mjs`; an applicable established failure takes precedence over unavailable or unsupported evidence |
| Native mdoc original-byte signatures and shared component contract | `reference/mdoc-document-boundary.test.mjs`; component/framework cross-consumption, exact critical-header order, signature mathematics and explicit knowledge time |
| Offline document, preservation and retained-decision replay | [Public corpus](../reference/vectors/document-acceptance/README.md) and `node reference/verify-vectors.mjs`; the installed SDK consumes the document cases through its public export |
| Atomic retained archive publication | `reference/retained-authorities.test.mjs`; parent-issued process termination between archive write and SQLite commit, restart, retry and idempotent replay from distinct working directories |

Original evidence and external trust inputs remain separate. An authentic receipt supplies operation time only after its complete operation tuple is bound to the current document. Native issuer inspection establishes signature and structural facts; complete credential verification still requires the bound operation time. Explicit knowledge time governs timestamped credential-log checkpoints and mirrors, including their future limits.

The native mdoc wire selection uses the pinned component's credential-first critical-header order. The earlier framework order is rejected. The public corpus retains synthetic original bytes for the selected current contract; component cross-consumption uses one shared implementation and is not evidence of a second independently developed verifier.

Organizational delegation remains **CURRENT_STATE_ONLY**. Full independent PAdES LTA validation is **not established**. The ISO 18013-5:2021 source record retains **`fullNormativeTextReviewed=false`**. These limits remain applicable after successful local and CI checks.

## Next bounded draft package

The next proposed package is historical evidence for the existing single-path X509/CMS organization-delegation selection, addressing the intersection of CC-DOC-02 and CC-DOC-05. It is not implemented by this acceptance record and does not change the current-state-only result.

The package must define the retained original grant path, approver registrations and assertions, approval request, final authorization, permit, receipt, status and scoped authority history needed to reproduce an authorization decision at a trusted existence bound. It must specify which facts are evaluated at that historical bound and which later knowledge controls current admissibility. No archived authorization may imply current permission.

Acceptance requires public positive and negative inputs for issuer retirement, expired credentials, timely and missing retained status, later-known compromise, altered or absent approval evidence, and late preservation renewal. A runnable offline verifier must report historical authorization, preserved integrity and current admissibility separately, with exact failure reasons. The package is limited to the existing bounded grant path and selected CMS algorithms; organizational mdoc, arbitrary delegation graphs, deployment custody assessment and a second complete implementation remain separate work.
