# Draft 03 acceptance scope

This working draft records a bounded document-verification contract. It does not make a stable or complete-framework conformance claim. The [requirement map](../spec/conformance.json) retains partial coverage and the [conformance record](../spec/conformance.md) separates executable draft evidence from independent implementation and operational assessment.

| Selected boundary | Executable evidence |
| --- | --- |
| Four result classes, stable identity and reasons, and only evaluated dimensions | `reference/sdk-conformance.test.mjs`; an applicable established failure takes precedence over unavailable or unsupported evidence |
| Native mdoc original-byte signatures and shared component contract | `reference/mdoc-document-boundary.test.mjs`; component/framework cross-consumption, exact critical-header order, signature mathematics and explicit knowledge time |
| Offline document, preservation and retained-decision replay | [Public corpus](../reference/vectors/document-acceptance/README.md) and `node reference/verify-vectors.mjs`; the installed SDK consumes the document cases through its public export |
| Atomic retained archive publication | `reference/retained-authorities.test.mjs`; parent-issued process termination between archive write and SQLite commit, restart, retry and idempotent replay from distinct working directories |
| Historical X509/CMS organization delegation | `reference/organization-history-independent.test.mjs`; generated original packages and authenticated ERS proofs exercise separate historical authorization, preservation and current admissibility through the dedicated SDK export |

Original evidence and external trust inputs remain separate. An authentic receipt supplies operation time only after its complete operation tuple is bound to the current document. Native issuer inspection establishes signature and structural facts; complete credential verification still requires the bound operation time. Explicit knowledge time governs timestamped credential-log checkpoints and mirrors, including their future limits.

The native mdoc wire selection uses the pinned component's credential-first critical-header order. The earlier framework order is rejected. The public corpus retains synthetic original bytes for the selected current contract; component cross-consumption uses one shared implementation and is not evidence of a second independently developed verifier.

The live organization-delegation application remains **CURRENT_STATE_ONLY**. The separate retrospective API below grants no current execution permission. Full independent PAdES LTA validation is **not established**. The ISO 18013-5:2021 source record retains **`fullNormativeTextReviewed=false`**. These limits remain applicable after successful local and CI checks.

## Historical organization evidence

The dedicated [`createOrganizationHistoryVerifier`](organization-history.md) implements bounded offline verification of the existing single-path X509/CMS organization-delegation package, addressing CC-DOC-02 and CC-DOC-05. It verifies the original grant path, approver registrations and assertions, approval request, final authorization, permit, receipt, status and scoped authority history against an authenticated first complete-package ERS proof. The signed receipt supplies operation time A; the exact proof upper bound P includes fractional accuracy; constructor-bound current knowledge supplies K. The verifier requires `A <= P <= K`.

Historical authorization evaluates P under knowledge at P. Current admissibility evaluates the same historical operation under knowledge at K, while preservation checks continuous protection through K. All three must be `VALID`. Current successors cannot replace missing original evidence, and later GOOD status cannot erase admitted compromise or conflicts. Historical acceptance grants no current signing, reconciliation, recovery or output-release permission; the live application retains its current policy and journal checks.

The 55 cases in [`organization-history-independent.test.mjs`](../reference/organization-history-independent.test.mjs) use generated synthetic fixtures with real signatures, timestamp tokens and EvidenceRecords. They cover issuer expiry and scoped succession, missing retained status or original approval evidence, later-known compromise, altered approvals, fractional proof bounds and late renewal, with exact expected results. The [installed-package consumer](../reference/sdk/consumer-test.mjs) exercises fractional-time historical acceptance and later revocation through the public export. These are generated fixture tests; a pre-generated organization-history original-byte corpus and a second complete implementation remain unrecorded.

The selection retains the existing bounded grant path and selected CMS algorithms. Organizational mdoc, arbitrary delegation graphs, per-object proofs for authorities retired before the first package proof, separately preserved later status from retired signers, durable cumulative knowledge across verifier restarts, and independent identity or custody assessment remain outside this evidence.
