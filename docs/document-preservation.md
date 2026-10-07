# CMS and native mdoc document preservation

The current research baseline is a document whose MTC certificate, signature and validation evidence remain interpretable after the signer certificate expires and the live issuer shuts down. Certificate validity limits new signing. The document's validation horizon determines how long evidence must survive. Extending a certificate's validity period does not provide long-term validation.

The executable baseline uses standalone MTC with ML-DSA CMS or a native signer mdoc with COSE, ordinary WebAuthn activation, document timestamps, signed status and RFC 4998 evidence records. Retained RootTrustManifest history supplies scoped authority appointments, status/incidents and governance transitions. It introduces no new certificate, archive signature format or cryptographic primitive. This detached preservation path does not claim an AdES Baseline level. The separate [selected CAdES adapter](cades-preservation.md) adds standard ATSv3 container preservation and the [selected PAdES adapter](pades-preservation.md) adds PDF DSS/document-timestamp preservation, each with its own bounded P-256/direct-root profile. JAdES retains its distinct augmentation requirements.

## Preservation sequence

1. Qualify the signer and issue the purpose-bound MTC or native mdoc under externally admitted RA, issuer and transparency policy. For MTC, select the standalone representation before signing. Retain the independent scoped RA decision and exact credential bytes.
2. Bind the document bytes, intent and admitted key to the authorized operation. Obtain the document timestamp while the operation window remains open.
3. Collect and verify the signed status and other dependencies. Freeze the complete encoded evidence package, including status and its verification plan, before obtaining the initial archive timestamp. The earlier document timestamp deliberately excludes refreshable status.
4. Renew archive protection before it becomes inadequate. A TSA/signature transition and replacement of a data hash have different input requirements. Retain the original package and every preceding chain.
5. Verify the preserved package under externally admitted authorities and explicit security lifetimes at the later evaluation time. Report its historical validation result separately from a current decision.

The example treats one complete package as one archived data object. Later status responses can augment a current verification copy without rewriting that object or its evidence record. Preserving such additions requires archiving the augmented version and retaining the original; no second framework-specific signed archive manifest is required.

## Reference contract

`verifyERSPreservation(record, bytes, policy)` accepts these external inputs:

| Input                     | Meaning                                                                                                                                                                                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `at`                      | Evaluation time in integer Unix seconds                                                                                                                                                                |
| `dataValidUntil`          | Exclusive protection deadline for the original package, derived from the earliest applicable algorithm, commitment or authority failure; ordinary signer-certificate expiry alone is not this deadline |
| `hashValidUntil`          | Explicit exclusive deadlines by hash OID for evidence-record tree hashes                                                                                                                               |
| `resolveTimestamp(token)` | Authority selection returning the exact TSA certificate, issuer key, policy OID, optional revocation cutoff, `validUntil` and a historical status evaluator                                            |

Each TSA's `validUntil` covers its signature algorithm, CMS digest, issuer path and key/authority acceptability. Certificate expiry and an explicit revocation cutoff further restrict it. The resolver must reject unknown authorities; an embedded certificate cannot establish trust. Its `status({certificate, genTime, stateTime, knowledgeTime})` callback must consider admissible status and incident information at the supplied current knowledge time. Constant success is appropriate only for the synthetic example.

Every deadline is explicit and finite; missing assessments fail closed. The fixtures' lifetimes are artificial values, not forecasts for SHA-256, SHA-512 or ML-DSA. The reference does not calculate cryptanalytic lifetimes or fetch revocation, governance or incident histories automatically. The [retained-history resolver](historical-validation.md) authenticates supplied history under externally selected roots, publication proofs and deadlines.

Each timestamp requires a stated accuracy interval contained within the TSA certificate validity and ending no later than `at`. Adjacent intervals must not overlap except at their common boundary. This conservative subset does not use optional TSA ordering assertions to admit overlapping intervals.

The initial proof must precede `dataValidUntil`. Every successor proof must precede the preceding timestamp's protection deadline. A chain's data hash must remain acceptable until the first proof of the next hash-renewal chain, or until `at` for the final chain. The final timestamp must still provide protection at `at`. Equality with a deadline fails. A newly signed token cannot repair a lost protection interval.

The result separates `integrity`, `preservation`, the original `proofOfExistenceUpperBound`, `latestRenewalUpperBound` and `verifiedAt`. Renewal does not move the original bound forward. The older `verifyERS` and `verifyXMLERS` helpers return `preservation: NOT_EVALUATED`; XMLERS does not yet implement this lifetime evaluator.

## Historical and current results

`verifyPreservedDocument` verifies ERS against the unchanged original package, evaluates historical authorization at the selected earlier knowledge time, and evaluates current admissibility with later retained knowledge. Refreshable status can be supplied in a current verification copy only when its immutable document-operation commitment and trust domain match the preserved original. A historical VALID result does not establish that no later incident was discovered.

The retained resolver selects appointments at operation stateTime and applicable status/incidents at knowledgeTime. Contiguous authenticated manifests, conservative publication bounds and coverage horizons prevent backdating. Dual old/new root quorums admit succession; previously admitted appointments survive normal retirement. A later key compromise cannot be erased by a GOOD snapshot or another certificate for the same key. Every non-VALID dimension prevents overall acceptance.

The complete CMS and native mdoc tests obtain current VALID after issuer retirement using retained history and fresh signed status, while the unchanged original package with stale status yields INDETERMINATE. A later applicable compromise makes current admissibility INVALID while preservation and the earlier historical decision remain VALID. The smaller `demo:archive` example intentionally demonstrates the stale-status case and does not exercise the complete retained-history service.

MTC cosignatures establish the selected issuance commitments. They do not provide document signing time or completeness of later revocation collection. CertConcord's C2SP mirror/witness and RRA governance composition remains separate from the IETF MTC wire draft.

## Encoding and recovery

The RFC 4998 adapter supports bounded nonempty chains, SHA-256/SHA-512 tree hashes, matching timestamp imprint hashes and single-object renewal. An omitted `digestAlgorithm` comes from the timestamp imprint. The first reduced-tree level contains the target hash; later levels contain siblings of the computed node.

Hash renewal hashes the DER-encoded preceding `ArchiveTimeStampSequence`, including its outer SEQUENCE tag and length, and selects RFC 4998 Figure 4's binary-sorted construction. [Erratum 7411](https://www.rfc-editor.org/errata/eid7411) reports the conflicting section 5.2 prose and remains Reported, not an approved correction. Previous reference records omitted the outer sequence framing and used unsorted pairs. Those records are incompatible with this corrected encoding. There is no legacy fallback or silent rewrite of archived bytes.

The sequence framing agrees with the [Bouncy Castle 1.82 implementation](https://github.com/bcgit/bc-java/blob/r1rv82/pkix/src/main/java/org/bouncycastle/tsp/ers/ERSEvidenceRecord.java). This source comparison and the explicit imprint vectors are narrower evidence than a complete cross-implementation preservation assessment.

ArchivePublicationStore validates a complete proposed record against the original object and atomically publishes its ERS head, data commitment and authenticated governance/custodian history. Its external synchronous validator must authenticate the actual ERS and custodian role; structural storage checks alone do not do that. Compare-and-swap rejects competing heads. A crash before commit leaves the prior record usable until its own deadline. A truncated replacement is rejected.

ArchiveRenewalCoordinator reserves the exact nonce-bearing request before contacting the TSA. A lost response remains unknown across restart; reconciliation verifies the retained token, imprint, nonce, policy, TSA lifecycle and protection deadline before publishing. It does not repeat uncertain execution. A newly issued late token cannot repair a lost interval. The journal implements local atomic persistence and tested custodian succession; replication, disaster recovery, clock operation and rollback-resistant backups remain separate deployment obligations.

## Executable evidence

Run `node --test reference/retained-authorities.test.mjs reference/retained-document.test.mjs reference/archive-security.test.mjs` for the complete selected baseline and its lower-level boundaries. The full flows use real CMS/COSE, RFC 3161 and ERS signatures, close the live issuer, retain root and custodian transitions, renew timestamp and data-hash protection, and verify offline after signer expiry. Fault cases include missing coverage, backdating, late compromise, lost TSA responses, restart, competing publications and process termination between archive write and commit. `npm run demo:archive` remains a smaller introduction to detached renewal and historical replay.

All clocks, lifetimes, governance and custody in these tests are synthetic. Long-lived RAW_KEY appointments are explicit test policy, not an inference from an expired wrapping certificate. A second complete implementation and independent security assessment remain stability evidence. The separate CAdES adapter has a bounded container profile; additional container profiles, operational clock/custody assurance and distributed archive resilience remain gaps. [Conformance](../spec/conformance.md) records these limits.

The preservation model follows [RFC 4998](https://www.rfc-editor.org/rfc/rfc4998.html), sections 4 and 5. Broader requirements and standards boundaries appear in [MTC document validation](mtc-document-validation.md).
