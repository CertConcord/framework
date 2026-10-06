# MTC document preservation

The current research baseline is a document whose MTC certificate, signature and validation evidence remain interpretable after the signer certificate expires and the live issuer shuts down. Certificate validity limits new signing. The document's validation horizon determines how long evidence must survive. Extending a certificate's validity period does not provide long-term validation.

The executable path uses the existing standalone MTC, ML-DSA CMS signature, ordinary WebAuthn activation, document timestamp, signed status and RFC 4998 evidence record. It introduces no new certificate format, signed assertion or cryptographic primitive. PAdES, CAdES and JAdES retain their format-specific augmentation requirements; this detached preservation path does not claim an AdES Baseline level.

## Preservation sequence

1. Qualify the signer and issue the purpose-bound MTC under externally admitted issuer and cosigner policy. Select the standalone representation before signing and retain its exact bytes.
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

Every deadline is explicit and finite; missing assessments fail closed. The example's short lifetimes are artificial values, not forecasts for SHA-256, SHA-512 or ML-DSA. The reference does not calculate cryptanalytic lifetimes or obtain revocation, governance or incident histories automatically.

Each timestamp requires a stated accuracy interval contained within the TSA certificate validity and ending no later than `at`. Adjacent intervals must not overlap except at their common boundary. This conservative subset does not use optional TSA ordering assertions to admit overlapping intervals.

The initial proof must precede `dataValidUntil`. Every successor proof must precede the preceding timestamp's protection deadline. A chain's data hash must remain acceptable until the first proof of the next hash-renewal chain, or until `at` for the final chain. The final timestamp must still provide protection at `at`. Equality with a deadline fails. A newly signed token cannot repair a lost protection interval.

The result separates `integrity`, `preservation`, the original `proofOfExistenceUpperBound`, `latestRenewalUpperBound` and `verifiedAt`. Renewal does not move the original bound forward. The older `verifyERS` and `verifyXMLERS` helpers return `preservation: NOT_EVALUATED`; XMLERS does not yet implement this lifetime evaluator.

## Historical and current results

After validating preservation, the example re-evaluates the unchanged document package at the initial archive proof's upper bound. Its `historical.knowledgeTime` retains that bound and the caller supplies historical authority policy. This reproduces a historical decision; it does not establish that no later incident was discovered.

The separate evaluation with the later knowledge time returns `current: INDETERMINATE` because its original GOOD response is stale. Preservation can remain VALID. A current VALID decision after issuer retirement requires admissible historical status/incident closure and surviving authorities; that generic resolution service is not implemented here. New applicable compromise evidence can invalidate document validation while archived bytes remain intact.

MTC cosignatures establish the selected issuance commitments. They do not provide document signing time or completeness of later revocation collection. CertConcord's C2SP mirror/witness and RRA governance composition remains separate from the IETF MTC wire draft.

## Encoding and recovery

The RFC 4998 adapter supports bounded nonempty chains, SHA-256/SHA-512 tree hashes, matching timestamp imprint hashes and single-object renewal. An omitted `digestAlgorithm` comes from the timestamp imprint. The first reduced-tree level contains the target hash; later levels contain siblings of the computed node.

Hash renewal hashes the DER-encoded preceding `ArchiveTimeStampSequence`, including its outer SEQUENCE tag and length, and selects RFC 4998 Figure 4's binary-sorted construction. [Erratum 7411](https://www.rfc-editor.org/errata/eid7411) reports the conflicting section 5.2 prose and remains Reported, not an approved correction. Previous reference records omitted the outer sequence framing and used unsorted pairs. Those records are incompatible with this corrected encoding. There is no legacy fallback or silent rewrite of archived bytes.

The sequence framing agrees with the [Bouncy Castle 1.82 implementation](https://github.com/bcgit/bc-java/blob/r1rv82/pkix/src/main/java/org/bouncycastle/tsp/ers/ERSEvidenceRecord.java). This source comparison and the explicit imprint vectors are narrower evidence than a complete cross-implementation preservation assessment.

A custodian writes a complete renewed record separately, validates it against the original object and atomically publishes the new version. A crash before publication leaves the prior record usable until its own deadline. A truncated replacement is rejected. Retrying a timestamp request may yield another token, but recovery cannot claim an unpublished renewal or advance a deadline. Transactional storage, replication and authenticated succession are operational requirements; the in-memory example does not implement them.

## Executable evidence

Run `npm run demo:archive` and `node --test reference/archive-security.test.mjs`. The demonstration closes the issuer service, changes the TSA, renews the data hash and verifies after signer-certificate expiry. It uses generated software keys and synthetic clock/status services. Tests cover missing authority/lifetime inputs, altered original data, malformed chains, late renewal and rejection under changed trust. A subsequently published, signed compromise statement invalidates a current document decision even when the unchanged original package retains valid preservation evidence.

A second complete implementation and independent security assessment are later stability evidence, not prerequisites for continuing draft research. Current unresolved protocol work includes historical status resolution, archived governance transitions, container-specific LT/LTA augmentation and tested archive succession. [Conformance](../spec/conformance.md) records these gaps.

The preservation model follows [RFC 4998](https://www.rfc-editor.org/rfc/rfc4998.html), sections 4 and 5. Broader requirements and standards boundaries appear in [MTC document validation](mtc-document-validation.md).
