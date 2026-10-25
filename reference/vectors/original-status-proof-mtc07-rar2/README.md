# Original CMS status-proof vectors

This corpus retains the original CMS document package, original CertificateStatus CMS and complete-package ERS from [the CMS retirement corpus](../cms-retirement-mtc07-rar2/README.md). It supplies a separate RFC 4998 proof for the exact original status CMS and authenticated authority histories under explicitly selected synthetic governance roots. These roots are selected from the start; no signed transition from the earlier corpus roots is claimed.

The original package SHA-256 is `09e93450939c93b3dce9daa2ab8f278a357701b46d2d93f0c4fba3c9a0839133`, original status CMS SHA-256 is `65f5d18908b652ac34182411a19b96bf8f1bc1f0c951da74365dd3c7fe92b99e`, and whole-package ERS SHA-256 is `148c25cb9fb9c16846eb14ece6bc8927bdf442444d7ff76168b680236b343050`. Their signatures are retained without regeneration. The timely status ERS SHA-256 is `59d7e66f2170e58d6d9dfa3f22e0c088cc8c743634802eec054ebeaec14d6b3d`.

The fixed seconds are S=1792454400, Ps=1792454401, P=H=R=1792454402 and K=1792627202. The old STATUS appointment ends exclusively at R=P; this is Ps<R=P, not a strict Ps<R<P example. Other old-key roles retain their stated intervals. The status proof protection deadline D is S+100 and its timely renewal is D-1, after H but before D. The late-renewal case uses D+1. The original-TSA H-visibility pair uses H+1; the complete-original-not-yet-visible case uses H-1. Each configuration carries its exact H and K.

The optional selection has exactly three fields: `evidenceRecord`, `preservationPolicy` and `protectionTrust`. The reference verifier derives the status bytes, signer, target and scope from the authenticated original. Its [contract](../../../docs/historical-validation.md#optional-original-certificatestatus-proof) requires the complete original to be visible under H, the first status TSA to be admitted at Ps using both Ps and H knowledge, and the status proof chain to remain protected through K. Only then can B=min(P,Ps) supplement the independent S authority query.

The manifest contains one original-document case and 21 retained cases:

| Cases                                                          | Required distinction                                                                                    |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Default and early status proof                                 | Default P-bound rejection versus admissible S/Ps endpoints                                              |
| Expired, late, future, missing and empty proof; missing policy | Invalid protection, unavailable evidence and unsupported substitution remain distinct                   |
| Wrong role, wrong scope, unknown and revoked authority         | Proof unavailability does not mask established authority failures                                       |
| Unadmitted revocation                                          | An unsigned history alteration fails publication binding rather than becoming trusted revocation        |
| Missing or H-invisible original proof                          | A status-only proof cannot establish complete-original visibility                                       |
| Original TSA incident visible at H                             | A P-admitted original proof cannot supply B after its TSA is rejected under H                           |
| Status TSA interval at H                                       | Fresh Ps and K evidence cannot fill an H gap; the positive interval ends at H+300 and the negative at H |
| Stale current status and wrong current target                  | Historical proof does not repair current admissibility                                                  |

The unknown-authority history removes all old-key appointments, including other roles; it is not an isolated STATUS-only absence case. The admitted compromise applies to that old key across its roles and survives a later GOOD record. No exact signature creation instant or continuous role authorization between S and B is inferred.

## Offline replay

Run from the repository root:

```sh
node reference/verify-vectors.mjs reference/vectors/original-status-proof-mtc07-rar2
node --test reference/original-status-vectors.test.mjs
```

The existing document-vector loader validates the 85 encoded and decoded file hashes, closed data-only configuration and public-key types. Timestamp status in retained proofs comes from the selected authenticated history, so it needs no redundant local GOOD assertion. Stable expected results keep preservation, historical authorization, complete-original visibility, selected status proof and current admissibility separate. Detailed results retain both proof and authority diagnoses.

All signatures and times are synthetic draft fixtures. Replay uses saved public inputs without private keys, new signing, network access or current wall-clock dependence. Acceptance by this reference implementation does not establish complete independent interoperability, production trust, qualification, hardware custody or archive availability. The CMS-only option does not cover native mdoc or organization multi-status packages, and detached ERS does not establish PAdES-LTA or MTC/PQC AdES conformance.
