# Historical organization evidence

`createOrganizationHistoryVerifier` is a synchronous, offline verifier for the existing `certconcord-ecp-cms-organization-delegation-v1` package and an RFC 4998 EvidenceRecord covering its exact original bytes. It verifies the retained operation and its preservation. A positive result grants no current signing, reconciliation, recovery or output-release permission. The live organization application continues to enforce its signed `CURRENT_STATE_ONLY` policy and current journal checks.

## Time and result scope

| Value | Source and meaning                                                                                                                                                              |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A     | The signed receipt's `executedAt`, accepted only after the original document signature, operation tuple and execution binding are verified. It is an authenticated declaration. |
| P     | The exact upper bound of the first ERS timestamp covering the complete original package, including fractional accuracy. It is a proven existence deadline.                      |
| K     | The latest knowledge time selected by the constructor-bound relying-party source. It is integral and monotonic within one verifier instance.                                    |

The verifier requires `A <= P <= K`. SIM, activation, request, authorization, permit and original execution-lease windows must contain both A and P, with exclusive expiry boundaries. Original grants and registrations must permit the operation at those instants. A timestamp interval does not establish a creation not-before time. A later renewal does not replace P.

The result contains the fixed `coreRevision: 'draft-03'`, selected profile, four-state `overall`, nonempty `reason` and partial eight-dimension `dimensions`. Omitted dimensions are unevaluated. Known invalid mathematics or an applicable policy failure takes precedence over unsupported processing, which takes precedence over unavailable evidence.

| Result                    | State time             | Knowledge time | Scope                                                 |
| ------------------------- | ---------------------- | -------------- | ----------------------------------------------------- |
| `historicalAuthorization` | P                      | P              | `AS_KNOWN_AT_PROOF_TIME`                              |
| `currentAdmissibility`    | P                      | K              | `HISTORICAL_EVIDENCE_UNDER_CURRENT_KNOWLEDGE`         |
| `preservation`            | Complete renewal chain | K              | Continuous protection of the original bytes through K |

All three results must be `VALID` for overall acceptance. The first complete-package proof is authenticated independently at P. Consequently a failed later renewal or missing latest authority coverage does not erase an otherwise established historical view. It still prevents overall acceptance. Missing original dependencies remain `INDETERMINATE`; available independent signature or commitment failures remain `INVALID`.

## Relying-party configuration

```js
import { createOrganizationHistoryVerifier } from '@certconcord/verifier';

const verifier = createOrganizationHistoryVerifier({
  trust: selectedOrganizationTrust,
  authorityResolver: retainedAuthorityResolver,
  readKnowledge: () => ({
    knowledgeTime: latestKnowledgeTime,
    statusMaterial: cumulativeOrganizationStatus,
    certificateStatusMaterial: cumulativeCertificateStatus,
  }),
  preservationPolicy: {
    hashValidUntil: selectedArchiveHashDeadlines,
    resolveTimestamp: selectTimestampTrust,
  },
});
const result = verifier.verify({ originalBytes, evidenceRecord });
```

The alternative [declarative source](organization-history-source.md) constructs these callbacks from closed public-data configuration and exact signed knowledge inputs. Use `createOrganizationHistorySource({configuration, readKnowledge})` and pass the returned opaque source to `createOrganizationHistoryVerifier({source})`. Without `databasePath`, its complete result is equivalent to the callback form under the same selected inputs. The optional dedicated SQLite database retains authenticated negative knowledge across process restarts by reauthenticating stored raw material and adds a `knowledgeReceipt`. It never caches positive acceptance or grants current execution permission. The [saved organization corpus](../reference/vectors/organization-history/README.md) uses the memory form for offline replay through source and installed SDK exports.

`trust` contains `trustDomainID`, `organizationID`, `issuerID`, `identityNamespace`, the exact signed `policy`, `controlTrust`, `credentialTrust`, `algorithmDeadlines`, `hashDeadlines` and `keyDeadlines`. `credentialTrust` contains the selected original certificate, registration authorization, issuer certificate, RA certificate, original status certificate and issuance scope. `controlTrust` maps each exact control certificate to its admitted issuer, purpose and, for organizational status authorities, object types. The external resolver must independently establish the role and scope; a mapping or certificate pin cannot establish admission.

Every role query carries explicit `stateTime` and `knowledgeTime`. Original role holders must be admitted at P and at their relevant original issuance/publication events. An authority history may include authenticated root or role succession. It must retain historical appointments, later incidents and current coverage. Current replacement identities never substitute for original signer admission.

`readKnowledge` returns at most 64 organization status members and 64 certificate status members per evaluation, each `{cms, issuerCertificate}`. The source must provide cumulative applicable incidents, conflicts and current original status bytes. This is an evidence-source contract, not permission to return an outcome. The same verifier also retains up to 4,096 authenticated target/status observations for negative and rollback continuity. It never uses that cache as positive status material. Reaching the bound fails closed as `UNSUPPORTED`; observations are not silently evicted. For the callback constructor and sources without `databasePath`, retention is in memory. A [durable source](organization-history-source.md#durable-source) binds its cumulative knowledge to one immutable configuration, serializes admission with SQLite, and preserves authenticated negative observations without substituting old positive status for current evidence. Complete database rollback still requires an external anchor to detect. Historical reads neither consume nor modify a live operation journal.

The public `verify` method accepts only the original package bytes and EvidenceRecord. It has no operator snapshot, current execution row, caller-selected time, success override or mode to bypass either knowledge view. Unavailable callbacks return typed uncertainty; malformed bounded evidence returns a typed non-VALID result. Constructor configuration errors may throw.

## Original authorization and current knowledge

Original workload permission is attested by the signed final authorization, its exact approval request, and the attenuated grant path. Verification checks each original registration, raw ES256 assertion, independent person and key, exact challenge, scope, policy and original execution tuple. It does not reconstruct an `operator.active` database flag, actual nonce consumption or global credential counters. Its counter claim is limited to each signed registration's baseline.

Every original required status remains mandatory. A current successor cannot fill a missing original statement. Status retained inside the original package is protected by its ERS proof: its signer is admitted at publication and P, using the selected knowledge view. Later external status is outside that original proof. Without a separate preservation proof, its signer must be admitted at both claimed publication time and K, with acceptable certificate, key, signature-algorithm and hash protection through K. A currently admitted scoped successor can refresh the original target. External statements from a now-retired signer requiring their own preservation proof are outside this bounded selection.

All authenticated same-epoch conflicts and terminal incidents remain applicable. Ordinary revocation effective after P does not retroactively invalidate the operation. Revocation or compromise effective at or before P does. An admitted key-wide compromise follows the exact key across object identifiers. Applicable incidents dominate stale or missing current coverage; a newer GOOD statement cannot erase them. Retirement or expiry never waives latest coverage.

## Preservation and limitations

The initial data protection deadline is derived from the minimum of every original signature/key/hash dependency used in verification. This includes certificate expiry, certificate-signature algorithms, subject-signature algorithms, original status/control signers, raw approver P-256 keys, and commitment hashes. The result exposes `originalProtectionDeadline` and its `protectionLedger`. A supplied `preservationPolicy.dataValidUntil` can only tighten the derived bound. Later-only status successor keys are excluded from this original minimum and are evaluated separately through K.

The first proof must precede that bound. Every renewal must preserve continuity before the previous protection expires; a late renewal cannot repair an expired chain. ERS binds the entire original package; no signature archive format or replacement organization leaf is introduced. TSA status preserves `VALID`, `INVALID`, `UNSUPPORTED` and `INDETERMINATE`, including current history coverage failures. Every non-VALID result prevents acceptance.

The generic `createVerifier` continues to reject the organization delegation plan with `ORG_CURRENT_VERIFIER_REQUIRED`. The dedicated export supplies this bounded retrospective interpretation. It does not change existing execution recovery, privacy, identity-source, ES256 approval, parser-assurance or durable-storage limits described in [organization delegation](organization-delegation.md).
