# Declarative organization history source

`createOrganizationHistorySource` adapts declared public trust and retained material to the existing organization history verifier. It is synchronous and offline. In memory mode it returns the same complete result as equivalent callback-based verification. Durable mode adds the storage receipt described below. Neither mode grants current execution permission.

```js
import {
  createOrganizationHistorySource,
  createOrganizationHistoryVerifier,
} from '@certconcord/verifier';

const source = createOrganizationHistorySource({
  configuration,
  readKnowledge: () => latestKnowledge,
});
try {
  const verifier = createOrganizationHistoryVerifier({ source });
  const result = verifier.verify({ originalBytes, evidenceRecord });
} finally {
  source.close();
}
```

The reader returns material, never authority decisions or verification outcomes. The implementation copies the configuration at construction and the reader's snapshot on each verification. Functions, accessors, proxy objects, private key fields, KeyObject values and unknown fields are not accepted in the descriptor. Shared organization record and snapshot admission rejects proxies before type inspection or reflection, including nested proxies, without invoking their traps. The verifier input cannot replace K or its selected source. An asynchronous or throwing reader produces a typed non-VALID result.

The source is opaque. Multiple verifiers attached to the same source share its admitted negative observations and monotonic selected K. Closing it prevents further positive verification. Without `databasePath`, a new source starts with new memory, `readEvidence` returns undefined, and results contain no storage receipt. The existing callback constructor also remains memory-only. Durable storage is an explicit option described below.

## Configuration

The closed configuration schema is:

```text
schemaVersion: 1
trust: existing complete OrganizationHistoryTrust
retainedAuthorities:
  governance:
    roots: [{ publicKeyDER, validFrom, validUntil }]
    threshold
  algorithmDeadlines: { Node asymmetric key type: exclusive deadline }
  publication:
    format: "RFC3161"
    timestampAuthorities: [publication timestamp pin]
    hashValidUntil: { dotted hash OID: exclusive deadline }
preservation:
  hashValidUntil: { dotted hash OID: exclusive deadline }
  dataValidUntil: optional tightening bound
  timestampAuthorities: [archive timestamp pin]
```

Each timestamp pin contains exact X.509 DER `certificate`, canonical public SPKI DER `issuerPublicKeyDER`, explicit policy OID `policy`, finite exclusive `validUntil`, explicit `signatureProfile` (`CERTCONCORD-PQ` or `EXTERNAL-RFC3161`), and optional `revokedAt`. Publication pins additionally require `validFrom` and finite exclusive `knowledgeValidUntil`. Duplicate roots and duplicate timestamp certificate pins are rejected.

Publication pins are externally selected bootstrap trust, independent of the RTM they authenticate. The adapter verifies the actual RFC 3161 signature, certificate, issuer, policy, manifest-publication imprint and complete accuracy interval. It also checks the selected appointment, protection, hash and knowledge-coverage bounds. It never substitutes an unconditional positive timestamp status. Direct publication proofs become non-VALID after their selected protection/coverage bounds; this adapter does not invent an archival renewal for them.

Archive timestamp authority roles and status come from the authenticated RTM history. The token certificate only selects a candidate pin; it does not establish trust. Existing original-proof and complete-ERS verification still authenticate every required signature, imprint and preservation interval. `dataValidUntil` can only tighten the earliest deadline derived from the original signatures, keys and hashes.

## Knowledge snapshot

```text
knowledgeTime: nonnegative safe integer
authorityHistory: [
  {
    manifest: exact deterministic-CBOR RTM body Buffer,
    signatures: [{ keyID: Buffer, signature: Buffer }],
    publicationProof: actual RFC 3161 token Buffer
  }
]
statusMaterial: [{ cms: Buffer, issuerCertificate: Buffer, evidenceRecord?: Buffer }]
certificateStatusMaterial: [{ cms: Buffer, issuerCertificate: Buffer, evidenceRecord?: Buffer }]
```

RTM bodies are retained as exact canonical bytes. The adapter does not reconstruct a signed manifest from JSON. Existing root quorum, predecessor continuity and dual-quorum root succession rules remain in force. The caller supplies a complete retained history to this memory adapter. Missing history or current coverage is not replaced by a cached positive decision.

The historical view uses exact P, including fractional accuracy, as both state and knowledge time. Current historical admissibility uses state P and latest selected K. Publication coverage is evaluated for the corresponding knowledge view, so a missing latest window does not erase an independently established historical result. Every current status and authority check still uses current coverage.

Both external status lists may contain an optional `evidenceRecord` with exact RFC 4998 bytes covering the complete CMS. The [historical verifier](organization-history.md#original-authorization-and-current-knowledge) authenticates the exact status authority at publication S and first status proof P_status under current knowledge K, validates continuous preservation, and still requires current status coverage. For organization delegation status, the exact typed target must be admitted from an authenticated original package; the separate status proof does not replace P. An external CMS that also appears in the original package retains its P authority obligation as well as the attached-proof checks. For a statement considered at K, a present proof cannot be ignored, including on duplicate bytes, or replaced by the unpreserved path after failure. Delegation statements with signed publication S > K are excluded before proof verification and cannot enter current trusted knowledge.

Configuration is bounded to 4 MiB, each reader snapshot to 16 MiB, RTM history to 256 entries, each status list to 64 members, and root/TSA lists to 64 members. Each optional status ERS is bounded to 16 MiB and remains subject to the smaller available space in the complete snapshot. Existing tighter certificate, signature, profile, nesting and item bounds apply. These are capability limits, not retention guarantees. A memory source cannot preserve incidents across process restart or detect rollback of a separate external data store.

Frozen-byte replay uses the same descriptor and factories. A loader may resolve bounded file references into Buffer values, but must not supply a second interpretation of authority, timestamp, role or status semantics. Replay requires no private signing key, fixture generator, network request or live execution journal.

## Durable source

Pass `databasePath` to use a dedicated local SQLite database. `:memory:` and existing live operation journals are rejected. A database is bound to the selected trust domain, organization, issuer and identity namespace, and to the complete immutable configuration and implementation capability revision. Pins use the exact public DER bytes above. All selected policies, governance quorum, algorithm/key/hash deadlines and timestamp protection/coverage bounds participate in configuration identity. A changed configuration is rejected for that database; advancing K, adding signed status or extending authority history does not create a new namespace. Different originals in the same scope share key-wide incidents.

The current durable capability is `organization-history-sqlite-v2`, configuration revision 2. It includes independently preserved external delegation-status members. A v1 binding is rejected with `ORG_HISTORY_CONFIGURATION_MISMATCH`; no automatic relabeling or migration occurs. Retain the earlier database and its compatible implementation when that knowledge context is still needed. A new v2 database starts a separate context until its required raw evidence and history have been authenticated.

```js
const source = createOrganizationHistorySource({
  configuration,
  readKnowledge: () => latestKnowledge,
  databasePath: './organization-history.sqlite',
});
try {
  const result = createOrganizationHistoryVerifier({ source }).verify({
    originalBytes,
    evidenceRecord,
  });
  if (result.knowledgeReceipt.state === 'COMMITTED') {
    const retained =
      result.knowledgeReceipt.evidenceID && source.readEvidence(result.knowledgeReceipt.evidenceID);
    // Retained bytes have classification "UNVERIFIED_BYTES". Verify them anew.
  }
} finally {
  source.close();
}
```

Each verification copies the caller's knowledge once before entering a `BEGIN IMMEDIATE` transaction. Under that transaction it reloads all committed frames, reauthenticates exact raw RTM bodies, root signatures, publication timestamps and admitted status at each frame's original K, evaluates the new input, appends independently authenticated material and commits before exposing the result. SQLite uses WAL, `synchronous=FULL` and a 5-second busy timeout. Concurrent instances and processes reload after acquiring the write lock; they cannot overwrite a competing observation from a stale in-memory view. The database contains no cached positive authorization, imported verdict or live execution permission.

Raw replay retains an original ECP and ERS exactly when a newly authenticated observation requires that pair to reconstruct knowledge. A transaction with no new authenticated knowledge advances only selected K; repeated RTM/status material and a different opaque input do not create another replay frame or stored pair. Independent authority-history updates and selected-credential status retain their authenticated raw material without retaining the submitted original. Their frames have no evidence ID and are reauthenticated with original evidence unavailable. An earlier authenticated publication proof for an existing RTM remains a meaningful history update. Original bytes that are retained remain opaque evidence storage: a malformed or unadmitted leaf is not a trusted observation. Original target admission requires an authenticated package proof and the target's own signature, schema, scope, interval and applicable delegation-path checks. An unrelated missing execution leaf does not discard a separately authenticated negative. External status must bind an admitted target or the selected credential and pass its own signature, schema and time checks. Unpreserved status requires signer admission at S and K. Separately preserved CertificateStatus and OrganizationDelegationStatus use the S/P_status admission and continuous-protection requirements above; their proofs do not supply current authority or status coverage. Organization-status frames retain the exact CMS, issuer certificate and ERS together with the required original evidence ID, so target admission can be reauthenticated after restart. They cannot become frames with no original evidence ID. A globally INVALID, UNSUPPORTED or INDETERMINATE assessment can therefore commit authenticated negative material, while its unauthenticated siblings remain excluded from trusted frames.

Replaying old frames at their original K reconstructs terminal revocations, compromises, same-epoch conflicts and freshness heads even when the new reader supplies only newer GOOD status. Retained raw authority predecessors can authenticate a new successor suffix. Known RTM forks and authority revocations remain negative constraints. Retained knowledge never supplies a positive authority/status decision at current K: current coverage and preservation are evaluated again. Historical authorization remains a distinct P/P view. Recovery needs no signing, operation dispatch, reconciliation, nonce update or execution re-run.

The selected relying-party K is persisted monotonically. Equality is accepted; rollback is rejected. A well-formed selection may advance K despite failed evidence authentication, while malformed or unavailable reader input does not advance it. Authenticated evidence admission and K selection are separate facts. A failed transaction adds neither; uncertain commit acknowledgement requires closing and reopening the source before further use.

Every durable verification includes:

```text
knowledgeReceipt:
  mode: "SQLITE"
  state: "COMMITTED" | "NOT_COMMITTED" | "UNKNOWN"
  scopeID: lowercase hexadecimal scope identifier
  configurationID: lowercase hexadecimal complete-configuration identifier
  revision: committed head revision, or null
  evidenceID: identifier of the submitted original/ERS pair if retained, or null
```

`COMMITTED` reports that the transaction completed, including a transaction that recorded an INVALID result's authenticated negative material or sticky capacity failure. It does not promise retention of every submitted pair: `evidenceID` is null when the pair was not needed for a newly admitted observation and was not already retained. A replay of an already retained pair can return its existing identifier. It does not certify the original bytes or grant an operation. An idempotent replay can return the same revision. `NOT_COMMITTED` means no current transaction was confirmed and cannot expose a positive durable verdict. `UNKNOWN` means the transaction body completed but COMMIT acknowledgement was unavailable; the source refuses subsequent verification and evidence reads until reopened. A process killed after COMMIT but before returning has the same recovery path: reopen, retrieve exact evidence when its identifier is known, and verify again. No saved result is trusted during recovery.

`readEvidence(evidenceID)` returns `undefined` for an unknown identifier, or independent Buffer copies `{ classification: 'UNVERIFIED_BYTES', originalBytes, evidenceRecord }`. It validates chunk identities, lengths and the identifier's binding to that exact original/ERS pair, but does not perform historical authorization. Invalid identifiers, corrupt storage and reads after closure fail; returned bytes must be submitted to verification before relying on them.

## Durable bounds and recovery limits

Durable mode additionally bounds an original to 64 MiB, its ERS to 16 MiB, committed replay frames to 256, semantic observations to 4,096, distinct authenticated RTM bodies to 256, exact original/ERS pairs to 1,024 and distinct exact stored content to 256 MiB. Content uses chunks no larger than 1 MiB; the frame, chunk references, evidence identity, selected K and observation metadata commit atomically. Existing decoder and retained-resolver bounds still apply. A result is never authorized by omitted or truncated replay material.

Duplicate exact content, including raw frame bodies, is stored once. The ordered replay list may reference the same frame again when an intervening history update allows it to establish new authenticated observations. Each replay position counts toward the 256-frame limit. Reauthentication of unchanged knowledge and selection of a newer K alone do not create frames. New original-dependent observations, independently authenticated history updates and selected-credential status remain eligible for bounded retention even when the overall assessment is non-VALID. There is no eviction or automatic compaction. Exceeding a cumulative limit records a sticky overflow flag in the same transaction, preserves previously committed material and returns non-VALID. Reopening still reauthenticates the retained frames: an established INVALID remains stronger than the UNSUPPORTED capacity result. Once overflow is sticky, a well-formed newer K can commit only the selected-K metadata, with `COMMITTED`, the actual persisted revision and `evidenceID: null`. The frames, artifacts, observations, authority-history identities and exact content remain unchanged. An equal-K transaction may confirm the same revision; a lower K is rollback and returns `NOT_COMMITTED`. Old incidents are never replaced by an empty cache. Per-read oversized or malformed input is rejected before admission and cannot erase older observations. Applications must provision and retain this bounded store as part of their evidence policy.

The database is local persistence, not an external monotonic anchor. Missing, changed, reordered or truncated referenced chunks and inconsistent replay metadata fail closed. An attacker or administrator who restores an entire older, internally consistent database and its required WAL state can also restore its old K and incident set; this implementation cannot detect that complete rollback. Replacing the database or selecting a different configuration/database starts a different knowledge context and must not be represented as continuity. Durable storage also assumes the filesystem and SQLite durability guarantees hold. No remote checkpoint service or new signed archive format is introduced.

Organizational mdoc and per-object proofs replacing the complete-package ERS proof or admitting original-package roles retired before that proof remain outside this source contract. The optional external status proofs described above do not extend those scopes.
