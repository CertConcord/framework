# Declarative organization history source

`createOrganizationHistorySource` adapts declared public trust and retained material to the existing organization history verifier. It is synchronous and offline. It returns the same complete result as equivalent callback-based verification and grants no current execution permission.

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

The reader returns material, never authority decisions or verification outcomes. The implementation copies the configuration at construction and the reader's snapshot on each verification. Functions, accessors, private key fields, KeyObject values and unknown fields are not accepted in the descriptor. The verifier input cannot replace K or its selected source. An asynchronous or throwing reader produces a typed non-VALID result.

The source is opaque. Multiple verifiers attached to the same source share its instance-local admitted negative observations and monotonic selected K. Closing it prevents further positive verification. A new source starts with new memory. This version has no durable storage: `databasePath` is rejected, `readEvidence` returns undefined, and results contain no storage receipt. The existing callback constructor remains available.

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
statusMaterial: [{ cms: Buffer, issuerCertificate: Buffer }]
certificateStatusMaterial: [{ cms: Buffer, issuerCertificate: Buffer }]
```

RTM bodies are retained as exact canonical bytes. The adapter does not reconstruct a signed manifest from JSON. Existing root quorum, predecessor continuity and dual-quorum root succession rules remain in force. The caller supplies a complete retained history to this memory adapter. Missing history or current coverage is not replaced by a cached positive decision.

The historical view uses exact P, including fractional accuracy, as both state and knowledge time. Current historical admissibility uses state P and latest selected K. Publication coverage is evaluated for the corresponding knowledge view, so a missing latest window does not erase an independently established historical result. Every current status and authority check still uses current coverage.

Configuration is bounded to 4 MiB, each reader snapshot to 16 MiB, RTM history to 256 entries, each status list to 64 members, and root/TSA lists to 64 members. Existing tighter certificate, signature, profile, nesting and item bounds apply. These are capability limits, not retention guarantees. A memory source cannot preserve incidents across process restart or detect rollback of a separate external data store.

Frozen-byte replay uses the same descriptor and factories. A loader may resolve bounded file references into Buffer values, but must not supply a second interpretation of authority, timestamp, role or status semantics. Replay requires no private signing key, fixture generator, network request or live execution journal.
