# CertConcord Security Engineering Profile — draft 02

> Candidate binding for CertConcord draft 02. This is a working draft, not a final standard. Its requirements apply only when this binding is selected. The [draft architecture](../architecture.md) defines framework scope; the [profile catalog](../profiles.md) records applicability. The draft 02 namespace and wire domain identify experimental formats. Object schema numbers describe field layouts and do not indicate a stable edition.

Status: draft 02. Normative language: English.

## 1. Scope and relationship to the core

SEP defines implementation, measurement and distribution requirements for services implementing [DTI draft 02](DTI-draft-02.md), [COMMON draft 02](COMMON-draft-02.md), [DSCP draft 02](DSCP-draft-02.md), [DCP draft 02](DCP-draft-02.md), [PRF-KPP draft 02](PRF-KPP-draft-02.md) and [PSCP draft 02](PSCP-draft-02.md). It applies across credential types and ecosystems. It changes no signed object, OID, key mode, upstream wire format or historical verification plan. A SEP deployment MUST declare the software artifact and all enabled adapters.

## 2. Parser and execution boundaries

The reference implementation demonstrates and tests protocol semantics. Its custom DER, CBOR, CMS and container parsers are experimental and MUST NOT be treated as the recommended production verification boundary. Packaging them in the verifier SDK does not change that status. Production implementations SHOULD use maintained parser and cryptographic stacks with mature independent evaluation for the enabled formats and algorithms, and MUST apply the additional CertConcord semantic checks. A library's general reputation does not establish support for a particular MTC or post-quantum draft.

The integration MUST preserve original signed bytes, reject duplicate or ambiguous security fields and unsupported critical elements, constrain algorithms and key purposes, and enforce externally configured authority, operation binding, lifecycle, time and evidence completeness. Permissive library parsing or successful primitive verification MUST NOT bypass these checks. Differential tests cover the selected common subset; parser isolation and fuzzing do not establish full verifier assurance.

Every untrusted input MUST have byte, item, nesting, decompression and execution limits. Collection lengths MUST be checked against remaining input and item budgets before allocating arrays. Parsing establishes syntax only; authority, purpose, original signed bytes and policy MUST be verified separately. Public API results MUST distinguish accepted policy, rejected evidence and indeterminate evidence. A malformed object MUST NOT create a positive assurance result.

Externally supplied PDF, XML, certificate, COSE/JOSE, WebAuthn, attestation and archive bytes MUST be processed without provider credentials, root keys or application secrets. Deployments MUST isolate document parsers in resource-limited workers or processes and disable unnecessary network/filesystem access. Direct parser access MUST NOT become a public signing or key-management interface. The system MUST fail closed on resource exhaustion; it MUST NOT substitute a less restrictive parser after a rejection.

Coverage-guided parser campaigns MUST record target, source digest, corpus digest, engine version, limits, duration and findings. Differential tests MUST identify their independent implementation and common supported subset. Acceptance differences caused by deliberately stricter profiles MUST be distinguished from signature bypass or parser disagreement. Minimized regressions MUST use synthetic or appropriately redacted bytes. A test count MUST NOT be used as a measure of cryptographic assurance.

## 3. Durable distributed state

Trust watermarks, single-use authorizations, nonces, key lifecycle and operation outcomes MUST survive process restart. Concurrent writers MUST preserve compare-and-swap revisions and unique operation identifiers. An operation identifier reused with different input MUST fail. Completed results MUST be immutable. A reserved operation with an uncertain provider outcome MUST remain uncertain until the original operation is reconciled from authenticated evidence; recovery MUST NOT redispatch signing.

A transaction MUST atomically bind a log allocation to its issuance state. Log leaves and committed complete-subtree hashes MUST be immutable. A checkpoint and its proofs MUST use the same explicit prefix size even if another writer appends later. A mirror MUST reconstruct roots from retained entries and verify consistency before cosigning. Bounded upload batches MUST preserve verified prefixes and reject forks, reordered entries and mismatched indices.

Database failover policy MUST prevent acknowledged authorization/nonce state from rolling back. A deployment using replicas MUST specify synchronous replication, fencing, recovery point and failover tests; asynchronous replication alone cannot establish that property. Database access MUST authenticate the server and separate migration-owner privileges from runtime privileges. Database tenant identifiers scope locks and rows; they do not replace access-control separation between mutually untrusted operators.

Legacy state migration MUST preserve indices, original bytes, idempotency identifiers, operation outcomes and trust watermarks. It MUST be repeatable, verify source and destination commitments and retain a rollback/audit source. Existing checkpoints MUST remain verifiable. Production activation requires restore, failover and concurrency acceptance for the selected topology.

## 4. Correlation and data minimization

The privacy assessment MUST name observers and their views: issuer, RA, colluding verifiers, status host, log operator, wallet/platform and network observer. It MUST separately evaluate disclosed attributes, holder/document keys, issuer-authenticated bytes, status indices/URLs, proof positions, issue/expiry times and issuer/verifier metadata. Selective disclosure alone MUST NOT be described as unlinkability.

Where transaction unlinkability is required, issuers SHOULD support independently admitted keys and credentials scoped to a verifier or a bounded use window, short credential lifetimes, batched issuance and shared cacheable status lists. New keys MUST retain the core's exact-key admission and revocation requirements. Per-verifier keys MUST NOT be accompanied by a global identity, credential or derivation identifier unless its disclosure is explicitly required by policy. ARKG public derivation material MUST NOT be exposed as a cross-verifier linking handle.

Status caches MUST verify signature, issuer, list URI, bounds and freshness. Cache keys MUST bind issuer and list, not a user-specific query. Caching MUST NOT extend `exp`, `ttl` or the domain's maximum stale interval. A cache failure MUST produce the policy's explicit unavailable/indeterminate result. A list should cover a sufficiently large policy-defined cohort; a per-person list URI defeats aggregation. Fetching status through a cache does not erase indices visible to the verifier.

Intentional document signatures may require accountable signer identity and retained evidence. Their privacy objectives MUST distinguish necessary signer attribution from unnecessary cross-service identity disclosure. A transparency proof can reveal a persistent log position; its presence MUST be included in the observer model.

## 5. Measurements

Published measurements MUST include source/profile versions, environment, algorithm, key sizes, sample counts, warmup, raw samples, input sizes and methods. Signing latency, verification latency, evidence size, Merkle path size and cosignature size MUST be reported separately. Network, database, HSM and human-interaction time MUST NOT be inferred from a local software primitive benchmark.

Privacy datasets MUST contain synthetic subjects or data with an independently established publication basis. Equality attacks MUST report precision, recall and false-positive rate against separate ground truth. Modeled observers, excluded channels, cache assumptions and lifecycle windows MUST be stated. A synthetic outcome MUST NOT be relabeled as a production privacy measurement.

## 6. Supply chain and disclosure

Release artifacts MUST identify software and specification licenses separately and retain third-party notices. Release inputs MUST use exact dependency versions and immutable workflow references. Supported source branches MUST require functional and security checks and prohibit force-push and branch deletion. Exceptions require a documented repository policy.

Release artifacts MUST have content digests, an SBOM and verifiable build provenance binding repository, workflow, source revision and artifact digest. The consumer MUST check that binding against an independently selected repository/workflow. Provenance establishes build origin, not a cryptographic audit or product certification. Build identities MUST have minimal job-scoped permissions and MUST NOT be exposed to untrusted pull-request code.

A maintained implementation MUST provide a working private vulnerability-reporting route. Reports and minimized reproductions MUST exclude real private keys and personal evidence. Security patches MUST preserve evidence interpretation and publish affected versions and deployment implications.

## 7. Independent assessment and interoperability

Cryptographic review MUST identify independent reviewers, conflict disclosures, exact scope, source digest, methods, findings, corrections and retest evidence. Self-tests, AI analysis and SAST MUST NOT be labeled independent cryptographic review. [Assessment requirements](../../docs/assurance.md) define a review package and result record.

External interoperability MUST identify SUT role, exact suite revision, configuration, test identifiers, transport, format, security profile and original result artifacts. OpenID4VCI, OpenID4VP and HAIP are separately selected profiles. EUDI functional assessment is an additional ecosystem mapping when selected; it cannot replace the core tests or confer authority on external issuers. Local adapter acceptance, an external test execution, a reviewed conformance statement and formal certification MUST remain distinct result categories.
