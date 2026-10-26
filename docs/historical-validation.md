# Retained authority history and document preservation

`verifyPreservedDocument` reports preservation integrity,
historical authorization under a selected earlier knowledge time, and current
admissibility under later retained knowledge. Every non-VALID decision prevents
overall acceptance. A later discovered compromise can invalidate current
admissibility while the historical result and the integrity of the preserved
original bytes remain valid. Fresh status cannot change the signed operation.

Historical acceptance requires the authenticated first ERS proof of the exact
complete `originalBytes` at an upper bound P no later than
`historicalKnowledgeTime` H. A missing or later proof leaves historical byte
visibility INDETERMINATE, while independently invalid original mathematics remain
INVALID. Typed INVALID and UNSUPPORTED failures of a supplied initial proof retain
their outcome and reason, even when a later TSA status callback returns GOOD.
Absent proof and unavailable trust remain distinct INDETERMINATE outcomes.
Signed `publishedAt` and `iat` fields alone cannot establish that the
status bytes were available by H. The earlier document timestamp excludes those
refreshable leaves. A later full-package archive cannot backfill an earlier history
view. The optional original-status proof below supplies a narrower status-byte
bound while retaining the complete-original requirement.

Without an original-status proof selection, original status authority is checked
at its claimed publication time and at P,
with H knowledge in both queries. P is an existence upper bound, not an exact
signing time. A claimed publication after P is rejected, and a known key incident
or authority retirement by P cannot be bypassed with an earlier claimed time.
The initial TSA is checked under both P and H knowledge. The result exposes
`originalProof` and `historicalBytesVisibility` separately from preservation
through the current knowledge time. A later renewal signature failure does not
erase an independently authenticated initial proof. Later status remains eligible
for the separate current-admissibility decision.

The original evidence bytes are preserved by RFC 4998 ERS using RFC 3161
timestamps. Status and other refreshable evidence may be supplied separately for
current evaluation, but the immutable document-operation commitment must match.
Hash and authority protection intervals must remain continuous; a late timestamp
cannot repair a lost interval. An issuer outage does not prevent offline
verification when the retained evidence and selected knowledge coverage suffice.
It cannot be treated as evidence that an authority or credential is still good.

## Optional original CertificateStatus proof

The selected CMS reference path accepts an optional `originalStatusProof` record
with three fields:

| Field                | Meaning                                                                                                                                  |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `evidenceRecord`     | RFC 4998 DER ERS over the exact complete original CertificateStatus CMS                                                                  |
| `preservationPolicy` | Hash deadlines and the existing per-token `resolveTimestamp` callback                                                                    |
| `protectionTrust`    | External `keyDeadlines`, `algorithmDeadlines` and `hashDeadlines` for the status CMS, as used by the shared status-preservation verifier |

The verifier authenticates the typed original CMS under the exact status signer
from `historicalTrust`. It derives the target certificate, trust domain, issuer,
representation, profile and publication time S from the original and its selected
trust. These identities cannot be overridden by option fields; unknown fields
are rejected. No new signed object or archive format is introduced.

Let Ps be the first authenticated bound for those exact status bytes, P the
complete-original bound, H the historical knowledge time and K the current
knowledge time. The supplemental proof requires S <= Ps <= H, initial TSA
admission at Ps under both Ps and H knowledge, and continuous preservation through
K. Later renewal timestamps are evaluated with K knowledge. A GOOD status learned
at K does not fill a missing initial-TSA status interval at H.

The status authority is checked independently at S using H knowledge. Only after
the complete original is admitted under H and the supplemental proof passes is
the additional B = min(P, Ps) query admitted, also with H knowledge. This permits ordinary status-role retirement after Ps but no
later than P when the earlier proof and all other requirements pass. A later
supplemental proof cannot move the bound past P. Neither endpoint establishes an
exact signing instant or continuous role authorization between the endpoints.
The complete original still requires P <= H and its own TSA admission under H;
a supplemental status proof cannot make an unproven original historically visible.

The option is limited to a single original CMS CertificateStatus. Native mdoc
status lists and organization multi-status contexts produce an explicit
UNSUPPORTED capability result. Missing required original context is
INDETERMINATE; duplicate context objects are INVALID. An omitted or undefined
option retains the existing result shape and authority queries. Explicit null,
an array or unknown option fields are INVALID. Missing proof bytes are
INDETERMINATE, whereas empty or malformed supplied proof bytes are INVALID.
Missing preservation policy or protection deadline assessments are INDETERMINATE;
the latter retains the shared `ORG_PROTECTION_DEADLINE_MISSING` reason.

When selected, `originalStatusProof` reports the proof outcome and, on success,
`proofOfExistenceUpperBound` Ps. `originalStatusAdmission` records each matching
status-authority evaluation with S, H, B (null if no bound was admitted), and
separate `proof` and `authority` outcomes. The SDK may request the same status
authority more than once. The proof outcome participates in overall acceptance
even when an unsupported context produces no matching authority query. The
existing preservation, historical-authorization and current-admissibility results
remain separate.

For an authenticated original status, S is checked independently even when the
selected proof is unavailable or invalid. A rejected proof does not invent B or
silently select another proof. Established INVALID authority takes precedence
over unavailable evidence; UNSUPPORTED precedes INDETERMINATE, and both diagnoses
remain available. S/B resolver results use the existing SDK decision guard.
Current status and non-selected roles retain their own validation requirements.

The [saved original-status corpus](../reference/vectors/original-status-proof-mtc07-rar2/README.md)
replays this three-field interface against unchanged original CMS bytes, separate
status ERS and authenticated synthetic authority histories at explicit H and K.

The generated `original-status-proof.test.mjs` cases exercise these boundaries
with synthetic clocks, authorities and real signed CMS/ERS bytes. They do not
establish operational TSA assurance, a stable interface or an AdES level.

The retained resolver reuses the signed RootTrustManifest domain. Its version-2
snapshot includes domain, contiguous serial and predecessor commitment, issue and
validity times, knowledge coverage, and explicitly scoped authority appointments.
Publication proof authenticates the manifest and its root signatures together.
External governance roots, quorum, root lifetimes, and algorithm deadlines are
mandatory inputs. Root succession requires both the old and new root quorums on
the same snapshot. No root is admitted merely because retained evidence contains
its public key.

The publication verifier authenticates existing RFC 3161 or ERS evidence at the
configured `validationTime`. It returns a conservative proof-of-existence upper
bound. This verification time is separate from the historical `knowledgeTime`:
a valid later publication is excluded from an earlier knowledge view. Content
timestamps cannot substitute for an authenticated publication bound. Appointments
are selected at operation time, while status and incidents use the selected
knowledge time. Retirement or rotation does not delete an earlier appointment;
missing later status coverage still produces an indeterminate current result.
Key compromise is irreversible across subsequent GOOD snapshots, roles, and
certificate renewals. Appointments first published after the operation cannot be
backdated to authorize it.

The reference retained resolver takes one detached snapshot of the query before
calling the publication verifier. Identity bytes, role, scope and both times
retain their entry values throughout traversal and the final authority decision,
even if a callback changes the caller's query. `stateTime` and `knowledgeTime`
must be finite nonnegative numbers no greater than `Number.MAX_SAFE_INTEGER`,
with `stateTime <= knowledgeTime <= validationTime`. Fractional instants are
preserved exactly; invalid times return `INVALID/HISTORY_TIME` before publication
verification.

Query and scope records must be non-Proxy ordinary or null-prototype objects.
Consumed fields must be own data properties. Unrelated top-level properties are
ignored. Scope data keeps its enumerability, including nonenumerable selected
qualifiers; unused nonenumerable properties and symbols are ignored. Ordinary
scope errors, such as an unknown enumerable field or empty qualifier, retain
the existing authority decision and known-revocation precedence. Identity and
scope bytes use owned copies of ordinary `Buffer` views, including nonzero
offsets, without reading caller conversion, constructor or size properties.
Buffer subclasses, custom prototypes, other typed-array views, proxies, fake
Buffer objects and shared backing storage are outside this input profile.
Accessors on consumed record fields, executable scope values and unsupported
object or byte shapes return `INVALID/HISTORY_QUERY` before publication
verification. This data-only boundary does not authenticate a query or select
new governance, and does not change the direct resolver or configuration APIs.

The [fixed query replay vectors](../reference/vectors/retained-query-snapshot.json)
bind the selected raw signed history, external governance, RFC 3161 proofs and
complete expected decisions. A named local test adapter applies query changes
during verified publication callbacks; the vector contains no executable callback
code or additional policy authority. Earlier/later knowledge controls, restored
query values, nested byte and reference changes, accessor rejection and fractional
publication boundaries are evaluated against the same fixed signed material.

For an encoding explicitly selected at the operation time, known key compromise
also applies to an equivalent public-key encoding. The earliest applicable
incident remains effective after the original encoding is withdrawn or a later
snapshot reports GOOD. Original SPKI-derived KeyIDs, signed status bindings,
per-encoding rollback/conflict checks and positive appointments stay separate.
An unselected encoding remains missing; a certificate-only appointment requires
the exact certificate and does not select a bare SPKI query. A later appointment
cannot backdate admission. The retained resolver reports the same
`INVALID/AUTHORITY_REVOKED` decision for either selected encoding.

The [fixed retained authority vectors](../reference/vectors/retained-authority-key-incidents.json)
contain synthetic signed manifests and RFC 3161 publication proofs covering
both encoding directions, incident-publication and compromise boundaries,
withdrawal, later GOOD snapshots, admission timing, unrelated keys and incident
ordering. The EC encodings exercise a generic selected-policy resolver; they do
not widen governed document algorithm profiles.

`verifyPublication` is synchronous. It must return a non-Proxy plain or
null-prototype object with its own `overall` data property. A `VALID` decision
also requires an own finite numeric `poeUpperBound` data property; fractional
seconds are preserved. Missing or malformed decisions, accessors, inherited
verdicts, proxies, promises and thenables produce
`INDETERMINATE/HISTORY_PUBLICATION_PROOF_REQUIRED`. Explicit `INVALID`,
`INDETERMINATE` and `UNSUPPORTED` decisions retain their classification and own
string reason. An exception cannot supply a positive authority verdict. Thrown
values are normalized without executing accessors or Proxy traps: only own data
fields can supply a known negative classification and a string error code.
Missing or unsafe fields fall back to `INVALID` and `HISTORY_INVALID` respectively.
The same entry authenticator is used for in-memory resolution and durable admission and
replay; result validation does not replace proof authentication, root signatures
or manifest-chain checks. Ordinary native promise rejections are observed, but
custom `constructor` or `Symbol.species` behavior can prevent that observation.
Callbacks must handle their own asynchronous failures.

`ArchivePublicationStore` atomically persists the ERS head, original data
commitment, and retained governance/custodian history in one journal transaction.
Its required synchronous publication validator must authenticate the ERS, bind it
to the selected document and data commitment, and admit the selected custodian
through the retained history. Compare-and-swap rejects competing archive heads.
The validator must return a non-Proxy plain or null-prototype object with its own
`overall` data property equal to `VALID`. Proxies, promises, thenables, inherited
or accessor verdicts, and malformed results cannot authorize publication. The
store observes rejections from ordinary native promises, but custom `constructor`
or `Symbol.species` behavior can prevent attaching that observer. Callbacks must
handle their own asynchronous failures; observer exceptions still result in
`ARCHIVE_PUBLICATION_VALIDATION` without writing a publication. Rejected validation
leaves the committed archive head intact. Identical completed publications are idempotent
without calling the validator again. A process killed after the write
but before commit cannot publish only part of a renewal or custody transition.

`ArchiveRenewalCoordinator` reserves the exact nonce-bearing timestamp request
before contacting the TSA. An uncertain response remains uncertain across
restart. Reconciliation authenticates the retained token, request imprint, policy,
nonce, TSA role and status, and protection deadline before atomically publishing
the assembled ERS and completing the operation. It never silently repeats an
uncertain external execution. Completed result lookup does not renew authority or
create a new timestamp.

Reconciliation also requires the saved request to match the existing operation
reservation's digest before token verification or recovery callbacks. A saved
request without a reservation cannot create one during recovery. The same request
snapshot is checked again before publication and before completing the operation
in the publication transaction. Changes made by a publication validator roll back
with that transaction. A changed deadline, nonce-bearing request or archive
linkage cannot replace the originally reserved values; restoring the original
request still permits reconciliation of its retained token. These consistency
checks do not authenticate a database whose request and reservation records have
both been replaced outside the journal's trust boundary.

The synchronous `buildPublication` callback returns a CBOR-encodable publication.
The coordinator takes a detached canonical snapshot before checking its archive ID
and predecessor commitment. Those checks and the publication store therefore use
the same value, even when the callback returns changing accessors or retains
mutable references. A snapshot with a different archive ID or predecessor is
rejected before publication; the retained token remains available for reconciliation.

The synchronous authority resolver used by `requireAuthority` must return a
non-Proxy plain or null-prototype object with its own `overall` data property.
Malformed decisions, inherited or accessor verdicts, proxies, promises and
thenables produce `INDETERMINATE/AUTHORITY_DECISION_MISSING`. Explicit `INVALID`,
`INDETERMINATE` and `UNSUPPORTED` decisions retain their classification and own
string reason; an absent or unsafe reason uses `AUTHORITY_DECISION_MISSING`.
Verdicts and negative reason metadata are read without invoking accessors or
Proxy traps. Ordinary native promise rejections are observed, but custom
`constructor` or `Symbol.species` behavior can prevent that observation; the
resolver remains responsible for its asynchronous failures. Synchronous resolver
exceptions propagate unchanged. These result checks do not authenticate policy
inputs or replace the selected authority's role, scope and status evaluation.

The SDK evaluation wrapper applies the same guard before examining or normalizing
a returned decision. It additionally requires an admitted decision to have its own
nonempty string `reason` data property. An absent, empty, non-string or accessor
reason changes an otherwise `VALID` decision to
`INDETERMINATE/AUTHORITY_DECISION_MISSING`. Negative decisions keep their outcome
and use `AUTHORITY_DECISION_MISSING` for absent, empty or unsafe reasons. Accepted
objects retain their identity and metadata; unrelated metadata is not copied or
read during normalization. Ordinary rejected promises reach the shared rejection
observer before a missing decision is returned.

A rejected renewal decision leaves the old archive head and uncertain operation
intact, so the original token can be reconciled under a valid authority decision
without repeating the TSA request.

The process recovery tests terminate the coordinator after receiving a real
RFC 3161 token over loopback HTTP, inside the publication transaction, and after
commit. Restarted coordinators preserve an uncertain operation and the old archive
head until the original token is authenticated, or recover the already committed
publication and result together. Recovery after the protection deadline uses a
token issued before that deadline; it makes no additional TSA request. These
checks use synthetic authority appointments, clocks and local SQLite storage.
The combined recovery case also changes a saved request after process death,
rejects it against the original reservation, and restores the original request.
A fresh process then reconciles the retained HTTP timestamp into one detached
ERS publication snapshot after the deadline, with no additional TSA request.
Another process recovers the exact committed result and archive revision.

The reference tests use real signatures, timestamp tokens and ERS, with synthetic
governance, clocks, lifetimes and software custody. The long-lived raw-key
appointments in the complete CMS/native-mdoc fixtures are explicit external test
policy; they are not inferred from expired certificates. Tests demonstrate
protocol behavior, including missing coverage and late compromise, but do not
provide operational clock assurance, an independent implementation, or an external
security assessment. Formal archival service and ETSI conformance claims require
the separately selected standards, algorithm allowances and operational evidence.
