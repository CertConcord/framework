# Retained authority history and document preservation

`verifyPreservedDocument` reports three decisions: preservation integrity,
historical authorization under a selected earlier knowledge time, and current
admissibility under later retained knowledge. Every non-VALID decision prevents
overall acceptance. A later discovered compromise can invalidate current
admissibility while the historical result and the integrity of the preserved
original bytes remain valid. Fresh status cannot change the signed operation.

Historical acceptance requires the authenticated first ERS proof of the exact
complete `originalBytes` at an upper bound P no later than
`historicalKnowledgeTime` H. A missing or later proof leaves historical byte
visibility INDETERMINATE, while independently invalid original mathematics remain
INVALID. Signed `publishedAt` and `iat` fields alone cannot establish that the
status bytes were available by H. The earlier document timestamp excludes those
refreshable leaves. This selected interface has no separate per-status publication
proof input; a later full-package archive cannot backfill an earlier history view,
even when an application holds additional evidence outside this interface.

Original status authority is checked at its claimed publication time and at P,
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

`ArchivePublicationStore` atomically persists the ERS head, original data
commitment, and retained governance/custodian history in one journal transaction.
Its required synchronous publication validator must authenticate the ERS, bind it
to the selected document and data commitment, and admit the selected custodian
through the retained history. Compare-and-swap rejects competing archive heads.
Identical completed publications are idempotent. A process killed after the write
but before commit cannot publish only part of a renewal or custody transition.

`ArchiveRenewalCoordinator` reserves the exact nonce-bearing timestamp request
before contacting the TSA. An uncertain response remains uncertain across
restart. Reconciliation authenticates the retained token, request imprint, policy,
nonce, TSA role and status, and protection deadline before atomically publishing
the assembled ERS and completing the operation. It never silently repeats an
uncertain external execution. Completed result lookup does not renew authority or
create a new timestamp.

The reference tests use real signatures, timestamp tokens and ERS, with synthetic
governance, clocks, lifetimes and software custody. The long-lived raw-key
appointments in the complete CMS/native-mdoc fixtures are explicit external test
policy; they are not inferred from expired certificates. Tests demonstrate
protocol behavior, including missing coverage and late compromise, but do not
provide operational clock assurance, an independent implementation, or an external
security assessment. Formal archival service and ETSI conformance claims require
the separately selected standards, algorithm allowances and operational evidence.
