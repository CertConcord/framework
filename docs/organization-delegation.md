# Organization delegation application

The selected `certconcord-organization-delegation-v1` application authorizes one exact CMS organization seal through a bounded delegation path and independent ordinary WebAuthn approvals. It uses the existing organization-seal credential, Signing Intent Manifest, activation, permit, execution gateway and receipt. The application policy and evidence plan explicitly select the additional delegation and approval checks.

This is a draft reference profile. Its `CURRENT_STATE_ONLY` decision requires the operation and all relevant permissions to remain admissible at the verifier's actual current knowledge time. Retained evidence can be inspected independently, but this selection does not establish historical authorization through proof of existence.

## Selection and trusted context

`SignaturePolicy.organizationDelegation` selects the application profile, current-state mode, one configured identity namespace and a minimum of two to sixteen approvers. The policy requires `WORKLOAD` activation, the existing execution-binding profile, `requireTrustedTime: false`, and no `documentEvidence` field. The credential and SIM retain `CERTCONCORD-ORG-SEAL-v1`. The selected plan is `certconcord-ecp-cms-organization-delegation-v1`; the older direct organization plan and schema-1 authorization retain their own semantics.

The application constructor captures a synchronous current-context source, exact policy, organization, namespace, workload identity, seal credential and configured control-authority certificates. The operation message cannot choose trust roots, authority roles, a different workload, policy, time or resolver. A new configuration requires a new instance. Inputs, callback queries and results are detached before use. Native Promise and thenable results cannot authorize a synchronous boundary; rejected native Promises are observed without treating them as decisions.

Each authority has an externally configured role and exact purpose scope. Root grant issuance, intermediate grant issuance, final operation authorization, approver registration and status publication are different purposes. A terminal authority needs final-authorization permission; it does not need permission to delegate further. Permit, receipt and execution-binding authorities also require the selected application scope. Credential issuance and registration retain their original credential scope and signed binding.

The current-context source supplies current workload state, authenticated status knowledge and finite key, signature-algorithm and hash cutoffs. A certificate pin alone grants no role. Missing current knowledge cannot produce a positive decision. The source's completeness and clock assurance are explicit application trust assumptions; local state prevents ordinary rollback after an authenticated observation but does not authenticate a malicious replacement of the entire database.

### Context configuration

`readContext()` returns a plain bounded object with the following fields. Times are nonnegative safe-integer UNIX seconds, `id32` values are exact 32-byte buffers, and key IDs are SHA-512 hashes of validated original SubjectPublicKeyInfo bytes. The context is a constructor dependency, not a field in the public operation request or evidence package.

| Field                             | Required value                                                                                                   |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `knowledgeTime`                   | Actual current time `K`, at or above the durable domain watermark                                                |
| `trustDomainID`, `organizationID` | Fixed `id32` values                                                                                              |
| `issuerID`, `identityNamespace`   | Fixed organization issuer identifier and nonempty ASCII namespace of at most 128 bytes                           |
| `operator`                        | `{type: 'WORKLOAD', id, active, knownAt, validFrom, validUntil}` with fixed type and ID                          |
| `policy`                          | The exact selected `SignaturePolicy`, including its committed organization-delegation selection                  |
| `authorityResolver`               | One fixed synchronous shared role/lifecycle resolver                                                             |
| `controlTrust`                    | At most 64 original certificate and exact-purpose mappings described below                                       |
| `credentialTrust`                 | The fixed organization-seal credential configuration described below                                             |
| `statusMaterial`                  | At most 64 original `{cms, issuerCertificate}` status members                                                    |
| `keyDeadlines`                    | Own-data record from lowercase 128-character hexadecimal key ID to finite cutoff                                 |
| `algorithmDeadlines`              | Own-data record from canonical signature-algorithm OID to finite cutoff                                          |
| `hashDeadlines`                   | Own-data record for each used SHA-256 or SHA-512 OID to finite cutoff                                            |
| `executionCurrent`                | `null` or `{binding, observedAt}` containing the latest original signed execution binding and `observedAt === K` |

Each used key, signature algorithm and hash requires `K < cutoff`. Missing entries are unavailable knowledge; they do not imply an infinite lifetime. Hash OIDs are `2.16.840.1.101.3.4.2.1` for SHA-256 and `2.16.840.1.101.3.4.2.3` for SHA-512. ES256 approvals use signature OID `1.2.840.10045.4.3.2`. Certificate validity, scoped authority, current status and workload lifetime remain additional checks.

A `controlTrust` entry has exactly `{certificate, organizationID, identityNamespace, issuerID, purpose, objectTypes}`. The identity fields must equal the fixed configuration. `objectTypes` is a unique nonempty subset of `GRANT`, `APPROVER_REGISTRATION` and `FINAL_AUTHORIZATION` for the status purpose, and is empty for every other purpose. The tuple of original certificate hash, purpose and object-type set must be unique. Reusing one certificate for different roles requires separate explicit mappings.

All control queries use `{trustDomainID, profileID: 'certconcord-organization-delegation-v1', issuerID, representation: 'X509', purpose}` with the fixed organization issuer ID. The purpose determines the required role:

| Use                            | Purpose                                     | Role                          |
| ------------------------------ | ------------------------------------------- | ----------------------------- |
| First grant                    | `ORGANIZATION_DELEGATION_ROOT`              | `ORGANIZATION_AUTHORITY`      |
| Actual child-grant issuer      | `ORGANIZATION_DELEGATION_ISSUE`             | `ORGANIZATION_AUTHORITY`      |
| Final authorization            | `ORGANIZATION_FINAL_AUTHORIZATION`          | `ORGANIZATION_AUTHORITY`      |
| Approver registration          | `ORGANIZATION_APPROVER_REGISTRATION`        | `REGISTRATION_AUTHORITY`      |
| Delegation status              | `ORGANIZATION_DELEGATION_STATUS`            | `STATUS_AUTHORITY`            |
| Operation permit               | `ORGANIZATION_DELEGATION_PERMIT`            | `PERMIT_AUTHORITY`            |
| Execution receipt              | `ORGANIZATION_DELEGATION_RECEIPT`           | `RECEIPT_AUTHORITY`           |
| Execution binding              | `ORGANIZATION_DELEGATION_EXECUTION_BINDING` | `EXECUTION_BINDING_AUTHORITY` |
| Exact document-seal credential | `ORGANIZATION_SEAL`                         | `DOCUMENT_SEAL`               |

All used roles must remain admitted at `K`. Status authority is checked both at authenticated publication time and at `K`, with current knowledge `K` in both queries. Future publication supplies no current permission or durable observation.

`credentialTrust` has exactly `{certificate, registrationAuthorization, issuerCertificate, raCertificate, statusCertificate, issuanceScope, currentCertificateStatus}`. These are original X509 or CMS bytes. `issuanceScope` is the existing `{trustDomainID, issuerID, issuerKeyID, representation: 'X509'}` tuple, with the issuer key derived from the exact configured issuer certificate. Only `currentCertificateStatus`, a CMS buffer or `null`, may refresh without changing the credential identity. Credential issuer, registration and status roles retain the original `CERTCONCORD-ORG-SEAL-v1` scope, with no invented purpose field. Original registration authorization is checked at issuance; its short issuance window is not required to remain open for every later seal operation. Current role, key and certificate admission is required separately.

Later contexts may refresh current time, workload state, signed status, authenticated resolver state, finite cutoffs and the latest execution binding. They cannot replace the pinned policy, resolver function, organization, operator identity, credential or control certificates. The latest execution binding must independently authenticate its domain, provider, document key, policy, epoch, lifetime and status. Its exact original hash and epoch must match the operation's committed binding at final verification. A current observation is a trust assumption about the source's completeness, not an independent cryptographic proof that no newer binding exists.

Construction validates the complete configuration and local control-key/certificate matches. A well-formed expired or inactive context still permits construction for record retrieval. Every operation that can authorize, execute or release output performs its own fresh admission checks.

## One attenuating path

A path contains one to eight original CMS grants, ordered from a configured root to the terminal authorization signer. Each `OrganizationDelegationGrant` binds its domain, organization, identity namespace, grant ID, issuer key, designated delegate certificate tuple, finite entitlements and validity interval. A child commits to SHA-512 of the complete original parent CMS envelope.

Every child must preserve the operation purpose and selected container/adapter. Its operator IDs, seal certificate tuples, policy hashes, audiences, origins, RP IDs and eligible person IDs must be subsets of the parent's sets. Its interval must fit within the parent's interval, its remaining delegation count must decrease, and its minimum approval count must not decrease. The effective approval count is the greatest minimum required by the path and fixed policy.

The next-hop delegate identity and the permitted workload or document key are separate fields. Every actual issuer and final signer receives independent current lifecycle and purpose checks. Repeated grant IDs, envelopes or delegation keys, cycles, permission amplification and substitutions of the original parent certificate or envelope are rejected. The application uses the supplied path; it does not search alternate paths or combine their permissions.

## Independent people and exact challenges

Each approver has an original CMS `OrganizationApproverRegistration` from an independently admitted registration authority. It binds one organization and identity namespace to the person ID, credential ID, exact P-256 SPKI, approval purpose, RP, origins, backup eligibility, initial counter and finite lifetime. The roster contains exactly the effective required number of people, with distinct person IDs, credential IDs and public keys. Multiple registrations cannot turn one person or key into several approvals.

Preparation freezes the document's CMS signing input, SIM, activation, policy, original path, selected registrations, origins, operation ID and fresh server/person nonces. It commits these values in `OrganizationApprovalRequest` before any assertion exists. Each challenge is the existing COMMON hash of `OrganizationApprovalChallenge` and the request hash, person ID and credential-ID hash. The eventual approval-set hash is absent from that challenge, so there is no circular commitment.

The retained approval stores original `clientDataJSON`, authenticator data, signature and credential-ID bytes. Verification checks ES256 mathematics, exact challenge, RP hash, origin, UP, UV, credential and backup flag. The service consumes each one-use nonce and advances its durable credential counter atomically with storing the assertion. Both-zero counters still require a fresh nonce. Later checks reverify the accepted assertion and exact stored commitment; they do not attempt to consume it again using the already advanced counter.

The final `OrganizationAuthorization` uses schema 2. It binds the exact request, activation, policy, workload, seal certificate and the two original-evidence leaf IDs. The unchanged permit commits the complete original authorization CMS. A positive final authorization alone cannot replace verification of the original grant path and every selected assertion and registration.

## Current time and status

Preparation, approval, authorization, dispatch, completion, final output release and independent verification use the actual current knowledge time supplied by the fixed source. The time must remain at or above the durable high-water mark. Each applicable SIM, activation, request, challenge, authorization and permit window must contain that time. Authorization and permit lifetimes are at most thirty seconds and cannot exceed the request or activation expiry; the request and activation are bounded to one hundred twenty seconds.

`OrganizationDelegationStatus` authenticates one immutable grant, registration or final authorization through its object ID, complete original CMS hash and subject key. Every selected object needs a current head. Applicable revocation dominates stale, unavailable or unselected evidence. An older GOOD head cannot replace a higher authenticated epoch or clear an applicable terminal revocation. Different authenticated bodies at the same epoch conflict; another valid signature over the same body is not a new epoch.

A statement published after current knowledge time cannot advance the current epoch or incident watermark. Key-compromise observations require the verified original target binding or its already authenticated journal record. An unbound off-path statement cannot assign a compromise to a key. Independently authenticated current key cutoffs may supply other current incidents. Known compromise follows the exact key across new object IDs.

Status material can be refreshed without rewriting the immutable path and approval leaves. An old receipt time does not restore an expired current permission. After the short operation windows expire, retained verification returns a non-VALID current-admission result; it makes no claim that the historical signature was invalid when produced.

## Execution and recovery

`OrganizationDelegationApplication` exposes `prepare`, `approve`, `authorize`, `execute`, `reconcile` and `getOperationResult`. Preparation and approval record intermediate state. Authorization produces exact committed control bytes. Execution submits only the retained permit, SIM and CMS signing input to the existing gateway; callers cannot replace them when dispatching.

The constructor takes `{journal, readContext, authorization, permit, status, execution}`. Each of `authorization`, `permit` and `status` contains its exact `certificate` and local synchronous `privateKey`. `execution` contains `{binding, bindingCertificate, receiptCertificate, receiptKey, backend, keyRef}` for the existing governed message-signing backend. The gateway is private and created only after complete current admission. A caller cannot supply a prebuilt gateway or install a replacement binding through this application.

This selection uses one shared synchronous SQLite `Journal` for the application and its private gateway. The existing PostgreSQL adapter is outside this selection's current storage support. SQLite commit and revision checks do not establish protection against malicious replacement of the database.

| Method               | Input                                                                                 | Positive result scope                                                                   |
| -------------------- | ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `prepare`            | `{operationID, document, sim, delegationPath, approverRegistrations}`                 | `PREPARED`, `PREPARATION_ONLY`; exact request, activation and person challenges         |
| `approve`            | `{operationID, personID, credentialID, clientDataJSON, authenticatorData, signature}` | `APPROVAL_RECORDED`, `APPROVAL_RECORD_ONLY`; one committed approval and count           |
| `authorize`          | `{operationID}`                                                                       | Committed final authorization, initial GOOD status, permit and original-evidence leaves |
| `execute`            | `{operationID}`                                                                       | Asynchronous governed execution and committed CMS/package after fresh final admission   |
| `reconcile`          | `{operationID, signature}`                                                            | Asynchronous reconciliation of an exact existing candidate; no backend signing call     |
| `getOperationResult` | `{operationID}`                                                                       | `RETRIEVED`, `NOT_REEVALUATED`; scoped committed record, or `null`                      |

`prepare`, `approve`, `authorize` and retrieval are synchronous. Missing approvals leave authorization `INDETERMINATE` and pending, with no control output. None of these public methods accepts a policy, trust, resolver or time override. Record lookup is scoped to the configured application and organization before any gateway record is consulted.

After the final asynchronous authorization step, the gateway invokes a constructor-fixed synchronous current-admission check. Its exact request, binding, permit and key commitments, current time and journal revision guards must match before a callback-free transaction reserves the operation. The same boundary runs after signing and before completion, including the completed-result branch. The application performs another current check after awaiting the gateway and before storing or releasing the final CMS and package.

The existing gateway owns the document-key reservation, lock and dispatch. A failure before dispatch performs no document private operation. An uncertain dispatch or denied completion releases no new signature or receipt and retains the unresolved operation and key lock. Reconciliation uses an existing exact candidate signature and never invokes signing again. If the gateway has already committed completion but current admission fails before final output, the completed record remains intact and the output is withheld.

The two mandatory guards refer to existing journal rows: the operation record revision and the domain-wide current-state revision. The gateway independently derives their IDs from `OrganizationOperation` and `OrganizationCurrentState` COMMON hashes. It rejects arbitrary namespaces, absent rows, duplicate guards and stale revisions. Status, target, incident, execution-head and time observations change the current-state revision atomically. A changed revision requires fresh evaluation; an older decision cannot be paired with a newer revision to authorize dispatch.

The first selection signs authorization, initial authorization status and permit with local synchronous control keys inside one journal transaction after all external decisions. Failed commits release none of those new bytes. This selection has no external HSM control-signing exactly-once claim. Public CMS/package assembly can be recovered from an already committed signature and receipt without another private operation, subject to the current checks required for release.

`getOperationResult` retrieves committed records with `RETRIEVED` and `NOT_REEVALUATED` semantics. It supplies no fresh authorization verdict. Exact retries do not renew nonces or permit lifetimes; changed immutable input under an existing operation ID conflicts. Expiry or revocation can leave an unresolved locked operation, with no automatic unlock, re-sign or historical override.

After definite gateway completion, a later admission failure reports `OUTPUT_WITHHELD` with `executionStatus: 'COMPLETED'`. A package persistence failure reports `OUTPUT_PENDING`, `INDETERMINATE` and `ORG_PACKAGE_PERSISTENCE_UNAVAILABLE`, also preserving completed execution. Neither result releases the new CMS or package. `UNKNOWN_EXECUTION` is reserved for an uncertain document private-operation outcome; it does not overwrite a known completed result. `effectMayHaveOccurred` describes the document backend, not the local control-signing operations.

## Independent evidence and limits

The schema-2 flat package retains the existing document, credential, registration, SIM, policy, permit, receipt, certificate-status, CMS and execution-binding leaves. It adds schema-2 `OrganizationAuthorization`, immutable `OrganizationDelegationPath` and `OrganizationApprovalSet` collections, and mutable `OrganizationDelegationStatus` material. Every type and leaf ID is unique and referenced exactly once. There is no extra activation or nested verification-plan leaf.

`OrganizationDelegationVerifier` accepts exact serialized deterministic-CBOR package bytes and a constructor-bound current context and journal. It independently checks available signature mathematics, credential and document bindings, execution evidence, every path member, registration, raw assertion, final authorization, status and leaf commitment. Known invalid evidence takes precedence over recognized unsupported features and unavailable evidence. Every non-VALID outcome prevents current acceptance.

This plan requires the dedicated current-state verifier. The generic verifier SDK does not advertise it as a supported plan, and generic CMS package verification reports `UNSUPPORTED` with `ORG_CURRENT_VERIFIER_REQUIRED`. The package cannot fall back to an older execution or direct-authorization plan.

The selected bounds include eight grants, sixteen people, thirty-two members per entitlement set, sixty-four status statements, a sixteen-MiB document and sixty-four-MiB package. Original control, certificate, assertion and collection sizes also have separate limits checked before expensive member verification. No extra member is silently discarded to find an acceptable quorum.

| Material                                             | Selected maximum                     |
| ---------------------------------------------------- | ------------------------------------ |
| Original certificate                                 | 65,536 bytes                         |
| Original control CMS; registration CMS               | 131,072 bytes; 65,536 bytes          |
| Credential ID; P-256 SPKI                            | 1,024 bytes; 2,048 bytes             |
| Client JSON; authenticator data; assertion signature | 8,192 bytes; 65,536 bytes; 128 bytes |
| Origins per registration                             | 8                                    |
| Path; approval; status collections                   | 2 MiB; 4 MiB; 8 MiB                  |
| Combined new organization material                   | 12 MiB                               |
| Flat package leaves                                  | 128                                  |
| Grant or registration lifetime                       | 30 days                              |
| Status freshness interval                            | 300 seconds                          |

Sets use deterministic-CBOR byte order, grants preserve their semantic path order, and the roster uses person-ID order. Status statements use ascending ASCII object type, object-ID bytes, epoch and then `H('OrganizationDelegationStatus', body)` bytes. Malformed or contradictory evidence is `INVALID`; a well-formed capability beyond the selected bounds is `UNSUPPORTED`; required unavailable evidence is `INDETERMINATE`. Independently authenticated status and execution observations are retained even if another check denies the operation. Failure to persist required anti-rollback knowledge prevents acceptance. Retained assertion verification uses each signed registration's original counter and reports `SIGNED_REGISTRATION_ONLY`; it does not establish the service's global counter history or actual nonce consumption.

The identity source establishes the organizational person binding. Ordinary WebAuthn does not establish trusted display or physical separation beyond that source. The gateway's governed backend and durable-storage assumptions remain explicit. Organizational mdoc, person operators, arbitrary delegation graphs, external asynchronous control signers, historical delegation proof and independent production assurance require separate selections and evidence.

The complete package discloses its organization and identity namespace, approver person and credential IDs, public keys, origins, grant path and status evidence to its recipient. Stable person, credential, authority and document-key identifiers can link operations. This selection supplies no selective-disclosure or anonymity mechanism. Distribution and record-access policy must account for that original evidence; replacing it with an aggregate approval count would remove required verification inputs. ML-DSA control or document signatures do not upgrade the ES256 approvals to post-quantum authentication.
