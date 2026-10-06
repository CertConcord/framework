# CertConcord Execution Binding Profile — Draft 02

> Candidate binding for CertConcord draft 02. This is a working draft, not a final standard. Its requirements apply only when this binding is selected. The [draft architecture](../architecture.md) defines framework scope; the [profile catalog](../profiles.md) records applicability. The draft 02 namespace and wire domain identify experimental formats. Object schema numbers describe field layouts and do not indicate a stable edition.

Status: draft 02. Wire identifier: `certconcord-execution-binding-draft-02`. Normative language: English. This is a CertConcord proposal with an executable broker profile. COMMON-draft-02, DTI-draft-02, DSCP-draft-02 and SEP-draft-02 apply. Adoption by an external standards body is a separate event.

## 1. Problem and scope

An authorization service can approve exact bytes while a subsequent provider call uses a mutable buffer, a different provider configuration or an expired permit. A valid signature and an earlier authorization do not establish which execution boundary applied the authorization. A lost response creates a second problem: retrying a key call may create another signature even when a database transaction is atomic.

EBP connects an admitted execution boundary to the existing SIM, ActivationContext, OperationPermit and ECP. The document still has its normal CMS or COSE signature. An additional governed ExecutionBinding identifies the provider, document key, control authorities, policy, admission epoch and lease. It is not a new document-signature algorithm or a replacement for RA/CA qualification.

Draft 02 implements `BROKER_ENFORCED`. The broker controls exclusive access to its backend credentials, performs authorization checks and retains durable state. Its admission authority evaluates that deployment boundary. A signed admission is an accountable assertion by that authority; it does not cryptographically demonstrate hardware behavior, a trusted display, or absence of another key-use channel. KAL and SAL retain COMMON's independent requirements.

The implemented profile supports separate ML-DSA document keys and explicitly admitted P-256 document keys, represented through CMS/MTC/X.509 or a signer mdoc. It does not replace PSCP's parent assertion and raw-signing evidence. Selecting both PSCP and this draft's broker evidence plan is rejected until an explicit composition specifies and verifies both execution boundaries. Ordinary WebAuthn activation remains usable with EBP.

## 2. Authority and policy selection

The trust domain admits the broker through a separately configured binding-authority certificate. This authority is distinct in role from the credential issuer, RA, activation authority and execution-receipt authority. A deployment MAY assign multiple roles to one key only under an explicit governed role policy. Evidence MUST NOT choose its own trusted authority.

The SignaturePolicy contains this critical selection:

```json
{
  "executionBinding": {
    "profile": "certconcord-execution-binding-draft-02",
    "providerID": "example-broker",
    "maxLeaseSeconds": 300
  }
}
```

`providerID` is 1–128 ASCII letters, digits, dot, underscore, colon or hyphen, beginning with a letter or digit. `maxLeaseSeconds` is an integer from 1 through 86400. Unknown selection fields, revisions or enforcement modes fail. A missing property means the policy has not selected EBP; null is not an alias for absence.

Policy is frozen before its hash is used in a binding. Policy does not include the resulting binding hash, avoiding a dependency cycle. Clients and verifiers MUST negotiate the evidence-plan capability before accepting this policy. A reader that does not implement the draft MUST NOT install an EBP policy as though it were a legacy policy.

## 3. ExecutionBinding

The binding is deterministic RRA CBOR inside CMS `D("ExecutionBinding", binding)`, signed by the configured binding authority. The complete envelope is at most 65536 bytes. Its exact bytes are retained.

| Field                     | Meaning                                                                  |
| ------------------------- | ------------------------------------------------------------------------ |
| schemaVersion, profile    | `1`, `certconcord-execution-binding-draft-02`                                    |
| trustDomainID             | Governing 32-byte domain                                                 |
| providerID                | Selected provider identity                                               |
| epoch                     | Positive integer, monotonically increasing per provider and document key |
| status                    | ACTIVE, SUSPENDED or REVOKED                                             |
| keyID                     | SHA-512 of the admitted document SPKI                                    |
| permitKeyID, receiptKeyID | Exact activation and receipt SPKI hashes                                 |
| policyHash                | H("SignaturePolicy", policy)                                             |
| audience                  | Exact audience required by the activation policy                         |
| enforcement               | BROKER_ENFORCED                                                          |
| issuedAt, expiresAt       | UTC whole seconds; positive lifetime no greater than the policy limit    |

There are no other fields in this revision. Key and policy hashes are 64 bytes. The binding cannot authorize another document key, trust domain, policy or control signer. Backend aliases remain private configuration; successful resolution must yield the bound public key. The backend accepts original message bytes. A digest-only backend cannot be substituted for a pure-message algorithm.

The broker durably maintains the highest accepted epoch and exact envelope digest. A lower epoch is rejected. A different envelope at the same epoch is a fork, including a second signature encoding over the same payload. Retransmission therefore reuses the original envelope. REVOKED is terminal for that provider/key pair. SUSPENDED can return to ACTIVE only through a higher, separately signed epoch. Lease expiry does not erase a watermark or allow reuse of an old epoch.

Restoring a database snapshot can restore consumed operations or old epochs. Deployment MUST protect these records from rollback using its admitted persistence and recovery controls; signed objects alone do not prevent storage rollback. All active replicas serving the same provider/key authority MUST share the authoritative operation and epoch state.

## 4. Acyclic request commitment

The dependency order is:

```text
policy -> provider admission
document -> SIM -> exact container input -> ActivationContext -> authorization -> permit
provider admission + SIM + permit + exact input -> execution request
durable reservation -> key operation -> receipt -> evidence package
```

The request contains the original permit envelope, original TBS bytes and SIM. TBS is nonempty and at most 16 MiB; the permit is at most 1 MiB. The reference gateway copies these inputs synchronously before its first asynchronous operation. Callback and backend arguments receive separate copies. Checking an input and later signing a caller-owned mutable buffer is prohibited.

The exact request commitment is:

```text
H("IntentExecutionRequest", {
  schemaVersion: 1,
  profile: "certconcord-execution-binding-draft-02",
  bindingHash: SHA-512(original ExecutionBinding CMS),
  permitHash: SHA-512(original OperationPermit CMS),
  activationHash: H("ActivationContext", activation),
  simHash: H("SIM", sim),
  tbsHash: SHA-512(original provider message),
  keyID: admitted document KeyID
})
```

No field includes the final signature or receipt. The container input remains the exact CMS signed-attributes SET or COSE Signature1 structure required by the selected adapter. Document content and display metadata are not interchangeable with that input.

## 5. Admission and dispatch

Before dispatch the broker MUST:

1. Verify the binding signature against its external pin, exact policy, control keys, ACTIVE state, lease and durable epoch.
2. Resolve the backend key and verify exact KeyID and message semantics.
3. Verify the signed permit and all ActivationContext bindings. Permit lifetime is positive and at most 30 seconds, contained in the activation lifetime.
4. Bind SIM to the same domain, transaction, certificate identifiers, key, policy, origin, lifetime and activation hash. Profile and origin must be allowed by the frozen policy.
5. Apply the deployment's current subject, key, certificate, credential and provider authority checks. The authorizer MUST return boolean true. False, absent values, objects and exceptions deny the operation. An authorization callback is not a substitute for cryptographic checks or an authoritative identity/credential registry.
6. Recheck times and the current admission epoch after asynchronous authorization, inside the reservation transaction immediately before dispatch.

The existing DSCP authorizer remains responsible for the certified subject/key/purpose relationship, exact container/SIM relationship and verified user authorization. EBP cannot turn a signed permit from an unauthorized service into authority. Implementations MUST configure the activation pin and authorization callback from governed policy.

## 6. Persistent execution state

The operation identifier is the ActivationContext's random OperationID. Reservation atomically stores its request commitment, exact inputs, original binding, dispatch time and a lock for the document KeyID. A different request under the same OperationID is an idempotency conflict. Repeating a still-authorized completed request returns the original signature, receipt and binding evidence. After authorization expiry, the governed result-retrieval interface can return the original result without performing a new execution or changing its recorded authority. Result access has its own caller authentication and disclosure policy. DISPATCHED or UNKNOWN_EXECUTION never triggers a second key call.

The key lock survives binding renewal and process restart. Another operation on that key is rejected while an unresolved reservation exists. Failed reservation of another operation rolls back its operation row. The reference SQLite and PostgreSQL journal contracts implement the required transaction and compare-and-swap primitives.

After a provider response, the broker verifies the signature over its retained input, rechecks current authorization, times and admission epoch, and atomically stores the result and clears the key lock. A clock earlier than the retained dispatch time is rejected. Revocation during an in-flight call can prevent release of an accepted result; it cannot undo a signature already produced inside a backend.

Timeout, lost response, invalid signature, authority change or failure after dispatch leaves UNKNOWN_EXECUTION and retains the lock. Cancellation of a network request is not proof that signing did not occur. Reconciliation verifies the original returned signature against the stored request and current authority without making another key call. The selected adapter requires authorization to remain valid at reconciliation; an expired permit does not gain a new lifetime. If no acceptable original result can be established, that key remains blocked for this execution path and must be handled by the governed retirement/replacement procedure. A local reset is not reconciliation.

This is an at-most-one-dispatch protocol under the admitted shared-state assumptions. It does not claim that a database alone provides exactly-once physical execution by an external device.

## 7. Receipt and verification

The ordinary signed ExecutionReceipt retains OperationID, activationHash, permitHash, KeyID, TBS hash, signature hash and executedAt. EBP adds:

- provider: the admitted providerID;
- dispatchedAt: retained reservation time;
- executionProfile: `certconcord-execution-binding-draft-02`;
- enforcement: `BROKER_ENFORCED`;
- executionBindingHash: SHA-512 of the original binding envelope;
- executionRequestHash: the section 4 commitment.

Unknown receipt fields fail this revision. The receipt key must match the binding. Dispatch is no earlier than permit issuance or binding issuance and no later than execution. Both dispatch and execution must occur within the binding lifetime; execution must also occur within the SIM, activation and permit lifetimes. A binding admitted after the declared dispatch cannot retroactively authorize that dispatch.

The additional evidence object is `ExecutionBindingEvidence`, encoded as `{binding: bstr}`. The mandatory plans are `certconcord-ecp-cms-execution-draft-02` and `certconcord-ecp-mdoc-execution-draft-02`. They include every object required by their existing CMS or mdoc plans plus this object. Removing it, selecting the legacy plan, or adding EBP evidence to a policy that does not select EBP is rejected.

The verifier receives `executionBindingCertificate` and synchronous `executionStatus(binding, {at, knowledgeTime})` from its governed configuration. The latter must affirm the applicable historical/current provider admission at the declared execution and knowledge times. A self-supplied GOOD flag in a package is not accepted. The verifier checks the whole original binding, permit, exact TBS, document signature, request commitment and receipt in addition to normal CA/MTC/mdoc, policy, status and evidence checks.

The result reports execution profile, enforcement boundary and epoch. Execution time remains an assertion by the receipt authority. Trusted timestamps, archive renewal and compromise-effective-time evaluation retain their existing DTI requirements. A broker admission does not raise a classical document signature to post-quantum assurance.

### 7.1 Correlation and status access

The admitted KeyID, providerID, control-key identifiers, binding digest and lease are visible to a party receiving the evidence. Reusing a binding links its executions even when different credential attributes are disclosed. The same document KeyID already permits linking signatures made with that key; rotating only a binding epoch does not remove that link. Relying-party metadata can add further correlations.

Separate keys and provider identities SHOULD be scoped to the intended trust domain and privacy context. Reducing cross-context linkage requires separately admitted keys and credentials, with corresponding issuance and operational cost. The request commitment and OperationID are not public transparency-log identifiers; deployments MUST NOT publish them together with identity-intake evidence merely to demonstrate execution.

The status callback SHOULD use authenticated, cacheable admission snapshots or batches with explicit freshness and compromise-effective-time rules. A direct per-signature lookup at the provider reveals verification activity and can defeat selective-disclosure goals. Historical acceptance MUST use authenticated history at both supplied times, including revocations known later. A short binding lease limits unattended future use; it neither revokes completed signatures nor erases historical linkability. Synthetic evidence-size measurements distinguish the binding envelope, receipt and whole package; deployments separately measure status-query visibility and key-rotation cost.

## 8. Platform proposals and credential integration

Sections 8.1 and 8.2 describe candidate improvements to experimental platform interfaces. Their behavior is a contribution surface; current upstream APIs are not treated as implementing it. The referenced interfaces are the [WebAuthn signing extension version 5 snapshot](https://github.com/YubicoLabs/webauthn-sign-extension/blob/812b911a2a5d737d2ebdb91ead8bfd78f8277710/index.bs), the separate [WebAuthn PR 2078](https://github.com/w3c/webauthn/pull/2078), and the [pinned WebKit Remote CryptoKeys explainer](https://github.com/WebKit/explainers/blob/6ce73fa4f91bbe7fb1990b6c1e7276c8dbd12609/remote-cryptokeys/README.md). Version 4 remains a historical compatibility input. The [upstream baseline](../../docs/upstream-baseline.md) identifies current sources; section 8.3 uses existing credential-transport extension points without proposing a replacement OpenID or ISO standard.

### 8.1 Experimental platform interface proposal

The independent [Protected Signing Operation Context proposal](../external/signing-context/draft.md) owns the proposed capability, input-binding and lost-result requirements for WebAuthn signing and Remote CryptoKeys. Its source snapshots and open questions are independent of the framework's permit and receipt objects.

The current broker remains an application-level prototype. It does not establish that an authenticator or browser implements the proposal. The selected raw-signing adapters retain their declared preauthorization semantics; protected enforcement requires separately admitted implementation evidence.

### 8.3 Existing credential-transport integration

OpenID4VP transaction data or an Annex C extension may transport the same activation commitment and requested execution profile. The holder response qualifies the signer and binds the presentation transcript. A subsequent admitted key operation produces the actual document signature and execution receipt. Issuance, identity presentment and signature activation retain separate authority. Receipt fields do not alter a government mDL/photoID/PID or create signing permission on a credential that lacks it.

## 9. Reproduction and assessment

Run `node --test execution-binding.test.mjs`. Complete synthetic exchanges are available with `node demo.mjs --execution-binding --passkey`, `node foundation-demo.mjs --execution-binding --passkey`, and the latter with `--device-key`. These use ordinary WebAuthn activation fixtures and software document keys; they validate the broker protocol and evidence composition.

`node fuzz/run.mjs containers 60` mutates signed admissions, permits, receipts and exact input bindings using a network-free synthetic execution fixture. [Published synthetic measurements](../../docs/benchmarks.md) include the binding's contribution to complete evidence size. These measurements preserve their environment and raw timing samples.

Required adversarial cases include explicit denial, missing authority, mutated inputs across awaits, wrong key/provider/policy, expiry before or after invocation, replay, concurrent key use, epoch rollback/fork, terminal revocation, restart with an unresolved operation, original-result reconciliation, forged receipts, changed binding evidence and plan downgrade. Independent deployment evaluation additionally tests exclusive backend access, persistent-state rollback, replica/failover behavior, user-verification evidence and any claimed protected display or hardware enforcement.
