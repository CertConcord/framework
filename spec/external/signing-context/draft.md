# Protected Signing Operation Context — draft 01

Status: focused amendment proposal for experimental platform APIs. No new browser API, authenticator capability, registered extension or upstream adoption is claimed.

## 1. Target and problem

The pinned WebAuthn signing proposals provide selected associated-key operations. The Remote CryptoKeys explainer obtains remote key handles and leaves platform access-control and consent details to implementations. Neither fact alone proves that a particular authorization was enforced inside a protected signing boundary.

The review targets are the operation input, capability description and result/error behavior of those proposals. The question is how an application can distinguish ordinary preauthorization from protected enforcement, and how it can recover a result without unintentionally authorizing another signing operation.

The existing CertConcord broker experiment supplies examples of exact-input binding and uncertain execution. Its full permits, receipts, authority hierarchy and evidence graph are not proposed as mandatory upstream objects.

## 2. Minimal proposed contract

An optional operation-context facility should bind the selected key identity, provider identity, algorithm, message-versus-prehash semantics, input commitment, requesting origin/audience, authorization reference and a unique operation identifier. The input must have an explicitly versioned bounded encoding and understood critical fields.

The context is not substituted for the actual message passed to a generic signing API. Existing sign operations retain their established input semantics. A transport can carry a context only when the selected provider advertises and authenticates the corresponding behavior.

Existing standard protocol fields should carry these values where they express the required contract. The proposal does not require a new signed envelope or an additional receipt signature. A protected authenticated output or an existing signed assertion may be sufficient, but the specification must identify exactly which fields are authenticated and by which authority.

## 3. Capability and evidence

Capability negotiation must distinguish:

- access to an exact admitted key;
- application-side preauthorization before calling a generic signer;
- provider-side verification and durable enforcement of an authorization;
- any separately evidenced user verification or protected display.

An RP-generated receipt after raw signing cannot establish authenticator-side policy enforcement. Nonextractability of a key handle alone cannot establish exclusive access, an attested provider, informed consent or replay protection.

An attested enforcement capability would need to bind the implementation, admitted policy authority and update/rollback behavior. A platform with no such proof must report the narrower capability. No unsupported capability may silently downgrade to another key, provider or algorithm.

## 4. Retry and uncertain execution

The protected operation identity must survive transport retries. Before invoking an external signer, the enforcing service durably records the operation and exact input commitment. If a response is lost after invocation, the result is unresolved; it is not safe to conclude that no signature exists.

A result-query operation returns the original authenticated outcome when available. The same operation ID with changed input is rejected. Reconciliation must not invoke the key again merely to reconstruct a response. When the actual provider cannot supply durable idempotency or result recovery, that limitation remains explicit.

Crash recovery must preserve spent authorizations, immutable completed results, revocation epochs and unresolved operations. Cancellation after dispatch does not prove non-execution. Account recovery or key-handle reallocation cannot reset these records or transfer an old authorization to another key.

## 5. Privacy and open design questions

Stable provider, key and operation identifiers can become correlation handles. Use the smallest scope required for recovery, limit disclosure, and specify who may query an outcome. Provider-side status checks can reveal signing activity.

The open issues are the host API shape, interoperable context encoding, authenticated capability evidence and a privacy-preserving recovery channel. The current proposals are separate development lines and must not be treated as interchangeable. Implementing a remote broker is not evidence that deployed authenticators implement this facility.

## 6. Evaluation

cases.json records the adversarial contract. Existing integrated broker tests cover input mutation across asynchronous calls, denial, replay, concurrent execution, restart and result reconciliation. This repository contains the independently reviewable API amendment and cases; it does not contain an independent browser or authenticator implementation.
