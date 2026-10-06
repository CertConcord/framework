# PassSign Evidence Transcript Clarification — draft 01

Status: proposed amendment, not submitted or adopted. The target is the pinned PassSign community draft, especially sections 6.2, 7.2 and 7.3.

## 1. Specific ambiguity

The current draft places timestamp material inside its Evidence Record while requesting a timestamp over that record. It does not fully specify the original byte range or whether the service signature is produced before or after timestamp acquisition.

An implementer cannot hash an object that already contains the timestamp being requested. JSON parse/serialize cycles can also change the bytes even when an object appears semantically equivalent. This proposal fixes construction order using the existing signed evidence artifact, without another mandatory signature or cryptographic primitive.

## 2. Proposed construction

1. Complete the event facts already required by the upstream draft, including the manifest, activation evidence, identity context, original document signature reference and service statement.
2. Produce the existing service-signed Evidence Record as a compact JWS. Its payload excludes timestamps and later log proofs. Freeze the exact ASCII compact serialization after signing.
3. Request an RFC 3161 timestamp whose SHA-256 message imprint is the hash of those exact compact-JWS bytes, including its signature component.
4. Carry that unchanged JWS and the returned timestamp tokens in an outer evidence package. A log proof is also outside the original JWS. This packaging layer needs no additional mandatory signature: the existing service signature and timestamp supply the specified integrity relationships.
5. The receipt carries the original JWS bytes and required augmentation. It does not reconstruct or re-sign the evidence core.

The signature already fixes its payload encoding, so this construction does not require a new JSON canonicalization algorithm. The new revision must explicitly define this packaging and its media type or version discriminator. A verifier of the current draft cannot be assumed to accept the proposed revision.

## 3. Verification and later augmentation

First validate the service JWS under the appropriate key and authority policy. Then validate its event claims, document commitments and activation evidence using the upstream verification procedure. Independently validate each timestamp's TSA, policy, algorithm, status, accuracy and exact message imprint over the retained compact JWS.

An outer token covering different bytes is rejected. Whitespace, padding changes, payload reserialization or a replacement service signature change the transcript. Preserving a parsed JSON object instead of the signed serialization is insufficient.

Later timestamps, log proofs and status observations can augment the outer package without changing the original core. Each later proof must identify its exact target bytes and declared purpose. A proof over the earlier core does not automatically cover newer augmentation. Archive renewal remains the selected established preservation mechanism.

A timestamp establishes existence subject to its trust and time bounds, not the exact act of signing or informed consent. Service assertions about identity and approval still need the upstream trust checks.

## 4. Recovery and adverse cases

If timestamp acquisition fails, retain the completed JWS and retry the timestamp request over the same bytes. Do not repeat document signing or silently produce a different evidence event to obtain time evidence. A timestamp received after an application deadline does not retroactively satisfy that deadline.

If delivery fails, resend the original record and augmentation. The recipient verifies both, independent of whether they arrived together. Partial evidence cannot be reported as complete validation.

The byte-level reference shows invariant timestamp input during augmentation and different input after core substitution. It does not implement PassSign enrollment, service authorization, TSA validation or an AdES container. No claim of full PassSign conformance is made.

## 5. Proposed editorial change

Replace the ambiguous Evidence Record hash reference with the hash of the exact completed service JWS, move timestamp and log-proof carriage outside that JWS, and define the revised package discriminator. Make the signing-before-timestamp order and retention of original bytes explicit in creation, delivery and verification. Upstream authors may select a different acyclic representation, but must specify equally exact coverage and ordering.
