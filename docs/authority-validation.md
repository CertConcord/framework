# Scoped issuance and authority validation

A RegistrationAuthorization uses schema version 2 and signs exactly one
`issuanceScope`: a 32-byte trust domain identifier, a configured issuer identifier,
a 64-byte issuer key commitment, and one of `X509`, `MTC`, or `MDOC`. The existing
signed profile selects the credential purpose. A registration decision cannot be
reused with a different issuer, issuer key, domain, representation, or purpose.
There is no implicit multi-issuer grant or unscoped fallback. All issuance paths
check the decision lifetime and retain the result under a durable request identity.

Cryptographic certificate pins identify keys; role authorization is an additional
relying-party decision. The shared resolver receives an authority identity, role,
scope, operation `stateTime`, and evidence `knowledgeTime`. Appointments must state
their roles, scope, admission time, validity interval, and authenticated status.
Certificate appointments include the certificate validity interval. An explicit
raw-key appointment has its own selected lifecycle and does not inherit unlimited
authority from a wrapping certificate. An optional algorithm deadline further
limits the appointment. Issuer certificates must match the actual signing key.

Status is bound to the authority key and trust domain. A known key compromise
applies across roles, appointments, and reissued certificates. Future evidence
cannot authorize an earlier knowledge state. Missing, stale, unavailable, or
conflicting evidence prevents acceptance. Unknown critical semantics are
unsupported. An established cryptographic or authorization failure remains
invalid even when other evidence is unavailable.

## Time boundary types

These bounds have different meanings. Evaluation uses the exact state time for
the operation and the selected knowledge time for information availability; a
fractional proof bound is not rounded into a neighboring certificate second.

| Bound                                               | Admission at its upper endpoint                                                                                                                                                                      |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| X.509 `notAfter`                                    | Included, as required by [RFC 5280 §4.1.2.5](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5). A selected certificate authority can act at this instant if every other bound still admits it. |
| Authority appointment `validUntil`                  | Excluded. A renewal must cover the endpoint itself.                                                                                                                                                  |
| Authority `algorithmValidUntil`                     | Excluded. The algorithm is no longer selected at that instant.                                                                                                                                       |
| Status `nextUpdate` at knowledge time               | Excluded. The status is stale at that instant.                                                                                                                                                       |
| MTC subtree cache `expiresAt`                       | Excluded. A cache entry cannot extend certificate validity.                                                                                                                                          |
| Native mdoc credential `validUntil`                 | Excluded. It remains independent of the issuer certificate endpoint.                                                                                                                                 |
| Trusted proof upper bound against a TSA certificate | Must be strictly before `notAfter`, because the upper bound is a conservative bound for an unknown actual generation instant, not the exact certificate-use instant.                                 |

For a composed decision, every applicable bound must admit the same selected
state and knowledge times. An inclusive certificate endpoint does not extend an
exclusive appointment, algorithm, status, credential or cache deadline.

## External authority and status source contract

The reference verifier checks the selected authority decision and, when using
`createAuthorityResolver`, the status statement's key, domain, schema and time
binding. It does not authenticate an arbitrary caller-supplied callback result.
Production callers must establish that boundary before constructing the verifier:

1. Load authority appointments and status from a configured, authenticated
   source. Preserve exact signed bytes or an equivalent authenticated provenance
   record; do not read a trust source URL, tenant or authority from the evidence
   being evaluated. Bind the source to the selected trust domain, tenant,
   authority key ID, role and full scope. A domain-wide grant must be explicit.
2. Select one immutable source revision and one knowledge snapshot for each
   verification. The callback must answer every authority query in that
   verification from that revision, even if a newer revision arrives during the
   call. State time is the historical operation time; knowledge time is the
   information cutoff. Later-known compromise must remain available for a
   later-K re-evaluation without rewriting the earlier-K result.
3. Enforce a monotonic source revision and knowledge time within each tenant and
   trust domain. A rotation or policy change creates a new configured verifier;
   do not mutate the selected trust object or swap its callback closure in
   place. Retain the older revision when a historical K must be reproduced.
4. Treat missing, stale, conflicting, unauthenticated, asynchronous or throwing
   callback data as non-VALID. A temporary source outage cannot reuse the last
   positive decision beyond its authenticated coverage. Revocation and known
   compromise remain negative across later appointments for that key.
5. Keep an audit record of the selected source identity and revision, tenant,
   trust domain, knowledge time, requested state time, authority key ID, role,
   scope, decision, status publication time and coverage bound. This record is
   operational evidence, not a new signed CertConcord artifact or a substitute
   for the original input and authenticated status bytes.

The SDK copies closed trust data at construction and copies that private data
for each evaluation. Callback functions retain their identity and can observe
live external state; the caller is responsible for the immutable source revision
described above. Each authority resolver invocation receives a copy of its
query data, including nested bytes, so callback mutation cannot rewrite the
selected evaluation. Recreate the verifier for a deliberate trust or policy
update.

`KeyID` remains SHA-512 of the original DER SubjectPublicKeyInfo. If an explicitly
selected policy admits different encodings of the same mathematical public key,
an applicable `INVALID/AUTHORITY_REVOKED` decision also applies to a known,
selected identity using an equivalent encoding. This negative lookup does not
admit a missing or not-yet-known identity, add roles or scopes, or transfer GOOD,
STALE, unsupported, or malformed status from another encoding. Status callbacks
receive the original record's KeyID and the operation's unchanged role, scope,
state time, and knowledge time; raw status remains bound to that record's KeyID
and trust domain. Existing exact-KeyID negative decisions retain their precedence.
The [fixed generic-policy vectors](../reference/vectors/direct-authority-key-incidents.json)
use explicit synthetic P-256 selections; they do not change the governed
pure ML-DSA-87 profile or authorize an alternative encoding by themselves.

For explicitly selected RSA identities, this negative comparison also recognizes
the same positive modulus and public exponent in `rsaEncryption` and
`id-RSASSA-PSS` SubjectPublicKeyInfo encodings. These encodings carry the same
`RSAPublicKey` structure ([RFC 4055, Section 1.2](https://www.rfc-editor.org/rfc/rfc4055#section-1.2)).
PSS hash, mask-generation and salt restrictions remain attached to the original
key object; equivalence never replaces that key for signature verification.
The additional RSA-family fallback treats native-imported nonpositive modulus
or exponent values as non-equivalent. Existing same-type native key equality,
key-import policy, and governed signing profiles are unchanged.
The [synthetic RSA/PSS vectors](../reference/vectors/authority-rsa-equivalence.json)
cover both propagation directions, original status bindings, time and appointment
limits, unrelated material and retained native PSS signature restrictions. Their
policy and status inputs assume prior caller authentication; they are not a
signed governance directory or an operational RSA authority profile.

Online issuance and execution and offline CMS/mdoc verification use the same
resolver contract. Registration decisions are evaluated when issued, issuer roles
when the credential is issued, status roles when status is published, and permit
and receipt roles at execution and the trusted proof-of-existence bound. Native
mdoc document evidence retains the independent registration decision. The SDK
requires explicit scope and resolver inputs; evidence cannot appoint its own
authorities.

Actual verified MTC signers require COSIGNER admission. Native issuance requires
TRANSPARENCY_LOG admission for the log and MIRROR admission for the verified mirror
signers. Quorums count distinct authorized operators; an extra revoked member
cannot veto enough valid members. Trusted-time plans require the same contributing
key to be authorized at issuance and at the first trusted proof upper bound.
Self-declared issuance cannot bypass a later compromise. Normal retirement before
that first proof can also prevent acceptance without an earlier authenticated
anchor. These checks belong to the framework composition, not its independent
MTC or C2SP wire components.

`example-authorities.mjs` creates synthetic test policy. It is not an authenticated
operational directory. Durable tests, known-answer cases, and local examples do
not establish external implementation interoperability or production assurance.
This is the authority contract of the flat draft-03 evidence format and selected
retained preservation profile. Prior unscoped decisions and experimental wire
domains are unsupported; this remains a working draft, without a stable
deployment or legacy compatibility claim.
