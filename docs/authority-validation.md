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
