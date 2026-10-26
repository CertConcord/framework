# Certificate validity endpoint vectors

These synthetic vectors preserve two P-256 X.509 certificates and two MTC
TBSCertificates in their original signed encodings. Each pair covers UTCTime
and retained GeneralizedTime. The X.509 controls use a synthetic root and the
standard critical time-stamping EKU. The GeneralizedTime controls for 2026
exercise reader compatibility; they are not examples of the current issuer
encoding profile.

Eight explicit evaluation times include both certificate endpoints and adjacent
integer and fractional times. Certificate validity includes exact `notAfter`,
as specified by [RFC 5280 section 4.1.2.5](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5).
The first later instant is outside the interval; there is no added grace second.

Each MTC case contains a standalone proof and a landmark representation of the
same TBS, the raw log entry, root, public cosigner keys and exact cosigned
messages. Its certificate endpoint is inclusive while its declared cache expiry
remains exclusive. Signature, TBS substitution, revocation, quorum and cache
controls are exercised by `certificate-validity-endpoint-vectors.test.mjs`.
Certificate IDs, representation hashes and original commitments are checked
without regenerating or normalizing signed data.

No private keys are included. A synthetic root or cached MTC root is an explicit
test input, not an authority admission. These vectors test the certificate-time
primitives and their proof bindings. They do not establish TSA authorization,
status, historical knowledge, production trust or complete document validation.
Application windows and stricter proof-protection deadlines remain separate.
