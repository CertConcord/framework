# ML-DSA-87 Transparency Cosignatures — draft 02

Status: experimental extension and proposed C2SP amendment. No C2SP algorithm code or IANA registration is claimed.

## 1. Target and need

The pinned C2SP cosignature editor text defines the selected ML-DSA-44 subtree construction. An issuer or witness policy selecting ML-DSA-87 needs an unambiguous key identifier and explicit negotiation instead of treating another parameter set as that algorithm. ML-DSA-87 is an existing standardized algorithm; this proposal adds no new cryptographic primitive.

The technical change is limited to parameter-set selection, key discovery and interoperable encoding. Issuer admission, quorum, operator independence, retention and document authorization remain external policy.

## 2. Experimental selection

A verifier explicitly selects CERTCONCORD-MLDSA87-SUBTREE-v1 and an externally admitted witness name and ML-DSA-87 public key. The profile cannot be inferred from signature length or a document-supplied key.

Until an upstream discriminator is allocated, the experiment computes a four-byte key hint as the first four bytes of SHA-256 over the following concatenation:

    UTF8("certconcord/tlog-ml-dsa-87/v1\n")
    || UTF8(name + "\n")
    || DER_SubjectPublicKeyInfo(public_key)

The exact LF characters and DER SPKI are part of that input. This experimental key-hint derivation is not the C2SP ML-DSA-44 key identifier and must not be announced as a registered C2SP verification-key type.

The short hint only selects candidates from already trusted keys. It is not a collision-resistant certificate identity or authority decision. The verifier checks the actual name, key, algorithm and complete signature; ambiguous matches cannot silently select a different authority.

## 3. Signature input and checkpoint encoding

Use pure ML-DSA-87 with empty context over the existing subtree input:

    UTF8("subtree/v1\n") || 0x00
    || uint8_length(name) || UTF8(name)
    || uint64_be(timestamp)
    || uint8_length(origin) || UTF8(origin)
    || uint64_be(start) || uint64_be(end)
    || root_hash_32_bytes

Names and origins use the selected printable ASCII subset of the upstream name profile, excluding space, control characters and `+`, and fit their one-byte length. Other upstream UTF-8 names are outside this selected profile. Integer ranges and subtree alignment follow the pinned MTC/C2SP rules. A nonzero timestamp requires a prefix subtree starting at zero. The origin, range, root and witness name are all authenticated. Hashing the message again before a pure-message signing call changes the protocol.

For a checkpoint signed note, the signature payload is key_hint || uint64_be(timestamp) || signature, encoded with canonical padded base64 on the existing witness-signature line. A subtree cosignature is only the raw signature: it has no key hint or timestamp prefix. Its signed input still contains the fixed zero timestamp. Base64url, omitted padding, carriage returns and trailing bytes are not interchangeable encodings.

ML-DSA-87 signatures contain 4627 bytes. The key is supplied as an exact admitted SPKI; a public key with another algorithm is rejected. Reference verification uses Node's cryptographic stack, not a new ML-DSA implementation.

## 4. Selected subtree transport

The transport profile is `C2SP-20261007-MLDSA87-v2`, based on editor commit `a29318317776ae8a0e65ff45cfe450fd935a1aca`. This is an explicit experimental selection, not a stable C2SP release or assigned C2SP algorithm. The signing construction and experimental key hint remain `CERTCONCORD-MLDSA87-SUBTREE-v1`; changing carriage does not change the signed message.

`POST /sign-subtree` carries `subtree start end`, one base64 root hash, zero to 63 base64 consistency hashes, an empty line, and a checkpoint. Every line ends in LF. Integers are unsigned 64-bit decimal without leading zeros; hashes are exactly 32 bytes. The requested range must be aligned and end at or before the checkpoint size.

The submitted checkpoint MUST contain exactly one note signature, from the selected witness key. It MUST NOT include an additional log or witness signature. The service authenticates that checkpoint with the selected witness's key and verifies subtree consistency before signing. The response MUST use the same witness key. Rotation to a different response key is not inferred from a key hint.

A successful response is canonical padded base64 of exactly 4,627 raw ML-DSA-87 signature bytes followed by one LF. A signed-note response line, zero timestamp prefix, key-hint prefix, extra line or omitted padding is rejected. Neither a parser nor a length check authenticates a response: the client MUST verify the raw signature over the expected origin, range, root and witness name under its selected public key.

This witness-only request checkpoint is distinct from the published `/checkpoint` object of the tiled log API. A published log checkpoint MUST contain a valid signature from the admitted log and may also contain cosignatures. Applications MUST cryptographically verify that log signature. `assertCheckpointLogSignature` checks only structural presence of an externally supplied name and key hint; it does not establish authenticity, key ownership or log admission.

The selected reference rejects checkpoint extension lines, duplicate name/key-hint pairs and names outside its ASCII subset. It provides bounded encoding and cryptographic checks, not the log's durable consistency state, an HTTP server or a complete Merkle proof implementation. Those obligations remain mandatory for applications using this transport.

## 5. Downgrade and transition

Peers advertise and authorize this experimental profile separately. A peer requiring ML-DSA-87 cannot fall back to ML-DSA-44 or a classical algorithm after an unsupported-profile response.

An eventual upstream-assigned type requires a new explicit adapter and test vectors. Draft 01 subtree HTTP carriage is rejected by this draft; there is no implicit fallback or second runtime. Existing archived checkpoint notes retain their original bytes and experimental key-hint rules. Replacing a key hint in an old note is not a valid migration. Independent adoption does not require any CertConcord governance or signed control object.

## 6. Proposed upstream amendment and limitations

The upstream review question is whether another parameter set belongs in the cosignature registry, and, if so, which discriminator and public-key encoding should be assigned. A proposed registered form should reuse the upstream key-hash layout with its actual assigned type; this experiment intentionally claims no free registry value.

The retained prefix vector covers exact key selection, a prefix subtree and a valid signature. The serialized transport vectors additionally cover the request, checkpoint signatures, raw response, required published log signature and rejected old carriage. Negative cases change origin, range, witness name, root, timestamp, algorithm and signature bytes. They establish encoding and signature semantics, not the necessity of ML-DSA-87, independent operator deployment, or a complete composition security proof. Larger keys and signatures require availability and transport-limit evaluation.

The reviewed editor delta separates checkpoint and subtree cosignature carriage, moves checkpoint key identifiers to the checkpoint specification, requires exactly one witness signature in a subtree request, and requires a log signature on a tiled-log checkpoint. The ML-DSA input structure is unchanged. The editor's link to an MTC draft-07 does not establish publication or implementation of that revision; this component retains its separately pinned MTC draft-06 and editor comparison.
