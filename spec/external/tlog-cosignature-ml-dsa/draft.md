# ML-DSA-87 Transparency Cosignatures — draft 01

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

## 3. Signature input and note encoding

Use pure ML-DSA-87 with empty context over the existing subtree input:

    UTF8("subtree/v1\n") || 0x00
    || uint8_length(name) || UTF8(name)
    || uint64_be(timestamp)
    || uint8_length(origin) || UTF8(origin)
    || uint64_be(start) || uint64_be(end)
    || root_hash_32_bytes

Names and origins use the selected printable ASCII note profile and fit their one-byte length. Integer ranges and subtree alignment follow the pinned MTC/C2SP rules. A nonzero timestamp requires a prefix subtree starting at zero. The origin, range, root and witness name are all authenticated. Hashing the message again before a pure-message signing call changes the protocol.

For a signed note, the signature payload is key_hint || uint64_be(timestamp) || signature, encoded with canonical padded base64 on the existing witness-signature line. Base64url, omitted padding, carriage returns and trailing bytes are not interchangeable encodings.

ML-DSA-87 signatures contain 4627 bytes. The key is supplied as an exact admitted SPKI; a public key with another algorithm is rejected. Reference verification uses Node's cryptographic stack, not a new ML-DSA implementation.

## 4. Downgrade and transition

Peers advertise and authorize this experimental profile separately. A peer requiring ML-DSA-87 cannot fall back to ML-DSA-44 or a classical algorithm after an unsupported-profile response.

An eventual upstream-assigned type requires a new explicit adapter and test vectors. Existing archived notes retain their original bytes and experimental key-hint rules. Replacing a key hint in an old note is not a valid migration. Independent adoption does not require any CertConcord governance or signed control object.

## 5. Proposed upstream amendment and limitations

The upstream review question is whether another parameter set belongs in the cosignature registry, and, if so, which discriminator and public-key encoding should be assigned. A proposed registered form should reuse the upstream key-hash layout with its actual assigned type; this experiment intentionally claims no free registry value.

The vector covers exact key selection, a prefix subtree and a valid signature. Negative cases change origin, range, witness name, root, timestamp, algorithm and signature bytes. They establish encoding and signature semantics, not the necessity of ML-DSA-87, independent operator deployment, or a complete composition security proof. Larger keys and signatures require availability and transport-limit evaluation.
