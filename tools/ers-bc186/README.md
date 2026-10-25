# BC 1.86 ERS compatibility probe

This probe consumes the public [fixed CMS retirement corpus](../../reference/vectors/cms-retirement-mtc07-rar2/README.md) through BC's original-data API, `ERSEvidenceRecord.validatePresent(new ERSByteData(original), at)`. The original is the complete 114435-byte ECP containing the CMS document, not a detached CMS object or a precomputed substitute hash. The complete timely ERS is 37979 bytes. Input filenames and the probe bind their SHA-256 hashes.

The eight predeclared presence/signature expectations match in **5/8 cases**. Initial and timestamp-only controls pass. Timely and late hash-renewal records, and the presence-only portion of the corrupted-final-signature case, fail with `object hash not found in wrapped timestamp`. All three unchanged token signatures validate separately. The corrupted final token fails signature validation; changing the original and truncating the record are rejected. The timestamp-only control wraps the first complete chain from the fixed record; no signed token is regenerated.

The three failed positive presence expectations remain failures. A passing regression means these exact observations were reproduced, not that BC and Framework fully interoperate. The probe exits 1; the replay wrapper succeeds only when the complete recorded observations match. The late-renewal presence expectation concerns byte membership alone: this BC call does not enforce Framework's algorithm-protection deadlines. Token validation checks the selected embedded signer and token constraints, not its historical TSA certification path, appointment or trust. No complete document or preservation acceptance is established.

## Hash-renewal boundary

Both implementations hash the preceding ArchiveTimeStampSequence with its outer DER SEQUENCE framing. Framework selects the binary-sorted pair in RFC 4998 Figure 4. BC 1.86's ERSByteData path uses `H(H(data) || H(previousSequenceDER))` without sorting. In these fixed bytes, the sequence hash sorts before the data hash, so the imprints differ. [Observed values](observed.json) record both constructions and the actual token imprint. No alternative ordering is tried during validation and no archived bytes are rewritten.

[BC 1.86 source](https://github.com/bcgit/bc-java/blob/eacda831fbe15b272933e40841d8b0827b556fae/pkix/src/main/java/org/bouncycastle/tsp/ers/ERSUtil.java) and [ERSByteData](https://github.com/bcgit/bc-java/blob/eacda831fbe15b272933e40841d8b0827b556fae/pkix/src/main/java/org/bouncycastle/tsp/ers/ERSByteData.java) identify the selected implementation. [RFC 4998 section 5.2 and Figure 4](https://www.rfc-editor.org/rfc/rfc4998.html#section-5.2) conflict on ordering; [erratum 7411](https://www.rfc-editor.org/errata/eid7411) was Reported when checked on 2026-10-25, not an approved correction. This versioned incompatibility does not adjudicate the standards ambiguity or establish a security bypass.

## Reproduction

Use Node.js 24.15.0 or the supported workspace version and JDK 17 or later. Download the three Maven Central jars listed in [dependencies.json](dependencies.json) into a separate directory. Their exact SHA-256 hashes are checked by the runner before compilation. Jars and compiled classes are not part of the repository.

```sh
node tools/ers-bc186/replay.mjs /path/to/bc-1.86-jars
node --test reference/ers-bc186-vectors.test.mjs
```

Optional `JAVA` and `JAVAC` environment variables select executable paths. The recorded probe used Temurin 21.0.12.1; Java version is reported but excluded from result comparison. BC version, all three jar hashes, every input hash, errors, token counts and diagnostic values must match. The protocol CI downloads these pinned jars and executes the replay. The Java probe uses only BC and Java APIs; the Node regression separately checks the unchanged Framework construction against the fixed bytes.
