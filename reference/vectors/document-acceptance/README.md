# Original-byte document acceptance vectors

This is the historical MTC revision-06 corpus. Its manifest, original bytes and expected results are retained unchanged and correspond to Framework commit `9923c17f03d0a93e770b91f39183bad474889e36`. Replay the commands below from that revision. The current runtime selects the separate [MTC revision-07 corpus](../document-acceptance-mtc07/README.md) and rejects this older corpus profile.

This corpus contains synthetic CMS with standalone MTC certificates and native mdoc document signatures. Both complete document paths use ordinary WebAuthn activation and a trusted document timestamp. The files contain public material only.

Run from the repository root with the selected Node runtime and installed reference dependencies:

```sh
node reference/verify-vectors.mjs
node --test reference/document-vectors.test.mjs
```

The runner reads the saved bytes, constructs external fixture policy from the saved public inputs, and invokes the existing verifier. It does not generate keys, sign, renew, repair, or contact an issuer. Decisions use the declared knowledge time and policy, independently of the process's current date. A mismatch exits nonzero. Changing an expected result does not change the actual verifier verdict.

| Group          | Cases | Selected observations                                                                                                                                                                                                        |
| -------------- | ----: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `documents`    |    21 | CMS and native mdoc success; altered commitments; missing time; unsupported profiles; wrong domain or authority role; stale status; bad signature mathematics; combined failure precedence; authenticated compromise status. |
| `preservation` |    10 | Each document format with original protection, timely renewal, absent renewal, absent hash renewal and a genuinely issued late hash renewal.                                                                                 |
| `retained`     |     6 | Each format with current renewed evidence, stale current evidence and a later authenticated authority compromise.                                                                                                            |

The expected objects are assertions about these saved scenarios. They are not inputs to the document verifier. The CLI reports the actual results, including the distinct preservation and current-admissibility decisions.

## Representation and integrity

`manifest.json` is a versioned inventory with three case groups: `documents`, `preservation`, and `retained`. Each file descriptor gives its stored byte count and SHA-256, encoding, and decoded byte count and SHA-256. Binary CBOR, DER, COSE and public SPKI bytes are stored as canonical base64 with one final newline in `.b64` files. Decoding returns the original saved bytes; replay does not re-encode any signed object. JSON configuration files remain UTF-8 text. A manifest hash is an inventory check, not an authority signature or trust root.

Configuration values use closed data tags:

- `{"$hex":"..."}` represents a short byte string.
- `{"$file":"files/...","type":"bytes"}` references exact decoded bytes.
- `type:"spki"` imports a public SubjectPublicKeyInfo; `type:"x509"` imports a pinned public certificate.

All references must be in the inventory and inside the corpus directory. File size/hash mismatches, unsupported fixture schema and unsafe references are corpus errors; they are not reported as document signature verdicts.

## External trust and fixed knowledge time

Each document case selects a format, original evidence bytes and a separate trust configuration. The latter supplies the relying-party domain, policy, explicit keys/certificates, finite appointments, status information and knowledge time. Declared domain-wide role grants are synthetic external appointments. Evidence cannot create its own appointment. Public timestamps use the pinned certificate, issuer key, policy and finite status record; a timestamp's claimed date does not supply its own authority.

The runner constructs the existing authority resolver from those records. The fixture times and security deadlines are synthetic scenario inputs, not retirement forecasts or a claim that these examples are currently acceptable. Replaying the same bytes at the later declared knowledge time demonstrates stale status separately from signature integrity.

The stable document result includes `overall`, `reason`, `coreRevision`, `profile` and only the `dimensions` actually evaluated. The manifest records their exact expected values. A complete leaf-hash inventory alone cannot justify an `integrity: VALID` result.

The installed SDK can be exercised with the same document loop through its unchanged public export:

```js
import { createVerifier } from '@certconcord/verifier';
import { runDocumentVectors } from './reference/verify-vectors.mjs';
runDocumentVectors({ createVerifier });
```

This injects the public verifier only. The corpus's external policy loader is published reference code, not an additional SDK export or an independent cryptographic implementation.

## Preservation and retained admissibility

The preservation cases pass saved RFC4998 DER records and exact original document evidence bytes to `verifyERSPreservation`. They include initial protection, timely TSU and hash renewal, missing renewal, missing hash renewal and a genuinely issued renewal at the old hash deadline. The negative records are retained as issued; replay does not alter their signed timestamps.

The retained cases additionally use saved signed root-manifest histories, publication proofs, external initial governance pins and explicit algorithm deadlines through `createRetainedAuthorityResolver` and `verifyPreservedDocument`. They report `preservation`, `historicalAuthorization` and `currentAdmissibility` separately. Original evidence remains the archived data; refreshed credential status is a separate current evidence package bound to the same operation. A later authenticated compromise may leave preservation valid while making current admissibility invalid.

SDK document `VALID` does not imply ERS preservation, CAdES/PAdES conformance, current enrollment eligibility, operational time/custody assurance, or an independent implementation. Publishing reproducible inputs and outcomes supports the draft's verification contract; external assessment and a second complete implementation remain separate evidence.
