# Original-byte organization history vectors (RAR schema 2)

This corpus issues RegistrationAuthorization schema 2 as required by COMMON-draft-03. It retains the prior scenario assertions and uses newly signed synthetic inputs. The original [organization-history](../organization-history/README.md) directory and its bytes remain unchanged; replay of that schema 1 corpus belongs to Framework commit `ac43db6dfd52acbac57a091cb2c9b5cc71e06244`. The current loader rejects its old profile identifier.

This separate corpus saves synthetic organization delegation evidence and real RFC 3161 / RFC 4998 protection bytes. It contains public material only. The existing 37 document acceptance cases remain unchanged.

Replay from a checkout with its locked reference dependencies installed:

```sh
node reference/verify-organization-vectors.mjs
node --test reference/organization-history-vectors.test.mjs reference/organization-vector-loader.test.mjs
```

The CLI reads exact saved bytes. It does not generate keys, sign, issue or renew timestamps, repair evidence, import the authoring fixtures or contact a network service. Declared relying-party K determines knowledge time; the machine's current date does not. It exits nonzero on malformed corpus data or any difference in a complete actual result.

Each case independently selects five inventoried references: original ECP bytes, EvidenceRecord, external policy configuration, external knowledge snapshot and expected result. Policy contains the initial governance roots, original credential/control trust, public timestamp pins and finite protection/coverage bounds. Knowledge contains K, exact canonical-CBOR signed RTM bodies with their original signatures and publication proofs, and current CMS status material. Original positive evidence cannot be supplied by a current replacement.

The adapter is deliberately small:

```js
const source = createOrganizationHistorySource({
  configuration,
  readKnowledge: () => knowledge,
});
const verifier = createOrganizationHistoryVerifier({ source });
const actual = verifier.verify({ originalBytes, evidenceRecord });
source.close();
```

The shared public source authenticates authority history and selects timestamp trust. The loader makes no authority, revocation or compromise decision. Expected results are read for comparison after verification; changing them cannot change the actual verdict. Complete result objects include all scopes, times, checks, partial dimensions, preservation details, protection ledger and limitations. No projection or rounding is used.

The cases cover issuer expiry and scoped root/status succession; exact integral and fractional exclusive PoE boundaries; all 14 missing originals; invalid raw approvals; ordinary post-proof revocation and later learned retrospective compromise; same-epoch conflicts and later GOOD heads; missing or expired current status/history coverage; late renewal; wrong bindings/scope and incomplete root succession. One combined scenario records different original target identifiers sharing a key with one compromised target. Its overall rejection also follows from that direct target incident. This corpus does not independently establish cross-original key-wide continuity without a direct target match.

Historical authorization uses state/knowledge P/P; current admissibility uses P/K; preservation must reach K. All three must be valid for overall acceptance. Every result is only retained evidence verification. No case grants current signing, reconciliation, recovery or output-release permission, and the signed live policy remains `CURRENT_STATE_ONLY`.

## Representation and limits

`manifest.json` has schema version 1 and profile `certconcord-organization-history-vectors-draft-03-rar2`. Every inventoried file records stored and decoded sizes and SHA-256 digests. Binary data is canonical base64 plus exactly one LF; filenames carry the decoded digest. JSON uses the canonical representation checked by the loader. Bytes and public SPKI references use closed `$file` tags; a short bounded `$hex` tag is also supported. SPKI materializes to exact public DER bytes for the shared source, not a caller-supplied KeyObject.

The loader bounds JSON to 4 MiB, files to 32 MiB, the inventory to 512 files, cases to 128, total stored and decoded bytes separately to 128 MiB and JSON/configuration depth to 64. It rejects undeclared or unsafe paths, malformed encodings, duplicate/case-colliding paths, noncanonical JSON, private-key/prototype/callback fields and hash mismatches. Reads use bounded descriptors and check observed identity and size before and after. Those checks are not an atomic directory sandbox on platforms without descriptor-relative open.

Inventory and provenance hashes establish consistency of the selected files. They are not authority signatures, initial trust appointments or runtime-code attestation. Provenance lists the authoring baseline, reviewed source hashes, semantic assertion hash, dependency lock and Node/OpenSSL versions. The declared baseline plus explicitly hashed source changes describe construction; normal replay can evaluate a newer implementation against these frozen bytes. Installed-SDK validation separately records the actual installed bundle hash.

## Authoring boundary

`tools/freeze-organization-vectors.mjs` and `reference/organization-history-vector-semantics.mjs` are separately reviewable authoring/test code. Neither is imported by the replay runner. The semantic module fixes outcomes and independently checks relevant public input facts before any full expected result is captured. The authoring utility uses ephemeral synthetic keys, refuses to overwrite an existing manifest, and writes no private key material.

Checking newly generated input facts alone is a separate operation:

```sh
node tools/freeze-organization-vectors.mjs --check-inputs
```

Writing a new reviewed corpus requires the explicit `--write --approved-semantic-sha256 <reviewed digest>` authoring arguments. This is not a replay update mode. Changes to frozen semantics or outputs need a separate review; a failing implementation must not dictate new expected answers.

The scope remains a bounded draft verifier and synthetic corpus, with direct RFC 3161 RTM publication proofs. Independent implementation validation, real operational custody, complete-store rollback detection and separate preservation of retired external status signers are not established by these cases.
