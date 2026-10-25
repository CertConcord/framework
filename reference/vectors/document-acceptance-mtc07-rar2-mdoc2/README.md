# Certified native mdoc contract vectors

This separately versioned corpus selects `certconcord-document-acceptance-vectors-draft-03-mtc07-rar2-mdoc2`. Newly issued native mdoc credentials certify a canonical absolute HTTPS status URI and a distinct `ra_authorization_commitment` over the authenticated RegistrationAuthorization body. The existing `ra_authorization_hash` remains SHA-512 of the complete original signed RAR. The DOCUMENT binding requires both.

The [earlier RAR2 corpus](../document-acceptance-mtc07-rar2/README.md) remains byte-for-byte unchanged. Its original interpretation belongs to Framework commit `72c40e27e108fe8dfe9b8bb87051801ea01cea10`; the current loader rejects its profile identifier. This corpus separately includes its exact original native mdoc package as a negative case. That original has an authenticated HTTP status URI and no certified body commitment; the current SDK rejects it with `MDOC_STATUS_REFERENCE`. Its decoded SHA-256 is `57bf0e9588956107dd5f876e4f8b9a78b0faaee0400cdaca1b79170986973661`.

The synthetic scenario clock remains 20 October 2026 00:00:00 UTC. Existing CMS cases, signed bytes and expected results are retained. Native mdoc inputs and their preservation records were newly signed. All prior scenario assertions retain their exact expected verdicts, including stale evidence and authenticated compromise. This is draft acceptance evidence; it does not establish external interoperability or operational identity, custody or clock assurance.

Run offline from the repository root:

```sh
node reference/verify-vectors.mjs
node --test reference/document-vectors.test.mjs reference/mdoc-certified-contract.test.mjs
```

The main manifest contains 22 document cases, 10 RFC4998 preservation cases and 12 retained-admissibility cases. The installed SDK replays the document cases through its public `createVerifier` export. The remaining original files are retained to preserve the earlier corpus's public material and the negative original; an inventory entry alone does not imply acceptance.

Six retained cases reuse the existing signed evidence and change one input each. A null ERS record produces preservation `INVALID/MALFORMED_EVIDENCE`; empty ERS bytes produce `INVALID/DER_LIMIT_OR_TRUNCATION`. Both leave historical authorization `INDETERMINATE/HISTORICAL_BYTES_UNPROVEN`. The two cutoff cases select historical knowledge time H = 1792454401, after the original document timestamp upper bound 1792454400 but before the first complete-package proof P = 1792454402. The original document remains valid under the same H and retained authority policy, while historical byte visibility and authorization are `INDETERMINATE/HISTORICAL_BYTES_NOT_YET_PROVEN`. The existing renewed cases retain the inclusive H = P positive boundary. Current admissibility remains VALID in all six additional cases; original/current signed bytes, trust inputs and current knowledge time are unchanged.

`certified-contract.json` adds 27 saved credential and registration-binding cases. Each contains newly signed IssuerSigned bytes, a matching post-quantum seal and transparency proof, exact RA CMS bytes and separate public trust inputs. They exercise invalid URI syntax, closed status-reference shape, invalid representable indices, absent or malformed body commitments, a different body, and substitution of either commitment for the other. Positive controls cover the certified credential, the selected DOCUMENT binding and DCP without DOCUMENT selection. Fractional and unsafe integer indices are rejected by the CBOR issuer primitive and are tested separately; they are not represented as signed-wire examples. These boundary cases call the credential and registration validators directly and do not claim full document or archive acceptance.

The manifest inventories stored and decoded byte counts and SHA-256 hashes. Binary files are canonical base64 with one final newline. The loader verifies them and returns the exact original bytes; replay never signs, repairs or contacts an issuer. Public configuration uses closed `$hex` and `$file` tags. Explicit external appointments and knowledge times supply fixture trust; signed evidence and manifest hashes cannot appoint their own authorities. No private keys or executable callbacks are included.

Document validity, original proof of existence, current admissibility and continuous preservation remain distinct decisions. A green SDK document result does not establish CAdES/PAdES conformance, current enrollment eligibility or production readiness.
