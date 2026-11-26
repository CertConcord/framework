# mdoc Signing Certificates - draft 03

Status: independent experimental application profile. This revision selects a post-quantum issuer path, issuerAuth, holder proof, status signature and detached document signature. It is an experimental mdoc algorithm extension, not an ISO/IEC 18013-5 amendment or a claim of standard mdoc wallet interoperability.

## 1. Scope and authority

An issuer certifies a subject's document key and personal document-signing purpose in issuer-authenticated mdoc data. A relying party explicitly authorizes that issuer, role, document type and application profile. An admitted government or other CA may issue this profile. Acceptance of an external mDL/photoID during enrollment does not appoint that identity issuer as a document-signing CA or import its roots into another CA's chain.

The complete base profile is `MDOC-SIGNING-PERSON-PQ-v3`: an ML-DSA-65 issuing path and MSO signature, an ML-DSA-65 holder key, an ML-DSA-65 status JWS and a separate ML-DSA-65 or ML-DSA-87 document key. The document type and signing namespace are `org.certconcord.signer.1`. Raw document signing is optional; a presentation does not prove an arbitrary document signature.

The earlier `MDOC-SIGNING-PERSON-PQ-v2`, `MDOC-SIGNING-PERSON-DEVICE-v2` and `MDOC-SIGNING-PERSON-ASSOCIATED-v2` profiles rely on classical issuer and holder authentication. They are historical test fixtures, not the default or an implicit fallback. The reference accepts them only with an explicit `allowLegacyClassical=true` selection and their exact historical profile IDs. The flag does not relax any v3 algorithm check. No v2 credential is upgraded by renaming it v3. Applications select the exact profile ID, document type, namespace and expected key mode as external verification parameters; credential claims cannot select trusted policy.

Organizational seals, encryption and legal qualification are outside this personal baseline. Its purpose is exactly `DOCUMENT_SIGN`; changing a string cannot create another capability.

## 2. Standards and development baselines

The published background edition is **ISO/IEC 18013-5:2021, edition 1, September 2021**. The ISO catalog identifies it as published and separately lists a DIS successor under development. The full licensed 2021 text has not been checked in this work. Public metadata and Multipaz code do not establish ISO conformance; production implementers need the normative text and relevant certificate-profile assessment.

The separately tracked public WG10 text is the September 14, 2025 CD-ballot-resolution document at commit `b250e7a64f99e22ceed10d2a5799bed38ee89f85`, blob `70af94f67df47e6d35ac5b055201892688c1c11a`. Its cover places it before a DIS ballot. It is neither the published 2021 edition nor evidence of the latest DIS text. Its certificate binding, revocation, DeviceSigned and device authentication sections were reviewed; hashes are in `sources.json`. The copyright-protected PDF is referenced, not redistributed. [The original source check](reference/standards-research-2026-11-24.md) and [PQC source check](reference/pqc-research-2026-11-25.md) record clauses and maturity boundaries.

RFC 9964 registers pure ML-DSA for COSE and JOSE, and RFC 9881 defines its X.509 encoding. The reviewed WG10 working text's issuerAuth and DeviceAuth suites do not select ML-DSA. Using RFC 9964 AKP as an MSO device key, ML-DSA issuerAuth and ML-DSA DeviceSignature is therefore this **experimental extension**. Published cryptographic encodings do not establish ISO mdoc conformance, wallet compatibility or document-signing CA authority.

That working text's sections 12.3.4 and 12.3.6 discuss protected certificate thumbprints and optional MSO revocation using identifier-list or status-list mechanisms, with COSE/CWT revocation lists and a reference to Token Status List draft 12. This component instead selects the application namespace/JWT binding in section 5 against Token Status List draft 21. Location, token representation and delegated status-authority rules differ. No automatic conversion, dual runtime or second-edition conformity is claimed.

Certificate binding uses existing RFC 9360 `x5t`, avoiding a new certificate-digest extension. It is an explicit application requirement here even where the working text recommends it. Document-to-credential binding separately commits to the complete original credential, not just its issuer certificate.

Informative Annex D.7.2 of the public WG10 text illustrates returning a document hash as a DeviceSigned element in a request/response. That is a session-bound device authentication example; it does not define this profile's separately certified document key, `DOCUMENT_SIGN` grant or standalone detached document signature. No clause-level claim about the unreviewed published 2021 text is inferred from that example.

## 3. Credential and issuer authentication

The credential is a complete encoded `IssuerSigned` map with exactly `nameSpaces` and `issuerAuth`. The reference accepts definite-length CBOR, shortest integer/length encodings, no duplicate map keys, depth below 32, at most 100,000 items and at most 8 MiB. Map keys are text or integers in the CBOR argument range from `-2^64` through `2^64 - 1`; schema fields separately constrained to safe integers retain those limits. Values use integers, strings, byte strings, booleans, null, arrays, maps and the selected tags. Floating point and indefinite lengths are outside this base.

Text strings contain well-formed UTF-8 and preserve every code point, including a leading U+FEFF. Text map keys and required field names match exactly; decoding does not remove a leading marker or normalize text. Fixed positive and negative encodings are retained in [the CBOR text vectors](vectors/cbor-text.json).

Each namespace contains nonempty tag-24 embedded issuer items. Each item has exactly `digestID` (nonnegative safe integer), `random` (at least 16 bytes), `elementIdentifier` (nonempty text) and `elementValue`. Repeated disclosed salts, duplicate names or digest IDs are rejected. SHA-256 covers the exact encoded tag-24 item, including its wrapper; re-encoding embedded contents is not equivalent. A signing credential contains every namespace and item named by the MSO. Partial disclosure is an explicitly selected low-level presentation capability, insufficient for the signing base.

The MSO selects version `1.0`, digest `SHA-256`, exact `docType`, nonempty `valueDigests`, and `deviceKeyInfo` containing only a COSE `deviceKey`. V3 requires RFC 9964 AKP with `kty=7`, `alg=-49`, `pub=-1` containing exactly 1,952 raw ML-DSA-65 public-key bytes and no private component. `validityInfo` contains valid tag-0 UTC dates with whole seconds and `Z`, satisfying `leaf.notBefore <= signed <= validFrom < validUntil <= leaf.notAfter` and `validFrom <= stateTime < validUntil`. Optional `expectedUpdate` lies between `signed` and `validUntil`. Unknown versions/digests are unsupported. The full signing base rejects MSO `status` as an unselected capability.

`issuerAuth` is untagged COSE_Sign1 over the encoded tag-24 `MobileSecurityObjectBytes`, using empty external AAD. V3 protected `alg=-49` selects pure ML-DSA-65 with empty context and a 3,309-byte signature. `x5chain` (33) occurs in exactly one protected or unprotected bucket and contains a leaf-first byte string or array of one to eight certificate byte strings. Its leaf and key match the externally supplied issuer certificate and key. The generic issuer-authentication primitive also retains explicit ES256 and ML-DSA-87 support for separate low-level or legacy use; v3 full-credential verification accepts neither ES256 nor ML-DSA-87 as issuerAuth.

Result classification belongs to this component. Missing or structurally invalid algorithm values are `INVALID`. RFC 9052 permits integer or text algorithm identifiers. The following finite table is recognized for a **key/algorithm mismatch**, returning `INVALID/MDOC_ISSUER_ALGORITHM_MISMATCH` when its algorithm differs from the public key's suite:

| Algorithms | COSE identifiers |
| --- | --- |
| ES384, ES512 | `-35`, `-36` |
| EdDSA, Ed25519, Ed448 | `-8`, `-19`, `-53` |
| ES256, ML-DSA-44, ML-DSA-65, ML-DSA-87 | `-7`, `-48`, `-49`, `-50` |
| ESP384, ESP512 | `-51`, `-52` |

The names and assignments were checked against the [IANA COSE Algorithms registry](https://www.iana.org/assignments/cose#algorithms), updated 2026-08-25, and RFC 9964. This is not complete coverage of that evolving registry. Other well-formed integer or text identifiers remain `UNSUPPORTED`, without guessing another algorithm's mathematics. This includes decoded CBOR integers outside JavaScript's safe-number range; their bigint representation does not make the wire value malformed.

For an implemented suite, verification uses the exact received protected bytes and payload before returning an unsupported critical-header or MSO capability. A bad available signature is `INVALID/COSE_SIGNATURE` even when those semantics are unimplemented. A critical list must be nonempty, contain unique integer/text labels and refer only to protected parameters; malformed lists are `INVALID`. Well-formed critical lists remain outside this issuer-authentication selection and return `UNSUPPORTED`. Certificate location, thumbprint and externally pinned leaf mismatches remain independently invalid. A correctly typed unknown MSO version or digest is `UNSUPPORTED`; wrong-type version/digest values in the selected MSO structure are `INVALID`. Future versions are not interpreted as version 1.0. These typed outcomes do not establish issuer authority, status or an application permission.

The complete signing base requires protected `x5t` (34) equal to `[-16, SHA-256(leaf DER)]`. The low-level issuer-authentication primitive permits absent `x5t` for separately selected presentation use, but checks it whenever present. Unknown critical headers, conflicting certificate locations and changed thumbprints fail. The holder key differs from the issuer key.

V3 requires an externally selected exact DER ML-DSA-65 trust anchor. The reference verifies its self-signature and CA flag, then every leaf-first X.509 certificate signature, issuer/subject link, ML-DSA-65 public-key type, CA role and time against that anchor. A missing anchor is `INDETERMINATE`; a substituted, classical or broken path is `INVALID`. The external issuer policy must still check complete PKIX rules, key usages, role, scope, revocation and admission. This bounded path check is not complete ISO certificate validation or an authorization grant. Identity-source roots are never imported automatically.

`inspectIssuerSigned(credential, {issuerKey, certificate, docType, allowPartial=false})` exposes authenticated mathematical and structural facts for applications that must bind other evidence before selecting an evaluation time. It retains every original-byte signature, certificate binding, item digest, schema, selected capability and internal time-order check, including `leaf.notBefore <= signed <= validFrom < validUntil <= leaf.notAfter`. It takes no evaluation time and returns no `overall`, issuer authorization, status or temporal-admission verdict. Its facts cannot establish a currently valid credential. `verifyIssuerSigned` shares the same implementation but still requires an explicit nonnegative safe-integer `at`, checks the certificate and MSO windows at that time, and never falls back to inspection. Full signing-credential verification continues to call that complete time-checked primitive.

## 4. Issuer-authenticated signing elements

The signing namespace includes the following. Additional application claims confer no base authority.

| Element | Type and rule |
| --- | --- |
| `subject_id` | 32-byte issuer-scoped opaque identifier. |
| `credential_id` | Independent random 32-byte identifier. |
| `issuer` | Nonempty exact identifier resolved by external issuer policy. |
| `signing_key` | Canonical DER SPKI; alternate encodings and trailing bytes rejected. |
| `signing_key_id` | 64-byte SHA-512 of those exact SPKI bytes. |
| `document_key_mode` | Exact externally selected mode. |
| `allowed_purposes` | Exactly `["DOCUMENT_SIGN"]`. |
| `profile_id` | Exact externally selected profile ID. |
| `status` | Exactly `{ "status_list": { "uri": tstr, "idx": uint } }`. |

V3 requires `INDEPENDENT_PQ` and a canonical ML-DSA-65/87 SPKI distinct from both the holder and issuer keys. Historical `DEVICE_KEY` and `PASSKEY_KEY` modes require explicit legacy selection and remain classical; neither is a v3 fallback. Compare canonical SPKI. Mode declarations cannot override these checks.

Key separation alone does not establish association, hardware or device support. Device-key equality does not turn a presentation-only API into document signing. Issuers verify possession and authority before certification; replacing keys requires new issuer-authenticated material.

## 5. Authorization and status interfaces

`verifySigningCredential` requires an explicit state time and synchronous, externally configured `authorizeIssuer` and `resolveStatus` callbacks. V3 additionally requires `trustAnchorCertificate`; missing decisions and unavailable evaluators fail closed. Callbacks receive copies of retained bytes; mutation cannot change the validated inputs.

The authorization request contains exact leaf/chain and selected anchor bytes, issuer ID, document type, namespace, profile, key mode, purpose, status algorithm, credential ID, `stateTime` and `knowledgeTime`. The component verifies the bounded PQ path; the resolver evaluates complete PKIX rules, explicitly admitted signing authority, role, scope, lifetime, status and applicable compromise history. Evidence cannot appoint a trust root. The result has `overall` equal to `VALID`, `INVALID`, `INDETERMINATE` or `UNSUPPORTED`; only `VALID` allows acceptance.

The status reference is an issuer-authenticated namespace item, not ISO MSO `status`. Its URI is canonical absolute HTTPS without user information or fragment; its index is a nonnegative safe integer. The v3 token is JWT with `typ=statuslist+jwt`, RFC 9964 `alg=ML-DSA-65` under the admitted DS key, `iss` and `sub` equal to the pinned URI, integer `iat` and `exp`, positive `ttl`, and binary `status_list` (`bits=1`). Maximum lifetime and age are 300 seconds. Verify the compressed list, index and a 1 MiB decompression bound. The external resolver authenticates the exact issuer/URI/index and selected key; token headers cannot change that key. It must return `algorithm=ML-DSA-65` for `GOOD`. A classical `GOOD` status claim fails even if a resolver supplies it. Other representations/methods require a future explicit profile, without fallback.

`resolveStatus` receives `{uri, idx}`, retained evidence, credential ID, certificate, selected issuer/profile/purpose/algorithm and both times. Its result is `{status, overall, algorithm?, reason?}`. `GOOD` maps to `VALID`; `REVOKED` or established inauthentic/malformed evidence (`INVALID`) to `INVALID`; `STALE`, `MISSING`, `UNKNOWN` and `CONFLICTING` to `INDETERMINATE`; recognized but unimplemented capability to `UNSUPPORTED`. Contradictory status/overall pairs are invalid. The callback is a trusted application adapter; returning an algorithm string without verifying a JWS is insufficient.

Freshness uses knowledge time, not a backdated clock. A status bit alone does not identify historical revocation-effective time or prove coverage after issuer retirement; absent historical coverage requires `UNKNOWN`. CRL/OCSP or other authenticated authority history can inform the authorization resolver without changing this credential's status wire binding.

## 6. Holder authentication

Issuer authentication alone does not prove control of the MSO device key. The bounded holder primitive accepts a complete original `IssuerSigned` credential and an exact externally selected CBOR `SessionTranscript`. It verifies the issuer signature and internal/time checks at an explicit `at`, matches the caller-selected profile ID to the signed claim, then verifies a distinct `DeviceSigned.deviceAuth.deviceSignature` with the certified ML-DSA-65 key. For v3 it always requires PQ issuer/device keys, including when historical support is enabled; classical proofs require an exact v2 profile ID plus `allowLegacyClassical=true`. Its result contains mathematical issuer facts and the holder proof, with no `overall` admission verdict. Applications still decide issuer trust, credential status, session challenge/freshness and presentation policy. A credential's identity source supplies none of those document-signing CA decisions automatically.

The selected `DeviceSigned` has exactly `nameSpaces` and `deviceAuth`. `nameSpaces` is tag-24 `DeviceNameSpacesBytes` containing an **empty** CBOR map, which the public WG10 §10.3.3 permits. A nonempty map is an unselected presentation capability (`UNSUPPORTED`), not a claim that mdoc forbids device namespace data. `deviceAuth` contains only `deviceSignature`; DeviceMAC alone is a different unselected method, while carrying both methods is structurally invalid. The v3 untagged COSE_Sign1 has protected ML-DSA-65 `alg=-49`, empty unprotected headers, null payload and a 3,309-byte signature. Extra protected headers and embedded payloads fail this base contract.

The exact detached payload is `DeviceAuthenticationBytes = #6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes])`, using the original selected transcript and the issuer-authenticated document type. Its COSE `Signature1` uses exact protected bytes, empty external AAD and that tagged payload. `prepareHolderAuthentication` returns the bytes to sign and verifies the returned signature before emitting `DeviceSigned`; `verifyHolderAuthentication` checks the original credential, selected transcript, document type and signature. The bounded reference requires a canonical three-element transcript with a non-null handover; the caller must bind a real session and prevent replay. The device authentication payload has no credential identifier or credential hash: two credentials sharing the same holder key and document type may both validate the same session proof. The application binds its selected credential and policy. A holder proof is not a signature on arbitrary document bytes.

## 7. Detached document signatures

The untagged COSE_Sign1 has an empty unprotected map and null payload. Standard `Signature1` uses exact protected bytes, empty external AAD and original detached document bytes. A DeviceMAC or presentation transcript is not this signature.

V3 protected algorithms are `-49` (ML-DSA-65) or `-50` (ML-DSA-87). ML-DSA uses pure-message signing with empty context and 3,309/4,627-byte signatures. The standalone document-signature primitive retains ES256 only for explicitly selected historical fixtures; `verifySigningCredential` never certifies a P-256 document key for v3. The protected content type is `application/certconcord-mdoc-document`.

Protected `urn:certconcord:credential:1` contains SHA-512 of the complete original credential and appears first in `crit`. Additional required critical headers are an externally supplied map of exact application values; their labels follow in canonical encoded-key order in `crit`. They cannot override algorithm, type, critical list or credential binding. Protected maps use shortest definite CBOR ordered by encoded key bytes. Unknown, missing or changed headers, including critical-list order, fail. Credential binding alone is not informed signing intent.

Missing, null, Boolean or otherwise non-integer/non-text `alg` values are `INVALID/COSE_ALGORITHM_STRUCTURE`. A well-formed unimplemented integer or text algorithm remains `UNSUPPORTED/MDOC_DOCUMENT_ALGORITHM`; no alternate algorithm is guessed. An implemented algorithm that differs from the configured key's selected suite is `INVALID/MDOC_DOCUMENT_ALGORITHM_MISMATCH`. With a matching implemented suite, the exact received protected bytes and detached document are verified first. Bad mathematics is `INVALID/MDOC_DOCUMENT_SIGNATURE`. Only then are all protected bytes compared to the selected header contract. Unknown critical headers, changed required values, noncanonical maps and a credential-last critical list are `INVALID/MDOC_DOCUMENT_PROTECTED_HEADERS`, even when their signatures are mathematically valid. These are strict policy-binding failures, not an extensible critical-header capability or a compatibility fallback.

`prepareDocumentSignature` returns the exact `tbs`; `finish` verifies native wire signature bytes before encoding. `verifyDocumentSignature` is only a cryptographic primitive. `verifySignedDocument` validates the complete credential/authorization/status before using its certified key. All signed bytes, the selected anchor and required headers are snapshotted before external callbacks.

## 8. Application extensions and maturity

Qualification, RA decisions, device admission, operation permits, transparency and operational PKIX validation are independent application requirements. Base success does not establish them. A separate PQ seal covers only its statement and cannot upgrade classical issuerAuth or DeviceAuth. Combined identity/signing credentials need original issuer authentication of both claim sets and explicit document-type permission.

Historical evaluation retains original bytes, policy and authenticated status/authority evidence. Retirement, late incidents, algorithm deadlines and archive renewal remain external lifecycle decisions; base tests do not close that entire service.

`cbor.mjs`, `key-relation.mjs`, `base.mjs` and `holder-auth.mjs` have no framework imports. `vectors/pqc-base.json` contains a complete ML-DSA certificate path, issuer credential, holder proof, detached document signature and JWS status fixture with positive and rejection outcomes. `vectors/holder-auth.json` contains v3 holder proof cases, including a mathematically valid extra-header signature and a validly signed classical DeviceSignature rejected despite the historical-support flag. `vectors/base.json` retains explicit classical v2 regression fixtures. A document COSE does not parse as DeviceSigned, and a DeviceSigned proof does not parse as this profile's detached document COSE. `vectors/manifest.json` records exact hashes. Tests use a synthetic admitted PQ root and a bounded JOSE/status adapter.

`vectors/classification.json` additionally retains classical issuer credentials and public certificate inputs for typed capability/structure regression results. ES256-good/bad pairs retain identical protected and payload bytes. An independent native mathematical check precedes each expected component result. A noncanonical protected-map order demonstrates that validation uses received bytes rather than a rebuilt header map. These vectors do not establish v3 PQ acceptance.

Integer critical labels outside JavaScript's safe-number range remain legal COSE labels. The bounded decoder accepts integer map keys through the full CBOR 64-bit argument range; shortest encoding, duplicate-key, non-integer-key and resource restrictions are unchanged. This is integer-label compatibility, not full CBOR support. The appended large-integer critical pair has an explicit per-case public certificate and identical signed message bytes: valid mathematics yields `COSE_CRITICAL_UNSUPPORTED`, while bad mathematics yields `COSE_SIGNATURE`. The original credential and certificate inputs are retained unchanged.

The five appended key-mismatch cases change only the protected algorithm identifier in the saved selected credential and retain its original signature. Their independent ES256 result is explicitly false; they do not claim valid signatures under the declared nonselected algorithms. The preceding 31 credential byte strings are unchanged.

`vectors/document-classification.json` contains independent serialized detached signatures for the two v3 document suites and the historical ES256 primitive, explicit public key inputs and exact document/credential-binding bytes. It covers malformed and unknown algorithms, implemented key mismatches, strict-header good/bad-mathematics pairs, changed document bytes and changed credential inputs. The opaque credential bytes in this primitive corpus are not issuer-authenticated credentials and establish no authority. The v3 credential/application composition is covered separately by `vectors/pqc-base.json`.

`vectors/issuer-facts.json` contains original issuer credentials with an explicit public certificate. Validly signed internal lifetime violations fail both inspection and full verification. The ordinary credential can be inspected without an external time, while full verification rejects times before or at the end of its certificate or MSO window. Existing malformed, unsupported and bad-mathematics vectors also exercise the inspection API without conferring admission.

This is one independently runnable reference, not a second independent implementation, full ISO certification, external security assessment or proof of operator independence. Its bounded codec and test JOSE adapter are not assessed production parsers. Production implementations need mature assessed CBOR/COSE/JOSE/PKIX and cryptographic stacks plus these semantics. Draft status remains until those separate stability gates are met.
