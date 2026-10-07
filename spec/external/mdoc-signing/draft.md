# mdoc Signing Certificates - draft 02

Status: independent experimental application profile. This selects a bounded mdoc encoding and detached COSE document signature. It does not revise ISO mdoc, OpenID issuance/presentation or wallet ecosystem rules. Draft 01 did not provide this complete executable base contract.

## 1. Scope and authority

An issuer certifies a subject's document key and personal document-signing purpose in issuer-authenticated mdoc data. A relying party explicitly authorizes that issuer, role, document type and application profile. An admitted government or other CA may issue this profile. Acceptance of an external mDL/photoID during enrollment does not appoint that identity issuer as a document-signing CA or import its roots into another CA's chain.

The complete base profile is `MDOC-SIGNING-PERSON-PQ-v2`: a P-256 holder key and a distinct ML-DSA-65 or ML-DSA-87 document key, carried in document type and signing namespace `org.certconcord.signer.1`. Ordinary WebAuthn may authorize the separate document key in an application. Raw signing is optional; presentation does not prove an arbitrary document signature.

Optional profiles `MDOC-SIGNING-PERSON-DEVICE-v2` and `MDOC-SIGNING-PERSON-ASSOCIATED-v2` select `DEVICE_KEY` and `PASSKEY_KEY`. Applications may select their own exact profile ID, document type, namespace and expected key mode as external verification parameters, while enforcing their additional admission and operation rules. Credential claims cannot select trusted policy.

Organizational seals, encryption and legal qualification are outside this personal baseline. Its purpose is exactly `DOCUMENT_SIGN`; changing a string cannot create another capability.

## 2. Standards and development baselines

The published background edition is **ISO/IEC 18013-5:2021, edition 1, September 2021**. The ISO catalog identifies it as published and separately lists a DIS successor under development. The full licensed 2021 text has not been checked in this work. Public metadata and Multipaz code do not establish ISO conformance; production implementers need the normative text and relevant certificate-profile assessment.

The separately tracked public WG10 text is the September 14, 2025 CD-ballot-resolution document at commit `b250e7a64f99e22ceed10d2a5799bed38ee89f85`, blob `70af94f67df47e6d35ac5b055201892688c1c11a`. Its cover places it before a DIS ballot. It is neither the published 2021 edition nor evidence of the latest DIS text. Its certificate-binding and revocation sections were reviewed; hashes are in `sources.json`. The copyright-protected PDF is referenced, not redistributed.

That working text's sections 12.3.4 and 12.3.6 discuss protected certificate thumbprints and optional MSO revocation using identifier-list or status-list mechanisms, with COSE/CWT revocation lists and a reference to Token Status List draft 12. This component instead selects the application namespace/JWT binding in section 5 against Token Status List draft 21. Location, token representation and delegated status-authority rules differ. No automatic conversion, dual runtime or second-edition conformity is claimed.

Certificate binding uses existing RFC 9360 `x5t`, avoiding a new certificate-digest extension. It is an explicit application requirement here even where the working text recommends it. Document-to-credential binding separately commits to the complete original credential, not just its issuer certificate.

## 3. Credential and issuer authentication

The credential is a complete encoded `IssuerSigned` map with exactly `nameSpaces` and `issuerAuth`. The reference accepts definite-length CBOR, shortest integer/length encodings, no duplicate map keys, depth below 32, at most 100,000 items and at most 8 MiB. Keys are text or safe integers. Values use integers, strings, byte strings, booleans, null, arrays, maps and the selected tags. Floating point and indefinite lengths are outside this base.

Each namespace contains nonempty tag-24 embedded issuer items. Each item has exactly `digestID` (nonnegative safe integer), `random` (at least 16 bytes), `elementIdentifier` (nonempty text) and `elementValue`. Repeated disclosed salts, duplicate names or digest IDs are rejected. SHA-256 covers the exact encoded tag-24 item, including its wrapper; re-encoding embedded contents is not equivalent. A signing credential contains every namespace and item named by the MSO. Partial disclosure is an explicitly selected low-level presentation capability, insufficient for the signing base.

The MSO selects version `1.0`, digest `SHA-256`, exact `docType`, nonempty `valueDigests`, and `deviceKeyInfo` containing only a P-256 COSE `deviceKey`. `validityInfo` contains valid tag-0 UTC dates with whole seconds and `Z`, satisfying `leaf.notBefore <= signed <= validFrom < validUntil <= leaf.notAfter` and `validFrom <= stateTime < validUntil`. Optional `expectedUpdate` lies between `signed` and `validUntil`. Unknown versions/digests are unsupported. The full signing base rejects MSO `status` as an unselected capability.

`issuerAuth` is untagged COSE_Sign1 over the encoded tag-24 `MobileSecurityObjectBytes`, using empty external AAD. Protected `alg=-7` selects ES256/P-256 with a 64-byte `r || s` signature. `x5chain` (33) occurs in exactly one protected or unprotected bucket and contains a leaf-first byte string or array of one to eight certificate byte strings. Its leaf and key match the externally supplied issuer certificate and key.

The complete signing base requires protected `x5t` (34) equal to `[-16, SHA-256(leaf DER)]`. The low-level issuer-authentication primitive permits absent `x5t` for separately selected presentation use, but checks it whenever present. Unknown critical headers, conflicting certificate locations and changed thumbprints fail. The holder key differs from the issuer key.

Node X.509/crypto parses the certificate and checks its exact bytes, key, time and signature. This is not complete ISO certificate validation or role admission. The external interface below supplies path/role/status decisions. A credential-carried certificate or equality pin is not by itself an authorization grant.

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

`INDEPENDENT_PQ` requires ML-DSA-65/87 distinct from the holder key. `DEVICE_KEY` requires P-256 equal to the holder key. `PASSKEY_KEY` requires P-256 distinct from the holder key. Compare canonical SPKI; the document key also differs from the issuer key. Mode declarations cannot override these checks.

Optional associated-key use additionally requires application admission of the parent association and separation from authentication/attestation keys. Base key separation alone does not establish association, hardware or device support. Device-key equality does not turn a presentation-only API into document signing. Issuers verify possession and authority before certification; replacing keys requires new issuer-authenticated material.

## 5. Authorization and status interfaces

`verifySigningCredential` requires synchronous, externally configured `authorizeIssuer` and `resolveStatus` callbacks. Missing decisions and unavailable evaluators fail closed. Callbacks receive copies of retained bytes; mutation cannot change the validated inputs.

The authorization request contains exact leaf/chain bytes, issuer ID, document type, namespace, profile, key mode, purpose, credential ID, `stateTime` and `knowledgeTime`. The resolver evaluates an authenticated path or explicitly admitted key anchor, role, scope, lifetime, status and applicable compromise history. A raw-key anchor needs its own selected lifecycle. Evidence cannot appoint a trust root. The result has `overall` equal to `VALID`, `INVALID`, `INDETERMINATE` or `UNSUPPORTED`; only `VALID` allows acceptance.

The status reference is an issuer-authenticated namespace item, not ISO MSO `status`. Its URI is canonical absolute HTTPS without user information or fragment; its index is a nonnegative safe integer. The selected token is JWT with `typ=statuslist+jwt`, ES256 under the admitted DS key, `iss` and `sub` equal to the pinned URI, integer `iat` and `exp`, positive `ttl`, and binary `status_list` (`bits=1`). Maximum lifetime and age are 300 seconds. Verify the compressed list, index and a 1 MiB decompression bound. The external resolver authenticates the exact issuer/URI/index; token headers cannot change the selected key. Other representations/methods require a future explicit profile, without fallback.

`resolveStatus` receives `{uri, idx}`, retained evidence, credential ID, certificate, selected issuer/profile/purpose and both times. Its result is `{status, overall, reason?}`. `GOOD` maps to `VALID`; `REVOKED` or established inauthentic/malformed evidence (`INVALID`) to `INVALID`; `STALE`, `MISSING`, `UNKNOWN` and `CONFLICTING` to `INDETERMINATE`; recognized but unimplemented capability to `UNSUPPORTED`. Contradictory status/overall pairs are invalid.

Freshness uses knowledge time, not a backdated clock. A status bit alone does not identify historical revocation-effective time or prove coverage after issuer retirement; absent historical coverage requires `UNKNOWN`. CRL/OCSP or other authenticated authority history can inform the authorization resolver without changing this credential's status wire binding.

## 6. Detached document signatures

The untagged COSE_Sign1 has an empty unprotected map and null payload. Standard `Signature1` uses exact protected bytes, empty external AAD and original detached document bytes. A DeviceMAC or presentation transcript is not this signature.

Protected algorithms are `-49` (ML-DSA-65), `-50` (ML-DSA-87) or `-7` (selected P-256). ML-DSA uses pure-message signing with empty context and 3,309/4,627-byte signatures. ES256 uses SHA-256 and 64-byte `r || s`. The protected content type is `application/certconcord-mdoc-document`.

Protected `urn:certconcord:credential:1` contains SHA-512 of the complete original credential and appears first in `crit`. Additional required critical headers are an externally supplied ordered map of exact application values; their labels follow in `crit`. They cannot override algorithm, type, critical list or credential binding. Protected maps use shortest definite CBOR ordered by encoded key bytes. Unknown, missing or changed headers, including critical-list order, fail. Credential binding alone is not informed signing intent.

`prepareDocumentSignature` returns the exact `tbs`; `finish` verifies native wire signature bytes before encoding. DER ECDSA providers convert explicitly at their boundary. `verifyDocumentSignature` is only a cryptographic primitive. `verifySignedDocument` validates the complete credential/authorization/status before using its certified key. All signed bytes and required headers are snapshotted before external callbacks.

## 7. Application extensions and maturity

Qualification, RA decisions, device admission, operation permits, PQ issuer seals and transparency are independent application requirements. Base success does not establish them. A PQ seal covers only its statement and cannot make ES256 holder/document proofs post-quantum. Combined identity/signing credentials need original issuer authentication of both claim sets and explicit document-type permission.

Historical evaluation retains original bytes, policy and authenticated status/authority evidence. Retirement, late incidents, algorithm deadlines and archive renewal remain external lifecycle decisions; base tests do not close that entire service.

`cbor.mjs`, `key-relation.mjs` and `base.mjs` have no framework imports. `vectors/base.json` contains complete credentials, certificates, document signatures, documents and signed JWT status fixtures with expected decisions. Negative cases include validly re-signed semantic violations. `vectors/manifest.json` records SHA-256 hashes. Tests use an independently configured synthetic issuer policy and status adapter.

This is one independently runnable reference, not a second independent implementation, full ISO certification, external security assessment or proof of operator independence. Its bounded codec and test JOSE adapter are not assessed production parsers. Production implementations need mature assessed CBOR/COSE/JOSE/PKIX and cryptographic stacks plus these semantics. Draft status remains until those separate stability gates are met.
