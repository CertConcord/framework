# mdoc Signing Certificates — draft 01

Status: independent experimental application profile. This draft uses issuer-authenticated mdoc data and existing COSE signatures; it does not revise ISO mdoc, OpenID issuance/presentation protocols or wallet ecosystem rules.

## 1. Scope and authority

An issuer can certify a subject's document key and permitted purpose using mdoc. A relying party explicitly authorizes that issuer for this signing profile. Acceptance of a government identity credential during enrollment does not make its issuer a signing trust anchor or cross-certify another CA.

A government or other CA may issue the signing profile directly when authorized to do so. A combined identity/signing credential requires the original issuer to authenticate both sets of claims and the relevant ecosystem to permit that use. A holder cannot append signing authority to an already issued identity credential.

The first profile covers personal document signatures. Organizational seals, encryption, additional algorithms and legal qualification require their own explicitly defined profiles and evidence; changing a purpose string does not implement them.

## 2. Credential contract

The experimental standalone document type and signing namespace are org.certconcord.signer.1. A combined credential may retain its original document type only when the relying party explicitly permits that type and issuer for signing. The namespace is available to independent issuers; the name grants no trust.

IssuerAuth authenticates the MSO and its item digests using the selected ISO issuer-authentication rules. Production implementations need the applicable normative ISO edition. The pinned Multipaz files are implementation cross-checks and do not substitute for that standard.

The following signing elements MUST be issuer-authenticated:

| Element | Contract |
| --- | --- |
| subject_id | Opaque 32-byte subject identifier scoped by the issuer and declared identity policy. |
| credential_id | Independent random 32-byte credential identifier. |
| issuer | Exact identifier resolved under the relying party's accepted issuer policy. |
| signing_key | Exact DER SubjectPublicKeyInfo for the document key. |
| signing_key_id | SHA-512 of those SPKI bytes; the original bytes remain available. |
| document_key_mode | INDEPENDENT_PQ, DEVICE_KEY or PASSKEY_KEY. |
| allowed_purposes | Explicit list containing DOCUMENT_SIGN for this profile. |
| profile_id | Exact selected algorithm, purpose and application-profile identifier. |
| status | Status method, issuer-pinned location and credential identifier/index, with coverage specified by that method. |

Validity comes from the authenticated MSO and any narrower selected profile limits. Subject identifiers do not establish identity assurance by themselves. A qualification extension must identify the actual assessed process and its limits.

The MSO DeviceKey is a public holder-authentication key. It is not an issuer key, private key or substitute for a separately certified document key. Holder-authenticated deviceSigned values cannot add issuer-certified authority.

## 3. Key relationships

For INDEPENDENT_PQ, the document key is ML-DSA-65 or ML-DSA-87 and is distinct from the holder key. For DEVICE_KEY, the document key is P-256 and equals the MSO holder key. That equality authorizes a separate document-signing operation only when expressly certified; an ISO presentation-only API is insufficient.

For PASSKEY_KEY, the P-256 document key is distinct from the holder key. The selected associated-key profile additionally proves its association to, and separation from, the parent authentication and attestation keys. This optional mode depends on experimental upstream and device capabilities and is not required by the other modes.

Compare normalized SPKI public keys rather than aliases. Issuance checks possession of each subject key and separation from issuer/authority keys. Hardware provenance, fresh user verification and informed consent are distinct properties requiring their own evidence.

The reference key-relation function enforces the algorithm and holder/document equality rules. It does not verify issuer authentication, parent-Passkey admission, identity or hardware evidence.

## 4. Document signature contract

An application signs actual document-container input using the certified document key. Holder presentation and document signing are distinct operations. A DeviceMAC is not a publicly transferable document signature.

For the detached COSE binding, use COSE_Sign1 with an empty external AAD and the original document bytes as the detached payload. Its signed structure is the standard Signature1 structure with the exact protected-header bytes. The serialized signature has a null payload and an empty unprotected map.

The protected algorithm is -49 for ML-DSA-65, -50 for ML-DSA-87, or -7 for the selected P-256/ES256 mode. These values retain their existing registered meaning. ES256 signature bytes are fixed-width r followed by s. The protected content type is application/certconcord-mdoc-document.

The protected text label urn:certconcord:credential:1 contains SHA-512 of the complete original encoded credential and appears in the critical-header list. A selected application may require additional protected critical fields for intent, policy or context; it MUST define their exact bytes and verification rules. Unknown critical fields are rejected. A certificate digest alone does not bind signing intent.

Verification authenticates the issuer and credential first, validates purpose, lifetime, status, key mode and all selected critical fields, then verifies the signature with the certified key over the exact container input. An omitted credential, changed representation, unsupported algorithm, mismatched key or invalid status cannot yield a successful result.

## 5. Application extensions and lifecycle

This base profile does not mandate an RA authorization hash, device registry, operation permit, post-quantum seal or transparency log. Applications can impose those extensions with explicit scope and failure rules. Such an application must not advertise a base-only verifier as sufficient.

A separate PQ seal must identify its authorized issuer, original credential commitment, certified key and covered extensions. It strengthens only the statements it authenticates; it does not make ES256 holder or document signatures post-quantum. A transparency extension separately establishes issuance inclusion and monitoring policy.

Replacing either certified key requires new issuer-authenticated credential material. A presentation or registry edit cannot modify a previously authenticated MSO. Revocation, status publication, historical knowledge time and loss/recovery rules are part of the selected application. Historical signatures keep their original key and credential bytes.

## 6. Security and maturity

Reject credential substitution, mixed issuer chains, self-selected trust anchors, public-key aliases resolving to different keys, unsupported critical fields, purpose escalation and key-mode downgrade. Disclosure and document signing can create separate correlation handles; minimize unnecessary identifiers.

The extracted reference and cases cover key relationships. The complete CertConcord application adds issuer validation, qualification, status, intent and operation evidence. Those integrated tests are evidence for that application, not a second independent implementation or complete ISO conformance evaluation.
