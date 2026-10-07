# Selected CAdES preservation profile

This adapter implements a bounded standard CMS preservation path using the published [ETSI EN 319 122-1 V1.3.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf). Its requested levels are CAdES-B-B, B-T, B-LT and B-LTA, represented in the API as `B`, `T`, `LT` and `LTA`. A level is a validation result under the caller's external policy. An attribute's presence alone does not establish a level.

The selected profile uses one SignerInfo identified by issuer and serial number, DER CMS SignedData, `id-data`, attached or explicitly supplied detached content, and P-256/SHA-256 document signatures. Certificates, direct CRLs and RFC 3161 timestamp signatures use the same selected signature suite. Timestamp imprints may use SHA-256 or SHA-512. Trust paths contain one leaf and one explicitly trusted self-signed root. This is a finite-horizon classical profile, without a post-quantum preservation claim.

The existing [draft-03 CMS and ECP composition](../spec/bindings/DOCUMENT-draft-03.md) keeps its original verifier and exact byte interpretation. The new adapter accepts bare CMS, creates no CertConcord archive wrapper and defines no new cryptographic domain. It does not establish identity qualification, consent, an organizational grant or the original ECP's authorization verdict.

Import these APIs directly from `reference/cades.mjs`. The packaged `createVerifier` SDK exposes the CMS/MDOC ECP plans; the bare-CMS adapter has its own policy and result contract.

## Creation and augmentation

`prepareCAdESSignature` takes `content`, the signer `certificate`, additional `certificates`, `signingTime`, optional `detached`, and the selected `algorithmProfile`. Its `tbs` is the CMS signed-attribute SET input. `finish(signature)` verifies the supplied signature before returning CMS. The required signed attributes are created before signing: content type, content digest, signing time and SigningCertificateV2. The certificate binding hashes the complete certificate, so another certificate containing the same public key cannot replace it.

The minimal API does not infer a media type from opaque content. A caller should supply a known media type using the recommended standard MIME attribute through `additionalSignedAttributes`, or explicitly select the opaque-content exception. Omitting that recommendation alone is not an invalid signature. If CMS algorithm protection is supplied, its digest and signature algorithm must match the actual SignerInfo; a MAC choice is not accepted in this signature profile.

Self-claimed signing time is not trusted proof of existence. Missing required signed fields cannot be repaired by adding unsigned attributes. All certificates actually used to validate the signer, including the selected root, must be embedded already at B. An embedded root remains data; external trust policy selects the anchor.

`prepareCAdESAugmentation(cms, options)` takes the target level, detached content when needed, `validationMaterial: {certificates, crls}`, the external `policy` and timestamp request options. For T and LTA it returns the exact `requestDER`, `imprint` and `hashOID`. The caller obtains the timestamp externally, then calls `finish(token, {validationTime, knowledgeTime, policy?})`. LT needs no new timestamp. Finish revalidates with explicit current times and can consume an updated complete policy after the external operation. Preparation snapshots the input bytes; later mutation cannot change the signed or timestamped object.

The adapter performs no network request, durable publication or scheduling. A service must retain the exact request and uncertain response state when composing this API with durable storage. Reissuing an uncertain request does not prove that the earlier operation failed.

## Level dependencies

| Level | Required validated dependencies                                                                                                                                      |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B     | Exact content digest and document signature, mandatory signed attributes, signer certificate binding, embedded certificate path and external authority/status policy |
| T     | B plus a trusted signature timestamp over the raw signature value, with a conservative existence bound before signer expiry or applicable revocation                 |
| LT    | T plus the required signer and timestamp certificate/status material in standard SignedData fields                                                                   |
| LTA   | LT plus archive-time-stamp-v3, its verified ATSHashIndexV3 and continuous protection through the evaluation time                                                     |

LT material must close the dependencies of both the document signer and the timestamp signers. Only collecting the document signer's chain is insufficient. Current external material may authenticate the newest timestamp but does not count as embedded LT material or as something protected by an older archive timestamp.

## Archive byte contract

The selected route uses archive-time-stamp-v3 (`0.4.0.1733.2.4`) and ATSHashIndexV3 (`0.4.0.19122.1.5`). Each archive attribute has one token value. Renewals use separate attributes with the same archive OID. The index belongs to the timestamp token's SignerInfo unsigned attributes.

Each index contains the selected hash identifier and hashes of complete certificate choices, complete revocation choices, and each preexisting unsigned attribute value paired with its attribute-type OID. The new timestamp itself is excluded. Prior timestamps are included. Index order follows the source collections for generation; verification resolves exact referenced objects rather than inferring chronology from DER SET order.

The archive imprint hashes, in sequence: the encoded content-type OID; the content hash under the archive hash; the original SignerInfo version, signer identifier, digest algorithm, stored signed-attributes field, signature algorithm and signature field; and the encoded index. The stored signed-attributes field retains its context-specific tag here. The document signature's input uses the CMS SET tag instead. A SHA-512 renewal recomputes the content hash under SHA-512 even when the original document digest was SHA-256.

Removal or replacement of indexed bytes invalidates that proof. Later additions do not invalidate an older index or retroactively become protected by it. This selected profile requires protection of the current material set to report LTA; otherwise the missing augmentation proof is indeterminate at LTA while any established lower level remains distinguishable. Every renewal must preserve the original signed core and all earlier protected objects. Verification checks every layer, including original index resolution and the exact standard imprint.

## Authority, status and time

The caller supplies `validationTime`, the actual `knowledgeTime` and this external policy:

| Field                | Meaning                                                                                           |
| -------------------- | ------------------------------------------------------------------------------------------------- |
| `trustedRoots`       | Exact DER anchors admitted outside the container                                                  |
| `scope`              | External trust domain, issuer identity, `X509` representation and optional profile                |
| `authorityResolver`  | Shared synchronous role resolver, including applicable later-known incidents                      |
| `timestampPolicies`  | Accepted RFC 3161 policy OIDs                                                                     |
| `algorithmDeadlines` | Finite exclusive protection cutoffs by signature algorithm OID                                    |
| `hashDeadlines`      | Finite exclusive protection cutoffs by hash OID                                                   |
| `keyDeadlines`       | Finite exclusive cutoffs keyed by `core.keyID(publicKey)` in hexadecimal                          |
| `currentMaterial`    | Optional external DER certificates and CRLs for current authentication and later-known revocation |

The root is resolved as ISSUER, the CRL signer as STATUS_AUTHORITY at CRL publication time, and a timestamp signer as TIMESTAMP_AUTHORITY at its time interval. No role is inferred merely from possession of a certificate. The same knowledge time reaches these decisions, including when an earlier artifact state is being evaluated.

`validationTime` can select a historical signature evaluation time; `knowledgeTime` records the actual evidence and incident knowledge used now. A signature timestamp must establish existence by `validationTime`. A later archive proof may arrive after that historical time, provided it is known by `knowledgeTime` and protects the earlier layer before its cutoff. The reported level describes the evidence validated with current knowledge; it does not claim that every augmentation already existed at the historical evaluation time.

The selected CRL profile is v2, full, direct and root-signed, with a matching authority key identifier, root subject key identifier, CRL number and nextUpdate. Delta, indirect and partitioned CRLs are outside this profile. A CRL issued after the target certificate expired cannot prove an absent serial was still good: the initial implementation does not implement expired-certificate retention declarations. Authenticated applicable revocations remain relevant even when that CRL cannot supply positive freshness evidence.

Historical freshness requires a later authenticated archive proof over the exact certificates and CRLs used for that decision. A self-claimed publication date or signing time cannot supply that proof. `knownCRLs` gives the material helper all later-known container CRLs for revocation evaluation; it does not enlarge the historical positive material set. An archive timestamp cannot establish the authenticity of its own otherwise unprotected validation inputs. The newest archive layer needs currently admissible external authority and fresh status evidence.

These authenticity rules also apply to negative CRL entries. Exact historical CRL bytes need proof before the root key/signature/hash cutoff; other CRLs need current cryptographic acceptability at knowledge time. A claimed old thisUpdate value does not authenticate a newly found CRL after that cutoff. Such unproven revocation knowledge is indeterminate, not an established certificate revocation.

Timestamp accuracy must be present. Absent accuracy is indeterminate in this profile, and is never interpreted as zero. The full conservative interval must fit the applicable certificate and authority conditions. The initial signature proof and every later archive proof must arrive before the relevant protection cutoff; equality fails. The final unprotected layer must remain cryptographically admissible at `knowledgeTime`, including a bare B signature when no trusted timestamp exists. Choosing an earlier `validationTime` cannot authenticate a token after its key, signature or hash protection is lost. A newly created token cannot repair an interval already lost to a cutoff.

Timestamp generation times have at most millisecond fractional precision in this implementation. A present TSA GeneralName must be a directoryName matching the actual timestamp certificate subject; other name forms are unsupported. Signature signingTime uses the CMS-required UTCTime form for years 1950 through 2049.

Ordinary certificate expiry limits new certificate use; it is not by itself the protection deadline of an already preserved signature. Conversely, a later-known key compromise cannot be defeated by presenting a token with a conveniently old claimed generation time. Key cutoffs are authenticated external policy at the actual knowledge time and constrain when a successor proof had to be obtained.

Without trusted signature proof of existence, a certificate or root that is outside its validity interval at evaluation leaves the claimed signing time unresolved, so the result is indeterminate. This does not hide an invalid signature, an authenticated applicable revocation or a lost key-protection interval.

## Results and unsupported input

`verifyCAdES` takes `minimumLevel` and returns an overall typed result, reason and requested/verified level information. Established malformed encoding, bad bindings, invalid signatures, indexed-byte changes and applicable revocation are INVALID. Recognized unselected capabilities are UNSUPPORTED. Missing mandatory evidence, insufficient knowledge, missing policy, absent timestamp accuracy and stale status are INDETERMINATE. INVALID takes precedence over UNSUPPORTED, which takes precedence over INDETERMINATE; every non-VALID result prevents acceptance.

The initial profile does not implement multiple document signers, subject-key-identifier SignerInfo selection, BER, intermediate or delegated paths, OCSP, additional signature suites, legacy certificate/revocation value and reference attributes, countersignatures or certified-attribute assertions. Its DER parser rejects noncanonical and indefinite-length encodings as malformed; it does not independently determine whether rejected input would be valid under BER. These boundaries must not trigger a retry with weaker rules. The optional `originalCMS` input checks exact signed-core and effective-content continuity with an original CMS object, including retention of every original unsigned attribute value; its acceptance does not import any separate authorization result.

The [detached preservation path](document-preservation.md) archives the complete original ECP and CMS bytes. Adding unsigned CMS data changes that original leaf's whole-object hash. Preserve and verify the original ECP separately; replacing its CMS leaf with augmented CMS while reusing the old document timestamp is invalid.

## Standards and assurance boundaries

The source selection uses EN 319 122-1 V1.3.1 for CAdES and [EN 319 102-1 V1.4.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf) for the reviewed validation process. The direct-root helper does not implement the latter's complete path building, constraint set or validation-report schema. [TS 119 312 V2.1.1](https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/02.01.01_60/ts_119312v020101p.pdf) informs suite selection; this P-256-only verifier does not claim support for all algorithms in its tables. SHA-512 imprints do not make classical timestamp signatures post-quantum safe. Deadline values are external assessments, not invented ETSI migration dates.

[TS 119 122-3 V1.2.1](https://www.etsi.org/deliver/etsi_ts/119100_119199/11912203/01.02.01_60/ts_11912203v010201p.pdf) defines a separate CAdES evidence-record route. That route preserves original ContentInfo encoding and has different mutation rules. Neither standalone ERS nor its internal/external evidence-record attributes substitute for the ATSv3 baseline path implemented here. The selected API reports those attributes as unsupported.

The official published versions were rechecked on 2026-10-07. ETSI work items also showed development versions EN 319 102-1 V1.4.2 and TS 119 312 V2.1.2. Their document downloads required login, so no unseen clause changes are asserted or selected. Exact published source digests are retained in [source-lock.json](../reference/source-lock.json).

Independent OpenSSL parsing and signature verification cover the selected CMS, certificate and timestamp primitives. Independently encoded archive-index vectors test byte-level construction. These checks do not establish an independent complete CAdES preservation implementation, production parser assurance, operational TSA clock/custody quality, legal qualification, QES/QTSP status or PAdES conformance. The repository retains working-draft status and the [stability gates](../spec/conformance.md).
