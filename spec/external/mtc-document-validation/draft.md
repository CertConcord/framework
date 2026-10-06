# MTC Document Validation — draft 01

Status: independent application draft. Normative keywords describe this proposed profile, not additional requirements of the IETF MTC specification.

## 1. Problem and scope

A document may need verifiable signatures after its signing certificate expires or its issuer retires. Certificate issuance, online service availability and document retention have different lifetimes. This draft specifies the retained inputs and validation decisions for that setting. It does not change MTC certificate bytes, introduce an archive-signature object, define a CA governance hierarchy, or replace an AdES container standard.

The published MTC baseline is draft-ietf-plants-merkle-tree-certs-06. The separately pinned editor snapshot contains later identifiers and structures; a deployment MUST select an exact revision and verifier. The deployment-use-cases-01 signed-artifact analysis supplies the starting point. This draft adds a document retention horizon, authority/status history, proof closure and explicit renewal deadlines. The latest editor has already corrected the landmark row bound; that correction is not a new proposal here.

## 2. Inputs and separate conclusions

The verifier receives original document and signature bytes, an identified application profile, the validation state time, the knowledge time, and externally admitted trust and algorithm policies. Trust MUST NOT be bootstrapped from certificates, checkpoints or policy objects supplied only by the document.

The result distinguishes cryptographic integrity, certificate authorization at the relevant time, preservation continuity, and present admissibility. It records both times and missing dependencies. A historically valid result does not establish current acceptance. A later known compromise may invalidate a signature at an earlier state time according to the applicable policy.

Identity qualification, signing-key possession and authorization for the particular document are separate checks. The selected application identifies their evidence and authority. Login, identity-credential presentation, an issuance inclusion proof and a timestamp are not interchangeable evidence for these claims. This draft does not prescribe a new identity or intent object.

## 3. Retained evidence closure

For self-contained distribution, the signer SHOULD select standalone MTC representation before constructing the signature. Preserve the exact TBSCertificate, proof, extensions, leaf position, inclusion path and required signatures. Retain the corresponding issuer/operator keys, accepted membership and scope, and the policy authenticating their authority.

A relative certificate requires an explicit preservation contract for its authenticated landmark, log/range scope, epoch, policy and all proof dependencies. A live cache or issuer URL is insufficient. Archived validation MUST NOT lower a live verifier's monotonic trust watermark.

Once the signature commits to a certificate representation, its original bytes MUST remain unchanged. Converting a relative certificate to standalone form does not preserve a commitment to the original encoding. Additional independently validated evidence may be stored only under a declared supplementary binding; this draft does not allocate such a wire format.

The retained set MUST include:

- original content, signature container and certificate representation;
- issuer, cosigner, timestamp and other application-required authority evidence;
- authenticated status history, its coverage and policy decisions for both supplied times;
- required inclusion, consistency and monitoring evidence, including scope;
- time proofs, renewal chains and the evidence needed to validate their authorities.

An unavailable required dependency yields INDETERMINATE. An invalid signature, inconsistent binding or applicable revocation yields INVALID. Required evidence that is stale at the selected time cannot yield VALID. Unsupported revisions fail explicitly; trying a weaker policy is not recovery.

## 4. Time and protection lifetimes

An authenticated timestamp bounds existence, subject to TSA authority, status and stated accuracy. It does not establish the signer's intention or the exact signing instant. Declared signing time, issuance time and a log clock do not replace that evidence.

For an archive protecting one immutable data object, freeze that object before requesting its first archive timestamp. Later status and authority material may form an augmented version; it MUST NOT rewrite the original object or earlier timestamp input.

Let a timestamp have generation time g, accuracy a, and upper bound u = g + a. The entire interval MUST fit the admitted TSA lifetime and precede or equal evaluation time. Initial archive protection MUST satisfy u less than the original data protection deadline. Ordinary signer-certificate expiry alone is not that deadline.

For consecutive renewals, the previous upper bound MUST be no later than the next lower bound g - a. The next upper bound MUST precede expiry of the previous protection. At evaluation, the final protection MUST still be adequate.

Timestamp renewal preserves the current chain's data hash. Hash renewal replaces that protection and must cover the original object and preceding evidence according to the selected evidence-record format. A later timestamp under an already inadequate data hash cannot repair the intervening gap. For each old hash, the replacing chain's upper bound MUST precede its protection deadline; when no replacement exists, evaluation time MUST precede it.

The reference lifetime function operates only on already authenticated timestamp facts. It does not parse ERS, verify a TSA, or resolve historical trust. A production verifier must perform those checks before using the function.

## 5. Monitoring, retirement and archive transfer

Issuance monitoring checks issued certificates, log consistency, operator policy and equivocation under the selected MTC composition. It cannot observe arbitrary later signatures produced with an existing private key. Document-operation monitoring requires separately justified application evidence.

An archive policy MUST state the document validation horizon, responsible custodians, retrieval obligations, status/authority-history sources, algorithm review schedule and succession process. Retention cannot end solely because the signing certificate expired.

Before an issuer or archive operator retires, the successor obtains the retained closure, verifies byte identity and completeness, and records responsibility and access continuity through the deployment's existing administrative mechanism. Partial transfer must not be reported as completed preservation. Transfer does not install new trust anchors or erase earlier compromise information.

## 6. Existing container standards

| Format | Application binding |
| --- | --- |
| CAdES | Preserve exact CMS signature inputs and certificate commitments; apply the selected ETSI timestamp, validation-data and archive rules. |
| PAdES | Preserve the signed PDF revision and ByteRange; distinguish validation augmentation from content changes, and apply DSS and document-timestamp requirements. |
| JAdES | Preserve protected headers, payload mode and signature bytes; use the selected signature-timestamp and archive-timestamp coverage rules. |

The editions in sources.json remain normative for their formats. A detached ERS around an application evidence object does not by itself establish any complete AdES LT/LTA level.

## 7. Security and evidence

Adversarial cases include missing proof material, archive-supplied trust, inconsistent log scope, stale status, retrospective compromise, late renewal, hash-protection gaps, timestamp interval overlap and cross-profile substitution. Availability and privacy of historical lookups remain deployment properties.

The positive and negative cases and reference lifetime tests cover ordering and protection deadlines. Complete historical authority resolution, actual archive succession and all AdES container augmentation require additional implementation evidence. Independent adoption is possible without a particular authority hierarchy or wallet ecosystem.
