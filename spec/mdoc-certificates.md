# Native mdoc signing certificates — draft 02

Developing a native mdoc personal digital-certificate profile is a core CertConcord deliverable. Existing ISO mdoc mechanisms provide a possible representation and presentation foundation; the document-signing semantics require their own explicit specification. The current [DCP candidate](bindings/DCP-draft-02.md) supplies concrete experimental bindings.

## Three independent decisions

| Decision                          | Authority and effect                                                                                                                                                                                          |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Accept external identity evidence | An RA accepts selected claims from an admitted mDL, photoID, EUDI or other issuer under an identity policy. This establishes only the qualified identity claim and its assurance.                             |
| Issue a signing credential        | A CA admitted under the target trust domain binds the qualified subject to an exact document key and signing purpose. Its certificate and status/transparency evidence establish the new issuer relationship. |
| Verify a document signature       | A relying party applies its own issuer admission and operation policy to the document signature and required evidence. Successful identity presentation alone does not satisfy this decision.                 |

CC-MDOC-01: External identity validation MUST NOT automatically import its issuer into the target document-signing trust chain. Identity roots and signing issuer roots MUST be separately configurable, even if a particular deployment intentionally admits the same organization in both roles.

CC-MDOC-02: A CA, including a government CA, MAY directly issue a native signer mdoc when it implements the selected CertConcord profile and is admitted by the relying party. Direct issuance does not require an intermediary CA. Other adopting CAs MAY likewise issue native mdoc personal signing certificates.

CC-MDOC-03: A signer mdoc MUST certify the exact document key, subject, permitted signing purposes, algorithms and profile, issuer authority, validity/status and evidence requirements. A combined identity/signing mdoc MUST separately define and protect these capabilities. Neither a normal mDL nor an ordinary mdoc presentation implicitly carries these semantics.

CC-MDOC-04: The signing profile MUST define the relationship among holder/device authentication keys and document operation keys, exact signature input, user authorization, key admission, custody, lifecycle and independent verification. Same-key and separate-key designs require their own explicit rules; the framework does not decide every future design in advance.

CC-MDOC-05: Any classical, post-quantum or composite proof MUST be identified by the assertion it protects. An issuer's post-quantum seal can protect its credential commitment without upgrading the holder's classical document key. EUDI-specific qualification or legal recognition is outside the generic profile claim.

The current independent-PQ, device-key and Passkey-associated variants are experimental selections within DCP. Optional [EUDI](../docs/eudi-architecture.md) and [Apple identity](../docs/apple-identity.md) mappings must follow these boundaries. New original mdoc structures and extensions can be researched privately and proposed publicly with precise deviations, compatibility claims and test vectors.

The independent [mdoc Signing Certificates draft](external/mdoc-signing/draft.md) owns the base credential, document-signature and key-relation contract. This application additionally requires its specified qualification, device admission, PQ seal, transparency, authorization and evidence rules. Base-only acceptance does not satisfy the integrated framework.
