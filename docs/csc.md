# CSC 2.2 remote signing selection

The `csc-v2.2.0.0-es256` provider selects [CSC API 2.2.0.0](https://cloudsignatureconsortium.org/wp-content/uploads/2025/11/csc-api.pdf), sections 11.1, 11.7, 11.8 and 11.13, with [CSC Data Model 1.0.0](https://cloudsignatureconsortium.org/wp-content/uploads/2025/10/csc-dm.pdf), sections 5.2 and 7.6. Both sources are pinned in [source-lock.json](../reference/source-lock.json). The API path remains `/csc/v2/`.

## Selected contract

| Boundary | Requirement |
| --- | --- |
| Service discovery | `info.specs` equals `2.2.0.0`; `methods` includes `credentials/info`, `credentials/authorize` and `signatures/signHash`. Other editions require a new selection. |
| Credential | Enabled P-256 key with ECDSA-with-SHA-256; exact leaf certificate pin and matching public-key pin. A negative provider certificate status prevents use; a positive status does not replace framework trust and status validation. |
| Authorization | `auth.mode = explicit`, `SCAL = "2"`, one authorized signature. The application receives `auth.objects` and any expression through its authorization callback and obtains the required factors. The RSSP enforces its authentication policy. |
| Digest | `hashes` contains one padded Base64 SHA-256 digest of the exact provider message; `hashAlgorithmOID = 2.16.840.1.101.3.4.2.1`. The authorization and signing requests carry the same digest. |
| Factors | `authorizeCredential` accepts `authData` objects identified by the provider's object IDs. Legacy top-level `PIN` and `OTP` are rejected. The helper does not collect factors, drive challenge protocols or interpret authentication expressions. |
| Signature | `signAlgo = 1.2.840.10045.4.3.2`, `operationMode = S`, one nonempty SAD, one DER ECDSA signature. The adapter verifies the result against the retained message and certified public key. |

The stronger `SCAL = "2"` requirement is a CertConcord selection, not a claim that CSC 2.2 forbids SCAL 1. CSC's SCAL field describes the hash-to-authorization relationship; it is not evidence of full CEN SCAL 2 assurance, trusted display, non-exportability or qualified-signature status. Custody and execution assurance still require the selected [DSCP](../spec/bindings/DSCP-draft-02.md) and [EBP](../spec/bindings/EBP-draft-02.md) evidence.

The adapter accepts only HTTP 200 JSON responses. HTTP 202 authorization handles, asynchronous signing results and missing or expired activation data fail closed. It performs no automatic polling, retry, token refresh or SAD reuse. An interrupted remote operation remains subject to the gateway's unknown-result rules; transport failure is not proof that no signature was created.

## Container and intent binding

The application freezes the real container signing input before invoking the provider. For CMS/CAdES and the CMS inside PAdES this is DER signed attributes. For JAdES it is the exact JWS signing input. The digest of this message is not generally the document digest in the Signing Intent Manifest. The local provider interface accepts the original message and performs one SHA-256 digest for the remote API; it must not receive an already hashed message in its place.

The callback participates in the previously validated activation and permit flow. A service access token, SAD or successful `signHash` response alone does not establish identity qualification, informed signing intent or organizational authority. Sensitive tokens and authentication factors are transient; retained evidence commits to the operation without publishing them.

## Compatibility boundary

This is a tested client profile, not complete CSC 2.2 implementation or interoperability certification. OAuth credential authorization, multiple OAuth servers, `signDoc`, asynchronous authorization/signing, credential creation/deletion and multi-signature transactions are outside the selection. The service access token is supplied by the deployment. Explicit authorization that needs an external challenge exchange requires that exchange in the application callback before a synchronous SAD is returned.

`signDoc` would require a separate binding for provider-side document formatting and its relationship to the authorized document representation. It cannot be substituted for `signHash` after intent and activation are frozen. ES256 remains a classical compatibility suite; this profile makes no post-quantum document-signature claim.

[csc.test.mjs](../reference/csc.test.mjs) exercises the HTTP contract, certificate/key pins, capability and version rejection, authorization binding, canonical Base64, pending responses, message preservation and signature verification with a synthetic peer. Deployment acceptance additionally needs a configured external CSC 2.2 service and its authenticated credential and assurance policy.
