# Security model 1.1

## Authority boundaries

An application account is not an RA, CA, root, document signer or organization representative. The offline root only authorizes trust-policy changes under its ceremony. RAs approve bounded subjects, keys and profiles. Issuing CAs consume those approvals. Mirrors verify and retain issuance data independently. Activation services validate current authority and exact transaction intent. Providers hold separate keys and execute only authorized messages.

`SigningGateway` must exclusively control its backend credentials. When hardware does not verify RRA permits internally, the gateway and its device credentials are part of the trusted boundary. Giving another service direct sign access defeats the authorization design. A database transaction cannot prove exactly-once execution across a remote HSM: lost responses remain `UNKNOWN_EXECUTION` until reconciled.

PSCP's `PREAUTHORIZED_EVIDENCE` is a separately selected enforcement model. An ordinary activation produces a permit before the raw-signing request, and the verifier requires the certified signing key, parent assertion, raw signature and receipt. This verifies an authorized evidence package. The extension does not parse an RRA permit, and an authorized compromised origin may invoke the signing API outside that package. A stronger claim of exclusive key-use control requires a separately evaluated protected broker. Raw signatures without PSCP evidence cannot satisfy the critical binding or native mdoc evidence profile.

## Key and algorithm separation

Root, RA, issuing/cosigning CA, mirrors, status, TSA, activation, receipt, personal intentional, passive provenance, organization seal, service and encryption keys have distinct purposes. Native holder keys remain ES256 under the selected native suite. The document plane uses its declared suite: INDEPENDENT_PQ requires a separate ML-DSA key; DEVICE_KEY explicitly certifies the holder's P-256 key for ES256 document signatures; PASSKEY_KEY certifies an independently attested P-256 key associated with a device-bound WebAuthn credential. The Passkey document key differs from the parent authentication, attestation and mdoc holder keys. Issuer, RA and credential-seal keys remain distinct from subject roles. Hardware algorithm limitations must result in a capability error, not a software fallback or an ES256 signature labeled ML-DSA.

PRF outputs, private roots and capability secrets stay inside the local client boundary. A compromised authorized origin can use an unlocked PRF secret; PRF does not establish a trusted display. Account/encryption recovery must not transitively recover a signing capability. The RCG validator evaluates threshold edges and their transitive closure. Signing-key loss requires replacement enrollment and revocation where appropriate.

## Credential trust

The issuer registry, device-binding registry and status policy are authoritative. A credential-supplied URL, x5c certificate or mdoc issuerAuth cannot create a new trusted issuer. Network fetching uses bounded bodies, explicit HTTPS endpoints and origin restrictions; loopback HTTP requires explicit local development or test configuration. Host integrations must enforce egress restrictions, rate limits, authenticated sessions and authorization on every exposed application route.

A mdoc DeviceSignature proves holder-key use. A separately issued DEVICE_KEY signing profile also permits that key to create a distinct, authorized document signature; a normal presentation cannot substitute for it. Fresh UV and informed transaction consent require additional evidence. QTB binds the exact ActivationContext; replay or substitution must fail. Browser-mediated origin comes from the authenticated browser/OS boundary, not a JSON parameter from an untrusted caller. The host must recheck current binding/qualification before signing even if a credential was valid when issued.

The X.509 validator enforces the constraints listed in the selected adapter profile and rejects unsupported critical constraints. Production registries must enforce certificate revocation and ecosystem-specific authorization before admitting issuer, reader, wallet-attestation or key-attestation certificates. Mere chain membership is not authority for every role.

Hardware admission validates original attestation evidence before DeviceBinding enrollment. Manufacturer roots, patch floors, application identities and device inventory are explicit server policy. A TPM AK must be independently enrolled as a restricted signing key with fixedTPM, fixedParent and sensitiveDataOrigin properties; a general-purpose signing key can fabricate attestation-shaped messages and cannot serve as an AK. Apple App Attest and DeviceInformation evidence do not certify an unrelated application SecKey. Revoked or stale platform authority evidence blocks new activation.

PSCP validates both the parent and child attestation, exact signed algorithm and key bytes, approved authenticator model, device-bound backup state and fixed per-use UV. A child attestation cannot make an unattested parent trusted. Generation during an assertion retrieves the parent from server inventory. ARKG public derivation requires an individually scoped context and CSR possession; possession of public seed material or a ticket grants no RA authority. Binding and parent changes stop new operations before status publication. Terminal revocation cannot be downgraded to suspension, and CRL publication preserves previous and unrelated revocations.

## Parsing and resource limits

RRA controls use deterministic CBOR and explicit domains. Upstream ASN.1, COSE, JOSE, PDF and WebAuthn inputs preserve their exact signed bytes. Duplicate/ambiguous members, unknown critical headers/extensions, trailing encodings, unbounded inputs, decompression expansion and unexpected algorithms are rejected. XMLERS rejects DTD/entity expansion.

PDF structure parsing runs in a fresh worker with a three-second deadline, a 256 MiB old-generation heap limit, bounded input and aggregate CMS size, and no signing keys. A timeout or worker failure rejects the operation. CMS verification remains in the caller and binds the returned ranges to the original bytes. Worker heap limits do not bound all native or external-buffer allocations; deployments additionally apply OS process/container memory and CPU limits as required by SEP. The internal structure module is not a verification API.

The local journal uses SQLite WAL with FULL synchronization and compare-and-swap revisions. The [PostgreSQL adapter and indexed log](docs/storage.md) preserve atomic consumption, monotonic watermarks, unique operations and immutable results across service processes. Its synchronous facade belongs in a dedicated service worker. Failover fencing, synchronous replicas and restore acceptance depend on the selected deployment topology. Copying a live SQLite database without its WAL is not a recovery procedure. Backups must include durable operation and trust-state records.

## Evidence and time

Evidence hashes authenticate bytes and graph dependencies, not the truth of a source assertion. A semantic plan must validate authority, relationships, lifecycle, time and scope. Trust anchors and accepted policy are relying-party inputs; a package cannot declare itself trusted. Timestamp proof-of-existence, receipt execution time and revocation publication/effective times are distinct. Later compromise information may change a historical decision.

Public evidence must minimize personal data and exclude private keys, PRF outputs, identity-source documents, access tokens and provider credentials. Document possession and an evidence identifier do not authorize downloads. Logs should identify commitments and outcomes without exposing secrets or full credentials.

## Reporting

Submit a [private vulnerability report](https://github.com/CertConcord/framework/security/advisories/new) through GitHub Security Advisories. This sends the report to repository maintainers without creating a public issue. Include affected release/adapter, minimal synthetic reproduction, expected boundary, actual result and security impact. Use placeholders for credentials and personal evidence. Reports, remediation and coordinated disclosure remain in the private advisory until an agreed publication.

Security fixes target the current working draft on main. No stable 1.x support line is declared. Historical evidence support follows the explicitly selected binding and retention policy; draft users must review breaking changes and apply relevant fixes. A maintainer triages severity, confirms the affected boundary, coordinates a fix and records regression/retest evidence before publishing an advisory. [Assessment requirements](docs/assurance.md) and [SEP draft 03](spec/bindings/SEP-draft-03.md) define the separate independent-review and external-conformance records.
