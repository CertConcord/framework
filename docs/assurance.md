# Security assessment and interoperability

[SEP draft 03](../spec/bindings/SEP-draft-03.md) binds assurance work to the core authority and evidence model. Each result belongs to an exact source revision, role, configuration and environment.

## Independent cryptographic review package

An assessment covers the following boundaries and attack questions:

| Boundary                              | Review focus                                                                                                          | Reproduction material                                                                      |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| CBOR, DER, ISO CBOR and JSON          | Ambiguity, resource use, signed-byte preservation, schema composition                                                 | `core.mjs`, `cose.mjs`, `json.mjs`, `fuzz/`                                                |
| RA, CA and MTC                        | Scope substitution, allocation atomicity, quorum/fork assumptions, log migration                                      | `enrollment.mjs`, `issuance.mjs`, `mtc.mjs`, `transparency.mjs`, `storage/`                |
| WebAuthn, PRF and PSCP                | Origin/RP binding, backup state, exact child-key admission, preauthorization, parent lifecycle, derivation separation | `webauthn.mjs`, `protection.mjs`, `raw-signing.mjs`, `arkg.mjs`, `passkey-credentials.mjs` |
| mdoc, COSE/JOSE and hardware evidence | Device/issuer/document-key separation, exact transcripts, typed identity admission, manufacturer-policy assumptions   | `mdoc.mjs`, `signer-mdoc.mjs`, `openid.mjs`, `key-attestation.mjs`                         |
| CMS, PDF, KEM and archives            | Algorithm binding, container coverage, recipient/AEAD integrity, time and status semantics                            | `pki.mjs`, `pdf.mjs`, `protection.mjs`, `archive.mjs`, `evidence.mjs`                      |
| Runtime and distribution              | Compromise containment, provider exclusivity, dependency reachability, SBOM/provenance, recovery/failover             | `SECURITY.md`, `STORAGE.md`, `sdk/`, `.github/workflows/`                                  |

The review record identifies reviewers and independence, artifact and policy digests, included/excluded code paths, attack model, proof obligations, discovered counterexamples, severity, remediation commits and independent retests. Review of algorithm selection does not cover side channels or implementation correctness unless those are explicitly tested. Hardware claims require exact devices/firmware, enrolled manufacturer roots and original attestation artifacts.

The release manifest, dependency lock, SDK build metadata, synthetic corpora and benchmark raw samples constitute the reproducible input package. Reviews should test both successful and adversarial traces, including revocation learned after signing, inconsistent mirrors, concurrent admission/revocation and loss of a provider response.

## External test environments

[OpenID Foundation conformance testing](https://openid.net/certification/) provides a natural external environment for the selected issuance and presentation adapters. The [suite revision and plan mapping](../reference/interop/profiles.json) pin test-plan source independently of the protocol source locks. HAIP selection must satisfy its complete applicable algorithm, transport, client authentication and format requirements; supporting one OpenID endpoint is insufficient. A hosted run uses controlled synthetic identities and explicitly registered issuer/verifier/wallet clients.

The pinned non-HAIP VCI wallet plan is marked alpha by its upstream publisher and directs certification users to the HAIP wallet plan. The existence of a test plan, a completed test execution and eligibility for a certification program are separate facts. Record the selected plan, format variants and applicable program rules with the result.

[EUDI FCAF](https://conformance.eudi.dev/latest/) provides a complementary framework with explicit SUT roles, test classes and maturity stages. Its current structure starts with Wallet Solution and includes relying-party, attestation-provider, PID-provider, infrastructure and UI test classes. A selected FCAF revision and the applicable ICS must be recorded independently of ARF 3.0.0. RRA deployments outside that ecosystem retain the same core requirements and choose their own rulebook.

`node interop/import-result.mjs record.json artifacts/` validates the result record and original artifact digests before importing it. The importer performs no enrollment, external submission or certification. Artifact files must be regular files inside the declared directory, with bounded size. The record includes `LOCAL_ADAPTER`, `EXTERNAL_EXECUTION`, `INDEPENDENT_REVIEW` or `CERTIFICATION` and the issuing assessor; these categories must not be inferred from test names.

## CI evidence

Protocol/native acceptance validates the selected exchanges and build targets. Security assurance runs dependency auditing, SDK clean-install/API checks, PostgreSQL process tests, coverage-guided fuzzing and SBOM generation. CodeQL analyzes JavaScript, workflows, Kotlin and Swift. Release jobs bind SDK tarballs to source and CycloneDX evidence using GitHub artifact attestations. All artifacts must be interpreted with their workflow, revision and actual conclusion.
