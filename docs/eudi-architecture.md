# EUDI interoperability and architectural mapping

## Scope and reference editions

This informative mapping uses the European Commission's [EUDI Wallet Architecture and Reference Framework 3.0.0](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/releases/tag/v3.0.0), released on 23 July 2026, at commit `c64f2cbb19aee37c571c58af66d359c4d5be29c8`. The reference architecture is in section 4.3; section 4.2 now contains design principles. The earlier 1.4.0 reference and its PID profile remain separately pinned for their original wire interpretation.

[FRAMEWORK draft 02](../spec/bindings/FRAMEWORK-draft-02.md) defines CertConcord's general architecture and evolution contract. This mapping applies to the `certconcord-governed-draft-02` composition defined by COMMON, DTI, DSCP, PRF-KPP and DCP. EUDI is one optional credential ecosystem. An CERTCONCORD-governed domain can use approved national credentials, Photo ID, custom mdoc rulebooks, MTC certificates, Passkeys and local or remote providers without adopting EUDI governance. Other CertConcord compositions may select different governance or issuance mechanisms. An EUDI deployment additionally selects its applicable external requirements; an architectural mapping does not confer ecosystem admission or qualified-signature status.

CertConcord's wallet roles, interfaces and trust model are defined independently of EUDI ARF. This mapping connects an explicitly selected EUDI deployment to those contracts. EUDI component names, trust infrastructure, attestation formats and certification rules do not govern unrelated CertConcord holder architectures. Shared use of mdoc or OpenID does not establish an EUDI dependency. Wallet ecosystem independence concerns this design boundary; personal wallet portability and key migration are separate capabilities.

ARF 3.0 adds or revises service registration, trust-list handling, wallet-to-wallet interactions and functional conformance assessment. Other useful distinctions below are part of the selected 3.0 architecture, not necessarily inventions of that release. The [release notes](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/releases/tag/v3.0.0) and exact chapter sources are pinned independently of protocol adapters.

## Component and authority mapping

The [reference architecture](https://eudi.dev/3.0.0/main/04-high-level-architecture/) separates the wallet application, cryptographic execution, provider backend and optional remote service. Its WSCD variants include remote, local external, local internal and local native devices. These are useful deployment categories for RRA providers; their names do not establish an assurance level for a particular implementation.

| ARF role or component                            | RRA responsibility                                                                   | Authority boundary                                                                              |
| ------------------------------------------------ | ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| Wallet Instance and optional Wallet Unit Service | Credential management, disclosure UI, protocol exchange and transaction coordination | An application or backend account does not acquire issuer or signing authority.                 |
| WSCA and WSCD                                    | Assessed key-custody and execution provider                                          | Evidence must identify the exact key, environment, algorithm and applicable operation controls. |
| Wallet Provider                                  | App/provider registration, wallet integrity and lifecycle assertions                 | Provider statements are accepted only under a declared role and evidence policy.                |
| PID or attestation provider                      | Approved identity-evidence issuer or separately appointed RRA issuer                 | Identity qualification and authority to issue signing credentials remain different roles.       |
| Relying Party, Service and Instance              | Organization, scoped service policy and authenticated runtime                        | A reader or client can request only its approved types, attributes, purposes and audiences.     |
| Signature Creation Application                   | Freeze document input, obtain consent, coordinate activation and collect evidence    | The selected provider signs the exact authorized input under DSCP.                              |
| Local QSCD or QES remote creation provider       | An externally assessed signing-provider integration                                  | RRA key or activation assurance does not itself establish QSCD or qualified status.             |
| Trusted List, LoTE and registration authorities  | Externally validated role and service-status inputs                                  | Entries do not automatically become RRA root appointments.                                      |

DTI section 4 defines these responsibilities in general terms. An MTC issuer, enterprise signing service or Passkey application applies the same boundaries without adopting EUDI component names. Software PRF vaults retain their software custody assessment; a manufacturer API name does not establish EUDI WSCD certification. The ARF also distinguishes ordinary keystores from the WSCA/WSCD required for its PID assurance and treats WSCD and QSCD certification separately.

## Service authority and external trust

[ARF chapter 3](https://eudi.dev/3.0.0/main/03-roles-within-the-eudi-wallet-ecosystem/) separates an organization from its Services and runtime Instances. Registration records associate Services with intended uses; access certificates authenticate the instance, while registration evidence describes the permitted service/use. This is useful for an organization offering, for example, both age verification and document signing: common ownership must not grant the age-verification service the signing service's authority.

RRA applies that principle through configured client/reader identity, origin, credential-purpose validation, policy hashes, audiences and transaction bindings. Display names and common hostnames convey no additional authority. Identity intake and signing activation retain separate service permissions even when one application implements both.

ARF 3.0 distinguishes Trusted Lists using ETSI TS 119 612 from Lists of Trusted Entities using ETSI TS 119 602. The roles covered by each are explicit; relying parties authenticate through the relevant access-certificate infrastructure rather than a universal list of every RP. RRA treats a selected external list as signed evidence requiring original-format validation, trusted publication authority, freshness, role/type matching and status history. Copying its keys into a local allowlist without those checks loses that evidence. Appointment as an RRA issuer still requires the governed trust-domain process.

The original records and effective suspension or invalidation times are relevant to historical signatures. A live list alone cannot reconstruct past authority. These requirements complement RRA's trust-state continuity, certificate inventory and archival evidence rather than replacing them with a current ecosystem membership lookup.

## Key Attestation, Wallet Instance Attestation and issuance

[ARF sections 6.5.3.4 and 6.5.3.5](https://eudi.dev/3.0.0/main/06-trust-model/) distinguish two evidence objects:

| Evidence                          | What its issuer asserts                                                               | What it does not establish alone                                                            |
| --------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Key Attestation (KA)              | Properties of a cryptographic environment, bound public keys and revocation reference | The person's identity, a document-signing purpose or approval for a particular document.    |
| Wallet Instance Attestation (WIA) | Wallet instance integrity, solution information and revocation status                 | Hardware custody of an unrelated document key. Its own private key need not be in the WSCD. |

The ARF presents these proofs to issuance providers, with privacy and lifecycle rules distinct from routine RP presentation. Its technical validity and revocation-maintenance periods also differ: issuance evidence may expire before the credentials it supports, while its status must remain available for the required period. Short-lived evidence is not a substitute for lifecycle continuity.

RRA's enrollment sequence remains authenticated session, fresh challenge, exact-key evidence, possession proof, RA approval and CA issuance. A deployment admitting provider-signed key evidence must separately validate the provider's authority and the claim about the proposed key. Existing Android, Apple managed ACME, TPM and PSCP admission paths do not become EUDI KA or WIA validators merely by returning equivalent application fields.

The issued credential's permitted lifetime, underlying key/provider status, revocation publication and historical retention must be reconciled before issuance. Account or wallet recovery cannot restore a revoked signing binding. Revocation of an external identity credential and revocation of a downstream RRA signing credential remain separately governed events unless the selected policy explicitly couples them.

## Credential rulebooks and version composition

[ARF chapter 5](https://eudi.dev/3.0.0/main/05-data-model-and-data-exchange-protocols/) distinguishes logical attestations, technical representations, schemes and rulebooks. An mdoc type is not limited to a driving licence: its type, namespaces, claims, authority, disclosure and lifecycle rules identify the credential's meaning. RRA applies those rules to mDL, Photo ID, PID and approved custom types without treating one family as the universal identity model.

ARF 3.0's [PID annex](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/c64f2cbb19aee37c571c58af66d359c4d5be29c8/docs/annexes/annex-3/annex-3.01-pid-rulebook.md) redirects to a separately maintained rulebook catalog. Its technical-specification pages similarly refer to another repository. Therefore, an ARF tag alone does not freeze the PID schema, certificate purposes, WIA/KA formats or every protocol option. A compatible deployment needs a composition of exact versions:

| Selection            | Required binding                                                                                                  |
| -------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Architecture         | ARF release and relevant requirement set                                                                          |
| Credential rulebook  | Immutable schema revision, `docType`, namespace/element paths, value types and issuance/disclosure rules          |
| Certificate purposes | Exact issuer and reader role profiles, trust anchors and status rules                                             |
| Wallet evidence      | Selected technical-specification revision, KA/WIA format, authorized providers and status-maintenance commitments |
| Exchange             | OpenID4VCI, OpenID4VP, HAIP, ISO and Digital Credentials API revisions actually used                              |
| Assurance            | Applicable assessment scope, algorithms, provider responsibilities and evidence                                   |

The executable `EUDI_PID_ARF_1_4` preset continues to select its original PID Document Signer and Reader purpose OIDs and original schema. It is not renamed to ARF 3.0. The general identity adapter can accept another approved rulebook, but that configuration must independently supply the complete semantics and trust policy. An architectural source pin is not an enabled wire adapter.

The selected PID example requests a purpose-specific disclosed subset. It does not validate an undisclosed complete issuance schema. Photo ID uses its own namespaces; custom types register their exact claim paths. No credential format, issuer brand or schema match supplies signing authority by itself.

## Transactional data and document signatures

ARF section 5.7.5 describes authenticating transaction-specific data through presentation mechanisms. This supports binding a wallet response to an operation's actual context. It does not remove the need to define the transaction object, user review, permitted key purpose and verification result.

RRA makes those distinctions explicit:

1. Identity presentation supplies approved facts to the RA.
2. RA approval binds a subject and admitted key to a signing profile.
3. The issuer authenticates that binding in a signer mdoc or MTC/X.509 certificate.
4. A SIM and QTB/ACB bind the document, input, purpose, service and one-use authorization.
5. The document provider creates a separately verifiable document signature and the applicable execution evidence.

The same attested DeviceKey can be certified for the explicit `DEVICE_KEY` profile, while `INDEPENDENT_PQ` uses a separate ML-DSA key and `PASSKEY_KEY` uses a separately admitted Passkey-associated key. A government issuer can issue a combined identity/signing mdoc when its rulebook permits that purpose. A downstream CA can instead perform its own RA qualification and issuance. Neither case requires pretending that ordinary mDL, PID or Photo ID presentation is an arbitrary document signature.

[ARF's qualified-signature functionality](https://eudi.dev/3.0.0/main/02-eudi-wallet-functionalities/) and Topic 16 additionally involve signature creation applications, certificate services and local or remote qualified devices/providers. In RRA, those are separately assessed provider and ecosystem properties. A native ES256 operation or PQ credential seal does not establish them.

## Passkeys, privacy and wallet-to-wallet exchange

ARF section 4.7 discusses WebAuthn/Passkeys for pseudonymous authentication. Thus wallet integration does not displace WebAuthn. The CERTCONCORD-governed composition uses WebAuthn directly for transaction activation, PRF for local protection and PSCP for explicitly certified associated document keys. Authentication under a pseudonym, certified identity and legal signature purpose remain distinct assertions.

Selective disclosure alone does not ensure unlinkability. A repeated document public key, status index, issuer signature, evidence handle or certificate can correlate transactions. ARKG can derive distinct public keys but does not remove correlation introduced by certificate claims or disclosure of derivation metadata. Per-service keys and minimized identity disclosures require explicit issuance and retention policies; they cannot be retrofitted by renaming an existing key.

ARF 3.0 also revises wallet-to-wallet interactions. RRA's transferable lesson is to authenticate the requesting peer, define its purpose, bind both sessions and obtain explicit approval. A peer being a wallet does not give it RA or CA authority. The selected OpenID/Annex C adapters retain their documented roles and transcripts; the ARF mapping does not silently enable a wallet-to-wallet protocol.

## Functional conformance and assurance

[ARF section 7.5](https://eudi.dev/3.0.0/main/07-wallet-solution-certification-and-risk-management/) introduces the Functional Conformance Assessment Framework as reusable functional test material. It is independently maintained and covers external interfaces as well as behavior that may require structured observation. It does not by itself provide the other security or operational assessments required by the ecosystem.

RRA's [conformance requirements](../spec/bindings/CONFORMANCE-draft-02.md) similarly bind each claim to the tested role, selected profile, environment and observed result. Protocol vectors, negative tests, browser behavior, native key evidence, user approval and operational custody provide different evidence. Functional tests must not be converted into a hardware or regulatory assurance claim.

## Attribution and normative relationship

The mapping is an analysis and adaptation of the European Commission's _European Digital Identity Wallet Architecture and Reference Framework_, versions 3.0.0 and 1.4.0, under [Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/). The original architecture, high-level requirements and historical PID reference remain attributed to their publishers. Exact source bytes are identified in [source-lock.json](../reference/source-lock.json).

RRA requirements arise from the core specifications and explicitly selected adapters. Ecosystem mappings explain applicability and additional integration obligations. [ECOSYSTEM.md](ecosystem.md) provides the general comparison; [WEBAUTHN-EVOLUTION.md](webauthn-evolution.md) distinguishes WebAuthn editions and signing proposals.
