# CertConcord Document Trust Infrastructure — draft 02

> Candidate binding for CertConcord draft 02. This is a working draft, not a final standard. Its requirements apply only when this binding is selected. The [draft architecture](../architecture.md) defines framework scope; the [profile catalog](../profiles.md) records applicability. The draft 02 namespace and wire domain identify experimental formats. Object schema numbers describe field layouts and do not indicate a stable edition.

**CertConcord**

Status: draft 02. Normative language: English. COMMON-draft-02 is an integral normative part of this specification.

## 1. Scope

DTI defines the infrastructure of the `certconcord-governed-draft-02` composition: governed identity qualification, transparent credential issuance, intentional document signatures, organizational seals, encryption and independent historical validation. [FRAMEWORK draft 02](FRAMEWORK-draft-02.md) defines CertConcord's broader architecture, including successors to current issuance/transparency mechanisms, evolving protocols and wallet ecosystem independence. A better architecture may replace MTC through a breaking upgrade. Holder interfaces and trust relationships are defined independently of EUDI, whose requirements belong to an optional ecosystem mapping. DTI's offline-root/RRA model is one concrete composition, not the definition of the entire framework. Within this composition, any application may request services under the same registration and authorization rules. Application login, local administrator access and document possession do not grant trust authority.

The framework develops original specifications and technology alongside standards integration. A separately identified successor may improve or replace a selected mechanism. Its architectural contract closes the relationships between upstream protocols: authority, subject/key/purpose binding, authorization, execution, status and retained evidence. Upstream objects remain governed by their selected standard revision. A CertConcord specialization or original extension MUST identify its additional semantics and compatibility boundary; it MUST NOT claim upstream adoption, conformance or endorsement solely because the framework implements it. The [architecture diagram](../architecture.md) distinguishes governance, identity qualification, holder interfaces, document operations and evidence services.

An implementation receives no implicit authority from its name or brand. [Licensing](../../LICENSING.md), [patent commitments](../../PATENTS.md), [contribution rules](../../CONTRIBUTING.md) and [conformance-mark policy](../../docs/conformance-marks.md) govern their respective rights and administrative records separately from protocol trust appointments. A mark grant MUST NOT substitute for an RA/CA appointment or change a Root Trust Manifest.

## 2. Normative interpretation

BCP 14 applies. Cryptographic validity, authority, subject identity, user intent, temporal validity and content coverage are separate assertions. A verifier MUST identify which assertions its result covers. Schematic endpoints and diagrams cannot override the pinned upstream wire formats.

## 3. Standards baseline

The baseline includes RFC 5280, CMS, ML-DSA RFC 9881/9882, ML-KEM RFC 9935/9936, RFC 9629, MTC draft-06, WebAuthn Level 3, OpenID4VCI/VP 1.0 and the declared timestamp/archive adapters. Raw-signing proposals, C2SP extensions, Remote CryptoKey and enrollment profiles use explicitly versioned adapters. Each adapter identifies its source revision, wire semantics and compatibility requirements.

## 4. Architecture

In the CERTCONCORD-governed composition, offline root governance authorizes a Root Trust Manifest (RTM). The RTM appoints registration authorities, issuing CAs, CA cosigners, independent mirrors, status authorities, activation gateways and evidence services. RAs approve exact subject/key/profile requests. CAs consume those approvals and publish verifiable issuance commitments. Document services enforce the resulting authority for signing, organizational seals and encryption; verifiers evaluate content, authorization, status and historical evidence under the selected policy.

MTC is one selected binding for credential issuance and transparency. Its proof, cosigner, mirror and lifecycle requirements apply to the MTC branch; native signer-mdoc issuance has its own binding. A replacement mechanism MUST have a separately identified profile, authenticated policy selection, complete evidence rules and a migration procedure. This does not permit omission of MTC checks while claiming the existing MTC profile. A different governance composition likewise requires an explicit authority contract rather than treating an RRA decision as unnecessary without replacing its applicable function.

DTI defines that infrastructure. DSCP defines document-signing keys, providers, containers and operation authorization. PRF-KPP defines Passkey-derived local protection, wrappers, rotation and recovery boundaries. DCP defines the credential and native-holder interfaces. COMMON supplies their shared encodings, identifiers, state machines and assurance rules. A deployment MUST preserve these responsibilities across its component and protocol choices.

MTC certificates and personal signer mdocs are two governed credential representations. MTC supports transparent certificate issuance and certificate-based document formats. The primary native personal credential is a signer mdoc, delivered through OpenID4VCI and usable through OpenID4VP, ISO 18013-7 Annex C and supported Digital Credentials API mediation. An RA may admit mDL, photo ID, EUDI PID or an approved custom mdoc as identity evidence under DCP section 11. An authorized issuer, including a government authority, may issue the signing profile directly. Identity-source trust remains separate from authority to issue signing credentials.

### 4.1 Mandatory credential-to-document contract

DCP-draft-02 is the normative native-holder branch of this architecture. A deployment providing that branch MUST implement DCP together with DTI, DSCP and COMMON. WebAuthn activation, MTC certificate operations and PRF-protected storage use their respective contracts below. All branches resolve to the same governed subject, key, purpose and policy; a protocol-specific account MUST NOT introduce independent signing privileges.

| Transition                                    | Required authority and binding                                                                                                                          | Rejection condition                                                                                            |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Identity evidence to RAR                      | Authorized RA, TrustDomainID, SubjectID, exact document SPKI, profile and policy                                                                        | Login-only approval; changed subject, key or policy                                                            |
| RAR to personal signer mdoc                   | Scoped audience/format, approved document-key profile, verified hardware admission and active holder binding, issuerAuth, PQ seal and native log quorum | Identity evidence alone; substituted key; missing seal/quorum                                                  |
| RAR to compatibility MTC certificate          | Consumed approval, durable leaf allocation, exact TBS, CA and independent mirror quorum                                                                 | Missing quorum; conflicting retry; unapproved profile                                                          |
| Native key to DeviceBinding                   | RA-signed DeviceRegistrationAuthorization, fresh proof of holder-key possession, document KeyID and the same domain/subject/policy                      | Foreign domain; wrong audience; reused approval; holder-key substitution                                       |
| DeviceBinding to OpenID4VCI credential        | Active binding and qualification, proof key equal to its holder key, binding epoch                                                                      | Caller-created qualification; revoked binding; replacement device without enrollment                           |
| OpenID4VP or Annex C to website qualification | Authorized issuer and reader, original browser session, holder proof, current credential status                                                         | Valid credential from the wrong session, issuer or holder                                                      |
| Qualification to signature permit             | DSCP SIM and exact TBS, COMMON ActivationContext, explicit QTB, matching domain/subject/document key/policy/epoch                                       | Presentation used as general login authority or reused for another document                                    |
| WebAuthn assertion to signature permit        | Registered credential and subject/key authority, exact ActivationContext challenge, approved RP/origin, fresh UP/required UV and atomic consumption     | Earlier login assertion; altered context; revoked credential; wrong document key                               |
| PRF evaluation to protected local material    | Exact credential and purpose, PRF-KPP derivation, authenticated wrapper, current epoch and declared recovery graph                                      | Server disclosure of PRF output; cross-purpose unwrap; vault recovery interpreted as renewed signing authority |
| Permit to signature/evidence                  | Exclusive provider boundary, one-use dispatch, execution receipt, certificate/status/time policy and closed ECP                                         | Unknown execution reported as success; evidence hash closure without semantic validation                       |

The mdoc holder key normally remains a native P-256 key in Secure Enclave, Android Keystore or Windows TPM. INDEPENDENT_PQ associates that key with a separately registered ML-DSA document key. DEVICE_KEY explicitly authorizes the same P-256 key for a distinct document-signing operation. The selected mode is signed into the credential and checked by the verifier; ES256 retains its classical algorithm assurance. A qualification-only presentation stops before the permit transition.

### 4.2 Lifecycle coupling

Credential issuance and activation MUST recheck current DeviceBinding status, qualification and epoch. Binding revocation blocks new issuance and activation. An already issued permit remains subject to a final live authorization check at provider dispatch; a permit signature alone cannot bypass a revoked key or binding. A document-key change requires a newly authorized binding. Credential renewal may retain an unchanged active binding, but MUST validate fresh holder possession and current qualification. Historical evidence retains the original binding epoch, certificate representation and policy; it is never rewritten to the replacement key.

Passkey registration, document-key enrollment, wallet binding and encrypted-vault protection have distinct lifecycles. PRF-KPP protects account roots, purpose-separated signing/encryption vaults, wallet metadata, private evidence, receipts and enrolled capabilities. A PRF-protected software signing key retains its assessed software/export boundary and requires DSCP authorization after unlock. PRF-KPP MUST NOT export, synchronize or recover a non-exportable native holder key. Device replacement follows RA enrollment; encryption-only recovery follows COMMON RCG and cannot restore signing authority.

### 4.3 Mandatory key-admission transition

The sequence is authenticated enrollment session -> fresh hardware challenge -> target-key generation or certification -> independent platform-evidence validation -> exact key possession -> RA DeviceRegistrationAuthorization -> DeviceBinding -> CA profile/equality/status checks -> signer mdoc through VCI. A copied attestation for another key or an app-integrity assertion about a different key MUST fail.

DCP sections 2.2–2.3 define the accepted evidence and document-key modes. The attestation policy is part of the domain's governed issuance policy. It fixes platform roots or enrolled AKs, allowed security boundaries, app identity, firmware/patch requirements, revocation sources and maximum binding lifetime. Issuers MUST refuse hardware-profile issuance when evidence is missing or cannot satisfy that policy. A software profile is an explicit separately evaluated policy choice.

The CA commits key_admission and document_key_mode through issuerAuth, the PQ seal and the issuance log. Credential delivery, activation and provider dispatch recheck current binding and attestation status. Attestation evidence is retained under access control with its policy revision and verification time. Changes to hardware roots, firmware eligibility or AK status can suspend bindings independently of identity qualification.

### 4.4 Component and capability composition

Identity source, credential representation, activation mechanism and key provider are independent policy selections. The following composition rules apply:

| Selection                                                                                 | Permitted role                                                               | Mandatory binding                                                                                      |
| ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| mDL, photo ID, PID, custom mdoc or another approved identity process                      | RA evidence                                                                  | Issuer eligibility, exact schema, disclosed claims, evidence/status freshness and enrollment request   |
| MTC certificate or personal signer mdoc                                                   | Certification of a subject/key/purpose relationship                          | Scoped RA approval, profile, transparent issuance and applicable status                                |
| HUMAN_WEBAUTHN                                                                            | Fresh signing authorization through a registered Passkey                     | ActivationContext challenge, RP/origin, UV policy, subject/key authority and one-use proof             |
| HUMAN_MDOC                                                                                | Fresh signing authorization through the selected holder-presentation profile | QTB, current credential/holder binding, original session and exact document intent                     |
| PRF-protected software key, native key, PKCS #11, remote HSM or another declared provider | Key custody and execution                                                    | Exact key/version, input semantics, assessed custody and exclusive permit enforcement                  |
| PRF-KPP                                                                                   | Local secret protection                                                      | Purpose-separated root/wrapper, epoch continuity, confidential PRF output and evaluated recovery graph |

A wallet application, its secure cryptographic component and its provider backend MUST have explicit authorization boundaries. Credential issuers, relying-party readers and wallet/attestation authorities receive separate trust roles. Wallet-provider attestations MUST NOT be accepted as evidence about an unrelated document or holder key. External ecosystem mappings are specified in the [ecosystem guide](../../docs/ecosystem.md); their use does not change the governed roles or the selected protocol editions.

Organization identity, service authority and runtime-instance authentication MUST remain distinct. A service's permitted credential types, disclosures, purposes and audiences MUST be bound to its configured client/reader identity and current policy. Two services operated by the same organization MUST NOT inherit each other's permissions merely because they share a domain or operator. Existing client identifiers, origins, certificate roles, policy hashes and transaction bindings enforce this boundary; display names convey no authority.

External trust-list entries MUST be evaluated for their exact role, service scope, validity and status before they can support an RA decision or a role appointment. Retained status history MUST preserve the effective time of suspension or invalidation. An external list entry does not itself create an RRA issuer, and a format translator MUST NOT replace independent validation of the original signed list and its authority.

User interfaces MUST distinguish attribute disclosure, credential enrollment, vault unlock and document approval. The document operation identifies the selected key/credential, requesting party, purpose and actual content scope. Cancellation stops that operation. A single interaction MAY carry multiple explicitly described decisions, but their evidence and authority checks MUST remain independently verifiable.

## 5. Root RA trust model

Root governance has independent administrative custody and a defined signing threshold. The offline root key MUST NOT enter a web service, application deployment or ordinary online signing route. Bootstrap distributes domain ID, root pins, thresholds, adapter locks and independent emergency authority through an authenticated ceremony. A root certificate file alone does not establish how a relying party acquired trust.

## 6. Root Trust Manifest

The RTM fixes authority and policy object commitments, validity, serial and update locations. Every referenced object is fetched with size/origin restrictions and verified against its commitment. LIVE high-water marks and HISTORICAL reads follow COMMON TSC. Missing policy objects cannot be replaced by whatever currently occupies their URLs. Root, CA, mirror and emergency transitions retain both old and new authorizations.

## 7. MTC CA model

The profile combines the selected IETF MTC draft with separately pinned C2SP protocols and CertConcord's RRA governance. MTC certificate/proof and cosigner semantics remain attributable to MTC; RRA authorization, operator independence policy, MQ23/MQ34 selection, document intent and archival obligations are CertConcord requirements. The composition and its ML-DSA-87 C2SP extension are not all part of the IETF MTC standard.

An MTC authority is a policy-bound logical issuer and its exact cosigning key. Its certificate inputs, permitted end-entity profiles, namespace, log lifecycle and independent mirror policy are explicit. A conventional certificate wrapping the MTC authority does not bypass MTC verification. An authority prohibited from issuing CA certificates MUST NOT issue one, including a self-issued certificate that might evade a conventional path-length count.

## 8. CA and log identifiers

The CAID is a valid Trust Anchor ID within a legitimately controlled namespace. Draft-06 log, landmark and landmark-group names use `{caID 0 N}`, `{caID 1 N L}` and `{caID 2 N L}`. Display strings are not substitutes for the prescribed RELATIVE-OID bytes. Log numbers range from 1 through 65535 and are not reused under the same CA identity.

## 9. Certificate serial number

`serial = (logNumber << 48) | leafIndex`. Both arithmetic and DER INTEGER encoding preserve the complete value without floating-point conversion. Leaf indices and exclusive proof endpoints obey draft-06's 48-bit bounds. Overflow, invalid log number, negative serial and ambiguous encodings are rejected. Serial reuse under an issuer is forbidden.

## 10. Cryptographic suites

COMMON fixes the primary post-quantum suites and separate native holder suite. Root/governance, CA/mirror, document, encryption, timestamp and archive algorithms each have independent lifecycle policies. A stronger document algorithm cannot repair an untrusted root, a broken Merkle commitment or absent activation authority.

## 11. Certificate profiles

All end entities have CA=false. Profiles include PERSON-SIGN, PERSON-COMMIT, ORG-SEAL, SERVICE-SIGN, EVIDENCE-SIGN, DOC-ENC and TSA, with the `CERTCONCORD-...-v1` identifiers in DSCP/COMMON. KeyUsage, EKU, algorithm, issuer authorization and RAR scope all apply. Default maximum validity is 90 days for personal/seal/encryption profiles and 30 days for service/evidence/TSA profiles. Shorter policy limits take precedence.

## 12. Subject identity

SubjectID is a private trust-domain identifier independent of product accounts and display names. A name change, duplicate name or shared email does not automatically create or merge a trust subject. Identity source evidence, consent, reviewed name, qualification, reviewer authority and recheck expiry are retained under access control. Certificates and public logs SHOULD exclude civil identifiers, birth dates, addresses and biometric evidence.

## 13. Registration authorization

A RAR is an authenticated RA decision over schemaVersion, requestID, subjectID, profileID, policyHash, identityEvidenceHash, spkiHash, csrHash or equivalent enrollment commitment, possessionMode, issuedAt and expiresAt. The CA checks that the RA's issuer/profile/subject scope covers the request. A RAR is consumed for one issuance transaction, with identical retry returning the same stored certificate. A changed key, subject, policy or request under the same requestID is a conflict.

## 14. Proof of possession

A signing CSR uses its requested private key and verifies before approval. RFC 9883 permits a signed private-key possession statement for a key-establishment CSR: its statement identifies the issuer/serial of a previously validated signing certificate and may include that certificate. Subject and SAN relationships must be proven under policy. `SIGNED_STATEMENT` is not direct KEM possession.

The direct KEM challenge adapter encapsulates to the requested SPKI. The response MAC commits to requestID, KeyID, SubjectID, audience, unpredictable nonce, expiry and ciphertext hash using the declared HKDF domain. The RA checks the response and atomically consumes the challenge. Its `DIRECT_PROOF` result is bound to the same enrollment request. Two submitted public keys or a self-asserted possession Boolean are insufficient.

## 15. Issuance log

Native personal mdoc issuance follows DCP section 12 and its separate entry domain. The following draft-06 rules apply to the X.509/MTC representation. Log entries use exact draft-06 MTCLogEntry/TBSCertificateLogEntry encoding. The serial/signature fields and SPKI commitment are reconstructed exactly as prescribed. RRA metadata uses registered extensions or committed private evidence references; it MUST NOT alter the Merkle leaf construction. Public log commitments are minimized, but authorized monitors can obtain the underlying issuance approval evidence.

## 16. Issuance transaction

The durable transaction binds RAR, profile, subject, exact TBS, allocated serial and log index. The CA persists authorization consumption and allocation, appends the exact entry, collects required signatures, assembles the certificate and stores its original representation before delivery. It cannot reassign a consumed index after a crash. An incomplete transaction is reconciled by stored commitments; a conflicting retry is rejected.

## 17. Batching

Issuance batching shares Merkle work and checkpoint signatures; it does not combine unrelated authorization. Every leaf retains its own RAR, subject, SPKI and profile checks. Document-signature batching is a separate DSCP authorization mechanism. Operators publish bounds on batch latency and resource usage and do not report queued issuance as a delivered certificate.

## 18. Cosigner policy

The policy fixes CA key, mirror operators, keys, algorithm schemes, threshold, epoch, freshness and additional statements. COMMON's quorum equations govern the stated fault model. A CA plus two of three mirrors is explicitly MQ23; high-assurance fork prevention with one Byzantine mirror uses MQ34 or a proven stronger policy. Membership changes require joint continuity evidence.

## 19. Key separation

Root, RA, issuing CA, CA cosigner, each mirror, status responder, activation authority, receipt signer, TSA, human signer, service signer, seal and encryption key have separate purposes. A holder key cannot silently become the document key. Shared key material across roles is forbidden even when APIs accept the operation. Key registration checks immutable provider key version and SPKI.

## 20. Standalone MTC

A standalone certificate contains its exact TBS and draft-06 proof. Verification reconstructs the leaf, verifies subtree inclusion, CA cosignature and mirror quorum under the applicable policy. Unknown cosigners do not count. Repeated operators, duplicate public keys, a mirror using the CA key, malformed TLS vectors and unrecognized required extensions cause rejection.

## 21. Landmark-relative MTC

A landmark-relative certificate may omit proof signatures only when its subtree is already authenticated through an accepted landmark sequence. A cache entry is scoped by CAID, log, subtree interval/root, membership epoch, policy hash, RTM hash and validation mode. An inclusion hash matching an untrusted cache is insufficient. Revocation and CA distrust are checked before cache reuse.

## 22. Landmark distribution

The distribution service publishes immutable landmark objects and source-to-target consistency material. A mutable `current` pointer is only discovery. Number, interval, root, CA/mirror authorization, policy and sequence continuity must be validated. Distribution responses are bounded and content addressed. An object cannot be replaced at an immutable identity; conflicting content is a fork incident.

## 23. Document signatures

Native mdoc-certified COSE signatures, CMS/CAdES, PAdES and JAdES use their own exact signing inputs and COMMON's ACB bindings. A generic container signature without RRA attributes is not an RRA intentional-signature result. Verification of an MTC certificate requires its MTC policy even when a generic CMS parser accepts the embedded ASN.1.

## 24. Trusted time

RFC 3161 requests bind the exact message imprint, requested policy and nonce. The response verifies CMS signature, TSA authorization, exclusive timestamping EKU, certificate/status at generation time and request correspondence. Freshness, acceptable clock accuracy and future skew are policy inputs. The proof-of-existence upper bound includes declared accuracy. A signingTime attribute or log integration timestamp cannot be substituted for a validated TSA result.

## 25. Document encryption

Document encryption uses a random content key and authenticated encryption, with ML-KEM recipient key establishment under RFC 9629/9936. All recipient identifiers and algorithm parameters are checked. Decrypted plaintext remains quarantined until authentication succeeds. Ciphertext integrity failure is not retried as another algorithm. Static recipient keys do not provide historical forward secrecy.

## 26. Multiple recipients

Each recipient gets an independent KEM encapsulation and wrapped content key. Duplicate recipient identifiers, unauthorized certificates and algorithm/KeyUsage mismatch are rejected. Additional recipients require an authorized new envelope; they cannot be appended while representing the original sender authorization as unchanged. Recipient-list disclosure is considered in privacy policy.

## 27. Sign then encrypt

When sender authenticity is required, the sender signs the defined plaintext document/container and then encrypts the complete signed artifact. The receiver first authenticates decryption, then validates the inner signature and its purpose. KEM encapsulation alone does not identify the sender. Transport encryption does not replace the document envelope.

## 28. Certificate revocation

For X.509 certificates, complete signed CRLs are mandatory; OCSP is supported as an optional online status adapter. Issuer, serial, time interval, CRL sequence, critical extensions and status signer authority are checked. Delegated responders require their own authorization profile. Complete CRLs, delta CRLs and scoped CRLs must not be confused. UNKNOWN, missing, stale or unsupported status material prevents a GOOD assertion.

## 29. Range and authority revocation

RRA incident statements can revoke serial/index ranges, an entire issuance log, CAID or governance key. They identify exact scope, authorized publisher, sequence, publication time, effective time and compromiseStart where known. A range statement supplements conventional certificate status; it does not redefine an OCSP GOOD response. Any applicable negative status takes precedence over a narrower positive assertion.

## 30. Validation procedure

1. Select a pinned policy, validation mode, stateTime and knowledgeTime.
2. Parse all objects with bounded, unambiguous encodings and locate trusted bootstrap material.
3. Validate RTM/authority continuity and the relevant issuer/mirror policy.
4. Verify certificate profile, time, issuance proof and CA/mirror quorum or landmark continuity.
5. Evaluate all applicable certificate/range/log/CA and device/authorization status.
6. Verify the container's exact signed bytes, certificate representation, SIM, policy and ACB evidence.
7. Validate required trusted time, archive renewal and ECP closure.
8. Return the independent result dimensions and precise coverage.

No step can be replaced by a successful TLS connection to an endpoint.

## 31. Document validation

A verifier compares expected use to certificate profile/EKU and operation purpose. It checks actual document scope, container syntax, signature and full certificate binding. For PDF it identifies the signed revision, verifies ByteRange and classifies later modifications. A valid earlier revision does not approve arbitrary current-page changes. For JWS it honors critical headers and the selected payload encoding.

## 32. Historical validation

The historical result states both the time being evaluated and the knowledge cutoff. Archived authorities and status material remain immutable. Later-published compromise evidence may affect earlier operations within its effective interval. Missing historical policy or status yields INDETERMINATE rather than substituting today's policy. Historical reads cannot roll back LIVE state.

## 33. Long-term evidence

ECP packages preserve exact original certificate representations, proofs, container bytes, intent/activation evidence, policy, trust state, status and time evidence. An immutable artifact may gain later sidecar evidence without changing its signed bytes. Public packages disclose only the evidence necessary for their validation scope; private registration evidence remains access controlled.

## 34. Evidence renewal

RFC 4998 ERS and RFC 6283 XMLERS support timestamp and hash renewal. Hash renewal includes the original protected bytes and previous evidence chains. XML canonicalization is fixed and DTD/external-entity processing disabled. Renewals must occur while the preceding chain still supports its security claim. A successful new timestamp cannot manufacture a lost historical chain. The [selected document preservation contract](../../docs/document-preservation.md) fixes the RFC 4998 subset, lifetime inputs, hash-renewal ordering and distinct historical/current results. XMLERS integrity checks do not yet evaluate those lifetimes.

## 35. Encryption recovery

KRA escrow is restricted to explicitly recoverable encryption material. Approval signatures, cryptographic shares, provider access and wrapping roots are modeled in an RCG. An account or KRA path must not recover or activate an intentional signing key. Recovery releases bind requester, target key/root, purpose, recipient key, expiry and audit evidence. Data recovery and identity continuity are separate outcomes.

## 36. Certificate directory

Directory lookups expose authorized public certificates and minimal status/discovery metadata. Mutable directory records are not trust anchors. Lookups bind certificate representation and current status to the issuer policy. Bulk subject enumeration and disclosure of private identifiers are controlled. A short code or certificate fingerprint is not document-download authorization.

## 37. Monitoring

Monitors independently inspect log consistency, mirror availability, membership transitions and policy-compliant issuance. Authorized monitors correlate committed RAR evidence with subjects and keys. A monitor reports provable conflicts without altering past entries. Evidence fetch failure is distinguishable from an invalid issuance claim.

## 38. Log and mirror storage

Mirrors verify consistency and entry contents before asserting durable possession. Partial uploads retain only authenticated complete packages and advertise the next resumable index. Checkpoint and entry commit state survives restart. Monitoring interfaces expose the accepted checkpoint and corresponding tiles/bundles. A service storing only a root hash is a witness, not a mirror.

## 39. Fail-closed behavior

Failures of required trust, authority, freshness, quorum, signature, activation or content checks prevent the requested positive assertion. Optional asynchronous evidence can remain pending without falsifying the completed core operation. Failure states preserve enough immutable context for reconciliation and do not trigger an unapproved fallback key or algorithm.

## 40. CA cosigner rotation

A changed key, algorithm or parameter set has a new immutable identity and registered policy. The applicable MTC instance/CAID transition follows the pinned adapter. Old signatures retain their old key binding. Replacing the public key behind the same identifier without a signed transition is forbidden.

## 41. Log rotation

Rotation advances the log number and commits the previous terminal checkpoint, the new initial state and the governing policy. Capacity bounds and operational recovery can require early rotation. An old log remains available for status and historical validation; emptying storage is not a rotation mechanism.

## 42. Algorithm transition

Algorithms migrate independently by plane. Parallel new and old credentials/evidence are permitted under explicit profiles. Earlier bytes continue to verify under their archived adapters and security lifetimes. A new post-quantum signature over an old artifact records a new statement; it does not retroactively change when the artifact first existed.

## 43. Governance log

Root policies, authority appointments, transitions and incident statements have an append-only governance history and externally checkable commitments. Mutable SQL audit rows alone do not establish tamper evidence. Governance confidentiality policy may separate private deliberations from public commitments and approved decisions.

## 44. Service interfaces

Interfaces declare media types, authentication, authorization, size bounds, expiry, pagination, idempotency and errors. The enrollment adapters preserve CMP/ACME wire semantics while requiring the same RA approvals. DNS control in ACME is not natural-person identity or document signing authority. OpenID endpoints use DCP-draft-02; hardware and remote providers use ACB, regardless of API style.

## 45. Security zones

The website, identity-evidence intake, RA decision service, online CA, activation service, signer, status service, mirrors and offline governance are separate authority zones. Network co-location does not collapse those roles. Secrets stay outside public repositories and logs. Public examples use synthetic keys and cannot be imported as production roots.

## 46. Hardware providers

Provider capabilities declare exact algorithm, input semantics, key version/SPKI, export controls, UV policy, attestation and result-query behavior. A PKCS #11, CSC or KMS API name is not KAL3. Where hardware cannot verify OperationPermit internally, the gateway and its exclusive device credentials are part of the trusted boundary. Every alternative signing path must enforce equivalent controls.

## 47. Retention

Policies define log, certificate, status, authorization, evidence and personal-data retention separately. Pruning requires retained material sufficient for the promised historical service and authenticated pruning boundaries. Erasing private document content does not revoke its signature; erasing required evidence changes what can later be established.

## 48. Availability

Availability targets follow the declared fault assumptions. Mirror failures do not authorize a smaller threshold. Result lookup and reconciliation tolerate uncertain provider execution. External TSA and transparency jobs can complete asynchronously, with separate states for queued, submitted, verified, failed and expired evidence. Delivery reports do not call a queued proof verified.

## 49. Conformance classes

Classes identify trust governance, MTC standalone, landmark, document signing, encryption, PRF, native holder, OpenID issuance/presentation, Annex C, provider, enrollment, revocation and archive capabilities. Each enabled class has executable acceptance tests and deployment evidence requirements. Unsupported input features are explicitly rejected rather than parsed approximately. A conformance record MUST identify the tested implementation, policy and environment.

## 50. Mandatory composition services

A complete trust-domain deployment MUST provide offline root governance, a signed RTM, scoped RA/RAR/PoP, transparent issuance with independent mirrors and explicit MQ23 or MQ34 policy, current key/authority status, DSCP SIM/ACB enforcement and semantic evidence validation. MTC issuance MUST implement the selected draft-06 certificate profile, durable allocation and complete CRLs. Personal native credentials MUST additionally implement DCP issuance/presentation, PQ credential seals, native issuance transparency, current DeviceBinding/admission status and QTB when HUMAN_MDOC is used.

Personal signing MUST support the independent ML-DSA profile. DEVICE_KEY and PASSKEY_KEY are additional explicitly selected ES256 profiles; PASSKEY_KEY MUST satisfy PSCP. HUMAN_WEBAUTHN activation MUST satisfy DSCP section 18; HUMAN_MDOC MUST satisfy DCP section 8. A deployment supporting PRF-protected roots or local keys MUST implement PRF-KPP, including wrapper integrity, rotation and recovery evaluation. Document encryption MUST use separate enrollment, keys and recovery authority. A policy promising long-term historical validity MUST additionally require validated trusted time and retained archive evidence.

Identity intake and signing-issuer acceptance are distinct trust registries. Direct issuers may use their own approved identity process. A component implementing fewer roles declares the applicable conformance classes under section 49. Every enabled adapter inherits its full requirements; selecting one credential or activation interface does not waive the common trust, document or lifecycle controls.

## 51. Complete trust path

The path is bootstrap authority → RTM and policy → RA/key qualification → transparent issuance → scoped certificate → actual signing input and fresh activation → provider result → temporal/status evidence. DCP supplies identity intake where used, direct or subsequent signing-credential issuance, holder proof and QTB. A personal mdoc itself certifies the subject/key/purpose relationship; it need not wrap a personal X.509 leaf. No single certificate or credential replaces the whole path.

## 52. Required security properties

The system detects key/subject/profile substitution, replay, rollback, split views under its stated quorum model, unexpected document revisions, cross-origin presentation, recovery escalation and incomplete evidence. It preserves the ability to state uncertainty. Its assurance claims identify their trust assumptions and do not exceed the evidence actually verified.

[SEP draft 02](SEP-draft-02.md) specifies parser isolation, distributed persistence, privacy measurement, supply-chain evidence and independent assessment for implementations of this trust path. It supplements these requirements without changing signed object formats or the applicable historical evidence plan.

## 53. Draft dependency governance

Business semantics, RRA bindings and upstream wire adapters evolve independently or through a coordinated architectural revision under [FRAMEWORK](FRAMEWORK-draft-02.md). Adopted revisions remain version-pinned for reproducibility while later drafts, final standards and original architectures may be evaluated and selected. An incompatible update uses distinct version semantics and an explicit cutover. It MAY retire old adapters and mechanisms without a compatibility bridge. Retained original evidence and OIDs keep their historical interpretation; a successor need not implement their verifier. Live trust decisions MUST NOT automatically follow a moving upstream branch.

CertConcord participants MAY develop independent experiments, draft profiles and specifications, including extensions to existing standards and alternative mechanisms. RRA is a governance role in this composition, not the authority that grants permission to conduct framework research. A protocol draft MUST identify its authoring authority, original contribution, exact wire revision, state machine, threat model, compatibility boundary and executable acceptance criteria. It MUST NOT be presented as an upstream capability solely because it transports or supplements upstream objects. [Execution Binding Profile draft 02](EBP-draft-02.md) applies this process to governed provider/key admission, immutable signing requests, durable single dispatch and mandatory CMS/mdoc execution evidence.

## 54. Uniform policy enforcement

Issuer and application names MUST NOT grant exceptions to the domain's published policy. Every issuer, wallet, verifier and signing provider is subject to the same applicable authority, key-purpose, evidence and lifecycle requirements.

## 55. Passkey-associated credential path

[PSCP-draft-02](PSCP-draft-02.md) adds a personal signing-key admission path to this infrastructure. The parent Passkey's authentication key, associated document key, attestation key and issuer key have separate roles. RA approval binds the independently qualified subject, exact CSR/SPKI and PasskeySigningBinding. CA/MTC issuance verifies that same admitted binding; signer-mdoc issuance carries it in the governed signing namespace and retains DCP transparency, seal and status requirements.

The path is key generation and attestation → exact CSR possession → independent identity decision and signed RAR → certified binding → frozen document/ACB → fresh verified activation and permit → raw signature plus parent assertion → receipt and semantic evidence verification. A prequalified identity can precede generation; final certification still binds the exact key. Unattended public ARKG derivation creates neither identity authority nor a CA issuance grant.

Passkey binding and parent revocation stop local authorization immediately and propagate through the issuer's existing CRL or mdoc status publication. Account recovery cannot silently rebind historical signatures. MTC/X.509, signer mdoc, independent ML-DSA, PRF-protected vaults and the new P-256 profile remain explicit choices within the same root, RA/CA and evidence model.
