# Design rationale — draft reference

## The central problem

A trustworthy document operation depends on more than a certificate signature. It must connect governance, identity qualification, possession of the correct key, the intended document bytes, authorized key use, current status and evidence that survives software and policy changes. [FRAMEWORK draft 02](../spec/bindings/FRAMEWORK-draft-02.md) separates those requirements from replaceable governance, issuance, transparency and interaction mechanisms. Within `certconcord-governed-draft-02`, DTI, DSCP, PRF-KPP and DCP divide the responsibilities, while COMMON provides their shared identifiers, encodings and state transitions.

The document infrastructure governs authority and transparent issuance. DSCP defines what a signing key is allowed to do and how an intentional operation reaches it. PRF-KPP protects local secrets and private evidence. DCP connects the same authority model to native holders and websites. A valid object in one domain does not automatically authorize an action in another.

## MTC, mirrors and evolving standards

MTC is one issuance/transparency architecture selected by the current composition. Future development may adopt a better architecture with different data structures, roles, proof systems and verification interfaces. Evaluation concerns security, privacy, verification cost, evidence size, scalability and operational assumptions for the intended scope; preserving MTC compatibility is not an adoption requirement. The current MTC design reduces repeated certification work through Merkle commitments and cosigned subtrees. Its benefit depends on verifying exact leaf bytes, stable issuer identifiers, correct tree intervals and the required signatures. A mirror has to possess the entries durably; a checkpoint witness only asserts consistency. Counting both as interchangeable votes would change the fault model.

For n independent operators, a quorum q has an intersection larger than f faulty operators only when `2q - n > f`. Availability additionally requires `q <= n - f`. Thus two of three tolerates one unavailable operator but does not prevent two conflicting accepted views when their sole intersection is Byzantine. Three of four supports both properties for one fault under the stated assumptions. Operational independence and policy continuity remain necessary.

MTC, OpenID, raw-signing proposals and C2SP revisions use explicitly versioned adapters. Each adapter pins its source, wire profile and validation rules, with independent vectors where available. These pins describe an evaluated revision rather than freezing framework development. Later drafts, final standards and original architectures can be adopted through the evolution contract, including by a breaking upgrade. A successor can retire old interfaces and readers. Historical evidence retains its original meaning wherever it is retained or verified; that requirement does not make the successor backward compatible.

RRA is similarly a selected governance role. CertConcord's authority requirements can be realized by a different declared governance model without making every deployment a Registration Authority system. Wallet ecosystem independence means that CertConcord defines its holder and trust architecture from its own requirements. EUDI supplies an optional mapping; unrelated holders do not inherit EUDI components, trust infrastructure or certification requirements. Credential portability and key migration are separate operational capabilities. Experiments may revise these architectures while keeping their assumptions and changed semantics explicit.

## Native credentials and document signing

Secure Enclave, Android Keystore and Windows TPM provide native holder boundaries when their exact keys satisfy the issuer's attestation policy. INDEPENDENT_PQ uses a separate ML-DSA document key. DEVICE_KEY uses the attested ES256 key for a separate document-signing operation when its application API and issued profile permit it. A device-bound ES256 mdoc proves possession of its holder key; it cannot be treated as an ML-DSA signature or unrestricted permission to use another key. DeviceBinding supplies the RA-authorized relationship between subject, holder, document key, policy and epoch.

The CERTCONCORD-governed composition uses independent identity-evidence and signing-issuer trust policies. An RA may verify a government mDL/photoID without importing its issuer into the subsequent CA chain. Any accepted signing issuer, including a government, may issue a personal signer mdoc directly or as an additional namespace in a combined identity mdoc. OpenID4VCI distributes the credential after scoped RA approval and possession of the approved holder key. The selected document public key and key mode are certified by the issuer-authenticated namespace and the required PQ seal. OpenID4VP and Annex C bind the presentation to the website request, recipient key, origin and nonce using their own transcripts. Qualification Transaction Binding adds the specific RRA ActivationContext and explicit consent. The same qualification may be valid for access while being insufficient for a signature requiring fresh UV or trusted display.

Privacy benefits are bounded. Selective disclosure reduces revealed claims, but reused device keys, status requests and issuer/verifier metadata can still correlate sessions. Independent per-device/issuer keys, short credential lifetimes, batching and cacheable status reduce exposure without claiming unlinkability that the wire protocol does not provide.

## RRA composition mechanisms

These are application composition rules, not new cryptographic primitives. The [composition review](composition-review.md) evaluates standard representations, signed-object necessity, state reduction, dependency order and independent implementation limits. Existing abbreviations remain identifiers in experimental bindings; they do not supply a security argument.

| Mechanism                               | Threat addressed                                                                                                                  | Verifiable invariant                                                                                                                       |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Operation authorization                | A successful login or generic approval can be reused for a different message                                                      | Exact document scope, SIM, TBS, key, certificate representation, policy, audience, nonce and expiry are bound before dispatch              |
| Qualification-to-operation binding     | A valid credential presentation is mistaken for document consent                                                                  | The holder authenticates the same activation commitment; the website consumes it for one original session/operation                        |
| Trust state continuity                 | Historical validation rolls a live trust cache backwards                                                                          | LIVE serial/digest watermark is monotonic; historical reads retain explicit stateTime and knowledgeTime                                    |
| Evidence Closure Package (ECP)          | Hash-valid evidence omits authority or authorization dependencies                                                                 | Every dependency is content-addressed; a declared plan also validates the semantics and external trust inputs                              |
| Recovery capability analysis           | Separate-looking recovery steps indirectly reconstruct signing authority                                                          | Modeled capability closure cannot reach explicitly declared signing targets; unmodeled real-world paths remain a limitation              |
| PRF wrapper epochs                      | A rotation receipt accepts a new wrapper containing a substituted root                                                            | Old and new authorized evaluations demonstrate the same protected root before atomic epoch replacement                                     |
| Ordered activation batches              | A UI approves a list but an attacker inserts or reorders operations                                                               | The acyclic complete ordered context list is committed; every item nonce is consumed atomically                                            |
| Passkey Signing Binding                 | A parent authentication credential is mistaken for the certified document key, or attestation about one key is applied to another | Exact child attestation, CSR possession, subject, RP, algorithm, RA approval and issued representation share one immutable commitment      |
| Preauthorized raw-signing evidence      | A raw signature is accepted without the earlier document authorization or its parent assertion                                    | Permit precedes the signing challenge; the parent authenticates the raw signature; the receipt commits to both proofs without a hash cycle |

For X.509/MTC, CertificateID commits to TBSCertificate, while CertificateRepresentationHash commits to the original certificate bytes. This permits an explicitly authorized change between standalone and landmark-relative MTC representations without pretending that a signature over one representation bound another. CMS signingCertificateV2 retains the complete original certificate binding.

## Time and execution uncertainty

A database cannot make a remote HSM call exactly once by itself. Persisting DISPATCHED before the call prevents an automatic reissue after a crash. A completed result can be replayed as the same bytes; an unresolved call remains unknown. A new attempt needs a new authorization and operation identifier, and policy must consider the possible earlier signature.

Receipt execution time, signingTime, timestamp proof of existence, certificate validity and revocation effective time are distinct. A timestamp creates an upper bound on existence, including its accuracy. A later compromise statement can apply to an earlier operation. Historical verification therefore needs both the time being evaluated and the time at which evidence is known.

## Recovery and assurance

PRF protects ciphertext against a server that lacks the credential secret, but an authorized compromised browser origin can access an unlocked secret. Non-extractable API handles, backup flags and biometric prompts are evidence of different properties. Key Assurance Level and Signature Activation Level stay separate so one property cannot inflate another.

Encryption recovery is useful and can have explicit escrow. Signing recovery has different consequences: an account reset must not let an administrator impersonate the original signer. New key enrollment can preserve identity continuity while clearly ending old key continuity. This distinction is retained in lifecycle records and historical evidence.

## Personal signing credentials as mdoc

A signer mdoc certifies the same kind of subject/key/purpose relationship required by the document trust model, without requiring a personal X.509 leaf. A COSE document signature is independently verified with its certified ML-DSA or explicitly authorized ES256 key. The latter remains a classical signature. The native issuance log and ML-DSA-87 seal preserve auditable issuance and PQ key certification while keeping ISO issuerAuth and hardware holder operations interoperable with their classical suite. This composition does not upgrade the security lifetime of the classical identity or holder proof. The X.509/MTC representation remains an explicit compatibility path for PDF/CMS ecosystems.

An issuer cannot add a namespace to somebody else's signed mdoc. A combined mdoc is newly issued by the authority controlling its MSO, and each ecosystem's schema/authority rules continue to apply. Verifier acceptance of the signing purpose is explicit; identity acceptance alone supplies no signing authority.

## Passkey-associated signing keys

Ordinary WebAuthn authenticates a prescribed assertion structure. Certifying its public key cannot turn that structure into a CMS or COSE signature. PSCP therefore certifies a separate document key and preserves the parent assertion as authenticated evidence about its use. The same binding can be represented by a newly issued signer mdoc or an MTC/X.509 certificate. Each issued representation retains its own lifetime and status; activation cannot switch an existing binding between them.

ARKG provides public derivation without releasing the seed's private material. Its useful role is scoped key separation, not unattended issuance authority. Enrollment-bound contexts, exact tickets, individual possession proofs and RA approvals constrain that capability within DTI. Public derivation test vectors and independent CSR/container verification validate different parts of the construction.

Raw-signing APIs and WebKit Remote CryptoKeys expose different provider boundaries. The selected PSCP flow checks an earlier activation permit and complete evidence, while the authenticator itself signs an input supplied by its RP. A protected broker can add exclusive execution controls through a separately specified integration. Keeping these enforcement claims explicit allows the proposed APIs to be implemented and evaluated without silently assuming hardware behavior that their interfaces do not establish.

## Execution commitments across providers

[EBP draft 02](../spec/bindings/EBP-draft-02.md) makes that broker boundary explicit. A governed admission binds a provider/key/epoch to exact policy and control authorities. The operation commitment joins that admission to the original permit, SIM and container input before dispatch. A mandatory evidence plan makes a missing admission detectable. Monotonic epochs address rollback and contradictory admission; a key-scoped durable lock prevents binding renewal from bypassing an unresolved operation.

The design remains useful when an upstream API offers only generic signing. Exclusive broker credentials can enforce an RRA policy at that boundary, while an authenticator with only a raw-signing API retains PSCP's narrower evidence semantics. An eventual permit-aware authenticator needs protected policy and replay state of its own. This separation allows protocol development without equating a transport hash, an application assertion and hardware enforcement.
