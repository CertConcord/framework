# CertConcord Framework Architecture and Evolution — draft 03

> Candidate binding for CertConcord draft 03. This is a working draft, not a final standard. Its requirements apply only when this binding is selected. The [draft architecture](../architecture.md) defines framework scope; the [profile catalog](../profiles.md) records applicability. The draft 03 namespace and wire domain identify experimental formats. Object schema numbers describe field layouts and do not indicate a stable edition.

Status: draft 03. Normative language: English.

## 1. Scope

CertConcord defines the composition of identity qualification, credential issuance, key protection, intentional operations and verifiable evidence. It develops original specifications and technology alongside integration of existing standards. Existing standards constrain compatibility claims for selected bindings; they do not prohibit a separately specified original or successor design. Its architecture supports advances in trust and issuance design, upgrades of upstream standards, independent wallet ecosystems, and independently developed experiments, drafts and specifications. Selecting a successor mechanism changes the framework's technical composition; it does not redefine the upstream standard that an earlier composition used.

The framework is not defined by a particular Registration Authority system, certificate construction, wallet, protocol edition, standards organization or implementation. RRA is one governance role available within the framework. MTC is one mechanism for credential issuance and transparency. Neither is a universal prerequisite for every CertConcord composition.

Wallet ecosystem independence is an architectural principle: CertConcord's holder interfaces and trust model MUST be definable without adopting EUDI's architecture. EUDI is an optional integration described by an explicit mapping. Architectural evolution likewise permits a successor to MTC when a better design is established for the intended scope. Backward compatibility is not a prerequisite for adopting that successor.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, NOT RECOMMENDED, MAY and OPTIONAL in this document are interpreted as described in BCP 14 when, and only when, they appear in all capitals.

## 2. Architectural layers

| Layer                           | Responsibility                                                                                           | Change boundary                                                                        |
| ------------------------------- | -------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Framework contract              | Authority, purpose, intentional operations, lifecycle, evidence and explicit assurance                   | Defined by this document and the declared framework edition                            |
| Composition profile             | Assigns responsibilities to concrete governance, issuance, holder, operation and verification mechanisms | An immutable profile revision, with its mandatory requirements and applicability rules |
| Standards bindings and adapters | Exact upstream or original wire semantics, cryptography, transcripts, errors and validation              | Versioned bindings and source revisions selected by the profile                        |
| Implementations and deployments | Wallets, applications, key providers, services, storage and operational policy                           | Assessed capabilities and explicitly authorized deployment changes                     |

A change at one layer MUST NOT silently grant authority or change the meaning of signed objects at another layer. Framework scope is broader than any one composition profile. A profile's mandatory mechanism remains mandatory for that profile until a separately identified revision or replacement is selected.

A successor MAY reorganize several layers together, introduce new interfaces and formats, and retire previous mechanisms. The layers identify responsibilities and the scope of a change; they do not require a new architecture to fit an old adapter API. A revision that changes the framework contract itself MUST identify a new framework edition and its requirements.

## 3. Invariants across mechanisms

Every composition profile MUST specify how it preserves the following requirements for each applicable operation:

1. **Scoped authority.** Identify who establishes trust policy, qualifies evidence, approves issuance, issues credentials, authorizes key use and verifies results. State delegation, separation of duties, authority changes and conflict handling. No application account, wallet brand or format grants these powers implicitly.
2. **Exact subject, key and purpose.** Bind approved evidence to the correct subject, public key, permitted uses, policy and lifecycle state. Distinguish the issuer key, holder/authentication key, document key, encryption key and recovery authority, including any explicitly permitted key reuse.
3. **Intentional operations.** Bind an authorization to the exact operation, content or cryptographic input, key, recipient or relying context, policy and freshness requirements. An identity presentation or account login alone does not authorize an arbitrary document signature.
4. **Current authority at execution.** Check applicable status and authority before execution, consume one-use permissions atomically, preserve immutable outcomes and handle uncertain results without uncontrolled redispatch. Recovery and retries MUST NOT create new signing authority implicitly.
5. **Independent evidence.** Define the authenticated artifacts and semantic checks needed to verify each claimed assertion. Separate mathematical validity, issuer authority, identity qualification, consent, execution, time, status and content coverage. Missing evidence MUST NOT be converted into a passing assertion.
6. **Explicit assurance and privacy.** Identify custody, authentication, display, disclosure and correlation properties with their evidence and limitations. A mechanism replacement MUST NOT inherit unproved assurance from its predecessor or from another key.
7. **Historical interpretation.** Preserve original bytes, identifiers, policy and state references. Distinguish historical validity from authorization for a new operation. Migration MUST NOT rewrite the meaning of previously signed evidence.

These requirements do not mandate a particular certificate tree, log format, registration hierarchy or wallet API. The selected profile supplies the concrete contracts and evidence required to evaluate them.

## 4. Replaceable responsibilities

| Responsibility                           | A binding MUST define                                                                                                                                       |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Governance and trust establishment       | Authority sources, role scope, delegation, decision authentication, continuity, revocation and emergency handling                                           |
| Identity and key qualification           | Accepted evidence and rulebooks, eligibility decisions, exact-key possession/custody, approval scope and consumption                                        |
| Credential issuance                      | Credential format, issuer authority, subject/key/purpose certification, issuance conditions, delivery and lifecycle                                         |
| Issuance transparency and accountability | Retained commitments or records, verifiable proofs, consistency and availability assumptions, observer roles and privacy properties required by the profile |
| Holder and wallet interaction            | Ecosystem-independent role and interface contracts, selected protocols, holder-key binding, origin/session/recipient binding and consent                    |
| Operation authorization and execution    | Exact request binding, activation evidence, provider admission, replay control, durable outcomes and reconciliation                                         |
| Status, time and archives                | Authority, freshness, historical interpretation, renewal, retention and evidence dependencies                                                               |
| Cryptography and containers              | Algorithms, encodings, key separation, identifiers, parsing limits, signature inputs and complete verification rules                                        |

Issuance, credential representation, delivery and transparency are separate responsibilities, even when one architecture combines them. MTC binds certificate issuance to Merkle-tree evidence in its selected profile. A successor MAY replace the issuance/transparency architecture, including its credential structures, operator roles, proofs, distribution and verification interfaces. Its evaluation MUST identify the requirements it improves or changes, its security and fault assumptions, and relevant privacy, performance, evidence-size and operational tradeoffs. An MTC compatibility layer, the MTC tree structure and support for old MTC clients are not prerequisites for that successor. A successor MUST specify its own complete semantics and MUST NOT label a different proof as an MTC proof. A profile that does not provide a particular assertion MUST state that scope and MUST NOT satisfy a relying party that requires it.

RRA provides trust-domain governance in profiles that select that role. A different profile MAY assign governance through other institution, federation or policy-authority arrangements. It MUST define equivalent applicable authority and lifecycle contracts. Replacing RRA is a governance transition, not deletion of authorization checks. Ordinary registration/qualification authority and overarching governance remain distinguishable responsibilities even if an organization performs both.

## 5. Composition profiles

A composition profile MUST identify:

- A globally unambiguous profile identifier, edition, immutable source revision and content digest.
- Its framework edition, covered operations and roles, mandatory requirements and explicit exclusions.
- The governance model and authenticated authority/state sources.
- Credential, issuance, transparency, wallet/holder, authorization, execution, status and archive bindings, as applicable.
- Exact upstream editions or draft snapshots, original extensions, algorithm suites and enabled adapter revisions.
- Dependency constraints, evidence plans, capability negotiation, failure behavior and privacy/assurance assumptions.
- Its assessment requirements, interoperability vectors and migration rules, including historical verification and rollback constraints.

A profile declaration is configuration and assessment material. It does not itself grant trust, install executable code or register a new wire format. A service MUST select only profiles it supports and its authorized policy permits. Unknown or incompatible selections MUST fail explicitly. A new profile identifier MUST NOT be used to bypass mandatory requirements of an existing signed policy or credential.

### 5.1 CERTCONCORD-governed composition

`certconcord-governed-draft-03` names the composition defined by [COMMON draft 03](COMMON-draft-03.md), [DTI draft 03](DTI-draft-03.md), [DSCP draft 03](DSCP-draft-03.md), [PRF-KPP draft 03](PRF-KPP-draft-03.md) and [DCP draft 03](DCP-draft-03.md), with applicable [PSCP draft 03](PSCP-draft-03.md), [SEP draft 03](SEP-draft-03.md) and explicitly selected extensions such as [EBP draft 03](EBP-draft-03.md). Its detailed applicability and evaluation rules are in [CONFORMANCE](CONFORMANCE-draft-03.md).

This composition uses offline root governance, a Root Trust Manifest, scoped RRA/RA/issuer roles and the declared authority/evidence objects. It includes MTC certificate issuance and native signer-mdoc branches with their respective evidence requirements. MTC requirements apply where the MTC branch is selected. Other enabled branches retain their own mandatory requirements. None of these selections establishes a framework-wide requirement to use MTC or a single wallet.

`certconcord-governed-draft-03` identifies the current composition. Draft 03 selects the domain-separated encoding `DCBOR(["CertConcord", 3, label, value])`, the `certconcord-` and `CERTCONCORD-` profile namespace, schema-2 flat evidence plans and the explicitly pinned component bindings. Earlier evidence is not retroactively upgraded to the framework edition or a new composition merely by adopting this architectural description. This runtime rejects prior experimental domains and layouts without rewriting their bytes. Alternative governance or issuance profiles require their own specifications, implementations and assessment; the existing verifier cannot accept an undefined replacement.

## 6. Standards and draft evolution

Upstream drafts and standards MAY be followed through later drafts, final editions, corrections and successor specifications. A source pin records what a particular binding implements; it is not a permanent ceiling on framework development. Release, framework, composition, upstream, adapter and object-schema versions are independent.

Source treatment MUST distinguish established specifications and ecosystem interfaces, working drafts, experimental proposals, and implementation references as described in the [upstream baseline](../../docs/upstream-baseline.md). Mature dependencies are integration and reference inputs; this research program does not extract them into replacement-standard projects or propose new drafts for them. This boundary applies to all mature dependencies, not only named examples or particular standards bodies. Separately specified original capabilities MAY use established extension points or draw on existing designs while preserving every claimed upstream contract.

Classification MUST identify the exact document and edition. A Final edition does not confer Final status on its successor working draft or exclude that draft from research. Studying or improving an existing successor draft is distinct from proposing a replacement for the established edition. Implemented compatibility and the current research comparison MUST be identified separately.

An upgrade MUST:

1. Identify the old and new authoritative source bytes and compare wire formats, cryptography, transcripts, authority, capability, privacy and error semantics.
2. Determine compatibility explicitly. A semantic or wire incompatibility requires a distinct binding/profile revision and, where ambiguity would remain, distinct wire identifiers or an authenticated context discriminator. Compatible updates still receive an immutable selection record.
3. Implement and evaluate the changed requirements, including rejection cases, cross-version confusion, downgrade resistance and historical evidence handling. A release title or successful parser run is insufficient evidence of interoperability.
4. Bind the selected version and capabilities using the selected protocol's authenticated negotiation or the profile's authenticated context. An advertised capability or a moving upstream branch MUST NOT override local trust policy.
5. Define activation, cutover and retirement rules, and any explicitly supported coexistence or rollback. A breaking upgrade MAY require coordinated peer upgrades and reject all earlier revisions. Peers MAY temporarily use different supported revisions through explicit negotiation when the new design supports that choice; failure MUST NOT silently select a weaker algorithm, custody boundary or authorization contract.

A draft becoming final does not automatically certify an implementation or transfer signed objects to the final format. Implementers MAY update adoption promptly once the concrete binding and evaluation are complete. Compatibility analysis MUST report whether revisions interoperate; it does not require a compatible result. Backward compatibility, dual operation and legacy readers in the successor are optional design choices. Retained historical evidence MUST preserve its original meaning. Its verification MAY use a separately maintained archival tool or service; a successor MAY retire the old runtime and return an explicit unsupported result for old formats.

## 7. Wallet ecosystem independence

A wallet implements selected credential-holder capabilities. CertConcord defines these capabilities from its own issuance, presentation, authorization, key-use and evidence requirements. Its core roles, interfaces and trust model MUST NOT require EUDI Wallet, EUDI ARF component names, EUDI trust infrastructure or EUDI-specific attestation and certification unless an explicitly selected ecosystem profile requires them.

A composition MAY select an independently designed wallet, another credential ecosystem, a platform holder service or an original holder architecture. It MUST define the actual interfaces, authority, custody and operation evidence required of that selection. Shared use of mdoc, OpenID or WebAuthn does not make a composition an EUDI deployment. EUDI-specific mappings and requirements remain local to an explicitly selected integration; they MUST NOT become hidden prerequisites for unrelated holders.

Ecosystem independence is evaluated by whether a holder can be specified and implemented against CertConcord's selected contracts without importing an unrelated ecosystem's architecture. Personal credential portability, device replacement and account recovery are separate operational capabilities. A composition need not implement them to establish ecosystem independence. When a deployment does migrate credentials or keys, the applicable lifecycle rules in [MIGRATION](../../docs/evolution.md#operational-holder-and-key-migration) govern that distinct operation.

## 8. Experiments, drafts and original standards

Any participant MAY develop and publish experiments, alternative mechanisms, new profiles, drafts and specifications within or alongside CertConcord. Experimentation does not require upstream maturity, upstream adoption or central permission from a particular implementation. Contributions incorporated into this repository follow its [contribution and rights policies](../../CONTRIBUTING.md).

An experimental artifact MUST identify its authoring authority, scope, revision, assumptions, changed semantics and intended compatibility. Experimental protocol use requires explicit peer and policy selection; new semantics MUST NOT be hidden under an existing stable identifier. Use test trust domains and synthetic identities when no real issuance or operational authority has been granted. Publishing a draft does not grant that authority.

Authors MAY investigate concrete gaps in current working drafts or define original capabilities within the scope in section 6. A proposed upstream change MUST identify its target revision and the behavior that existing mechanisms cannot express. Existing upstream objects retain the semantics of the revision they claim; divergent objects require an explicit original binding. Later upstream work MAY incorporate, overlap with or differ from such experiments. A convergence profile MUST describe the actual mapping and migration rather than relabeling earlier evidence.

Progression from an experiment to an interoperable draft and a stable profile requires explicit specification, executable behavior, evaluation and an identified adoption decision for the claimed scope. These are evidence requirements for deployment and conformance claims, not permission gates on research. A stable original specification need not wait for adoption by another standards body.

## 9. Transition and conformance

Adopting a successor architecture, governance model, protocol edition or holder ecosystem MUST identify the affected layers and the authority approving its deployment. Define the new requirements, evaluate the successor and its negative cases, settle pending operations, retire or explicitly delimit prior authority, and activate the new selection through authenticated policy. A new deployment MAY start with new credentials, keys, formats and verification interfaces, with no legacy runtime or compatibility bridge. Retained state and evidence keep their original meaning under the declared retention policy. Any supported rollback MUST NOT erase outcomes, restore spent permissions or lower monotonic security state. [MIGRATION](../../docs/evolution.md) supplies the current composition's operational transition rules; its old mechanisms do not constrain a successor's architecture.

A conformance claim MUST name the composition profile, framework edition, selected mechanisms and evaluated scope. Framework extensibility is not evidence that an implementation supports every possible alternative. A replacement is evaluated against its declared requirements, while an unchanged profile remains accountable for all its original mandatory requirements. Designated marks follow their separately registered scope and [mark policy](../../docs/conformance-marks.md).
