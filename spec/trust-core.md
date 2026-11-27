# Shared certificate trust core — draft 03

This document defines common draft requirements for every CertConcord application. Requirements are independent of a particular certificate format. Concrete encodings and algorithms come from a selected [binding](profiles.md); the framework-level contract alone is not a wire protocol.

## Core requirements

| ID         | Requirement                                                                                                                                                                                                                                                                                                                                                                                 |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CC-CORE-01 | A verifier MUST receive its trust-domain authorities and acceptance policy from an authenticated external configuration. Evidence presented for verification MUST NOT appoint its own trusted issuer or weaken that policy.                                                                                                                                                                 |
| CC-CORE-02 | An issued credential MUST bind a qualified subject, the exact public key or key commitment, allowed purposes, issuer authority, policy, lifetime, status mechanism and profile revision. Proof of possession or an explicitly specified equivalent MUST cover that same key and request.                                                                                                    |
| CC-CORE-03 | Identity-source acceptance MUST be separated from certificate issuer admission. A successful presentation or RA decision MUST NOT transfer authority beyond its recorded subject, key, purpose, audience and issuance scope.                                                                                                                                                                |
| CC-CORE-04 | The selected issuance/transparency mechanism MUST specify accountable issuance records, inclusion/consistency evidence where applicable, operator independence assumptions, privacy, availability, failure behavior and recovery. A missing required proof MUST NOT be treated as success.                                                                                                  |
| CC-CORE-05 | An operation MUST bind the exact document or message input, intended operation, key, credential representation, purpose, authority, policy, context and freshness. The execution contract MUST define replay handling, uncertainty, retries and reconciliation. Authorization evidence alone MUST NOT be reported as the requested cryptographic result.                                    |
| CC-CORE-06 | Keys and credentials MUST have explicit issuance, activation, renewal, suspension/revocation, replacement and compromise semantics. Status decisions MUST bind their authority, scope, evaluation time, publication time and freshness. Key recovery MUST NOT silently preserve superseded authority.                                                                                       |
| CC-CORE-07 | Verification MUST distinguish VALID, INVALID, INDETERMINATE and UNSUPPORTED. VALID means the selected implemented policy is satisfied; INVALID means an evaluated check failed; INDETERMINATE means required evidence or a decision is unavailable; UNSUPPORTED means a required known boundary cannot be evaluated by this implementation. Every non-VALID result MUST prevent acceptance. |
| CC-CORE-08 | Each selected path MUST declare its algorithms, parameters, composition and security assumptions, including any classical dependencies. Claims MUST identify the assertion actually protected, its time horizon and relevant key-custody assumptions.                                                                                                                                       |
| CC-CORE-09 | A version change MUST preserve unambiguous historical interpretation: original bytes, identifiers, relevant authority/status history and a declared supported verification path and retention scope. New revisions MUST NOT silently reinterpret old proofs.                                                                                                                                |
| CC-CORE-10 | New application profiles MUST select this core and declare their additional subject qualification, purpose, operation, container, status and evidence rules. Reuse of a subject or key across purposes requires explicit policy and cryptographic justification; shared semantics do not imply unrestricted key reuse.                                                                      |

The relying party MUST select authenticated trust and policy independently of
the submitted evidence. An implementation that retains a verifier instance MUST
bind its configured data bytes and nested policy values to that selection;
mutation of caller-owned objects after construction MUST NOT silently change
the selection. A deliberate pin or policy rotation uses a new verifier
selection. External callable authority and status sources remain separately
authenticated policy inputs. A deployment MUST bind each source to tenant,
trust domain, authority identity, role and scope; select one source revision
throughout an evaluation; preserve later-known negative history; and treat
unavailable, stale or asynchronous decisions as non-VALID. It MUST retain the
source revision and decision inputs needed to audit the selected result. This
does not make an arbitrary callback response self-authenticating. An external
callback MUST receive query data isolated from the selected evaluation's
private trust bytes. These rules elaborate CC-CORE-01, CC-CORE-06, CC-CORE-07
and CC-CORE-09.

Time bounds retain their defined types during composition. X.509 `notAfter` is
inclusive under [RFC 5280 §4.1.2.5](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5).
Appointment, algorithm and status freshness deadlines are exclusive, as are
the selected MTC cache and mdoc credential deadlines. A conservative proof
upper bound MUST fall strictly before a selected timestamp certificate's
`notAfter` when that bound stands for an uncertain actual generation instant.
The inclusive certificate endpoint does not extend any exclusive bound. These
time rules refine CC-CORE-05, CC-CORE-06 and CC-CORE-09.

## Logical credential model

A credential records a subject reference and qualification scope; a key representation and possession/custody evidence; an issuer and trust-domain context; permitted operations and relying-party restrictions; suite/profile identifiers; issuance, lifetime and status references; and required transparency/evidence bindings. Each concrete representation MUST state how these fields are authenticated and which fields are critical. Unknown critical semantics prevent acceptance.

RA qualification evidence supports an issuance decision. The CA's credential establishes the certified subject-key-purpose relationship within its trust domain. The operation's authorization and resulting signature or encryption evidence establish what was done with that relationship. These are distinct claims even when one operator performs several roles.

## Verification result contract

Every SDK input-evaluation result contains `overall`, a nonempty `reason`, `coreRevision`, `profile` and `dimensions`. `coreRevision` is `draft-03`; `profile` is the parsed candidate plan label or `null` when no usable label was parsed. A reported label does not establish support or acceptance. Invalid external verifier configuration throws before input evaluation.

The fixed dimension names are `integrity`, `issuerTrust`, `qualification`, `keyBinding`, `authorization`, `status`, `time` and `transparency`. Each reported dimension has its own `overall` and nonempty `reason`. Omitted dimensions are not established by the completed checks. A checked object commitment alone cannot establish complete signature integrity, and the presence of trust configuration cannot establish that its mechanism was used. A VALID dimension covers only the checks required by the selected policy. In particular, a policy that permits execution time without a trusted existence proof does not acquire trusted time from that result.

Malformed encoding, altered commitments, failed available signatures, inconsistent algorithm/key selections and applicable policy rejection return INVALID. A referenced but unavailable object or unavailable required decision returns INDETERMINATE. A structurally valid unimplemented schema, plan or explicitly classified algorithm/critical-feature boundary returns UNSUPPORTED. Unknown capabilities do not authorize algorithm substitution, implicit fallback or weaker policy. The selected CMS, COSE and native mdoc boundaries distinguish malformed discriminators from valid unimplemented selections; the mdoc base classification belongs to the pinned independent component.

An established applicable INVALID check takes precedence over UNSUPPORTED or INDETERMINATE. For a supported flat plan that cannot complete, the verifier can still evaluate independent available checks whose original inputs and required external authority are present. It does not fabricate a missing dependency or interpret an unknown plan as a supported one. A receipt's signed time is usable for status evaluation only after binding its operation, activation, permit, key, signed message and signature to the current document; an unrelated authentic receipt supplies no time for that operation. Separate failures remain visible in their own dimensions even when their reason codes match. When no invalid check is established, a required unsupported capability takes precedence over missing evidence. All non-VALID outcomes prevent acceptance. The [conformance record](conformance.md) and [public vectors](../reference/vectors/document-acceptance-mtc07-rar2-mdoc2/README.md) bound the implemented result contract; they do not claim support for every external format or future extension.

## Composition selection

The initial candidate composition is certconcord-governed-draft-03. [COMMON](bindings/COMMON-draft-03.md), [DTI](bindings/DTI-draft-03.md) and the selected domain bindings supply executable details. Alternative mechanisms must satisfy these core duties through their own explicit contracts; they do not inherit RRA, MTC or a particular wallet merely by implementing CertConcord.
