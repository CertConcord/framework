# CertConcord

**Certificate trust for document signing and encryption, with transparent issuance and post-quantum evolution.**

**Working draft 03 · reference software 0.3.0-draft.1 · no stable specification release.**

CertConcord develops certificate structures and trust protocols around **MTC-based issuance and transparency, post-quantum cryptography, native mdoc signing certificates, and expanded Passkey capabilities**. The initial lifecycle is **MTC/PQC for long-term documents**: intentional signing, retained certificate and status evidence, offline verification after issuer retirement, and timely preservation renewal. Signer-certificate validity and document retention have distinct lifetimes.

## Design focus

- **Transparent certificate issuance for document workloads.** Merkle Tree Certificates (MTC) provide the initial issuance and transparency architecture. Its proof structures, operator roles and evidence distribution are evaluated against document use, including retained evidence and historical verification. Alternative architectures can replace it through a fully specified binding.
- **mdoc as a signing certificate.** Native credentials bind a person or organization, an exact operation key and an authorized purpose. An adopting CA can issue this representation directly. Credential presentation, holder authentication and document signing have distinct verification rules.
- **Passkey capabilities beyond login.** Ordinary WebAuthn authorizes a separately admitted document key. Proposed raw signing remains an optional experiment with explicit upstream and device dependencies; it is not a hard dependency of the document baseline.
- **Post-quantum security with explicit boundaries.** Certification, holder proof, document signatures, encryption and retained evidence have separately stated security properties. Cryptographic suites can evolve while evidence retains its original meaning. A post-quantum issuer signature does not change the security of a classical holder signature.
- **Standards integration and original research.** Existing standards provide interoperable building blocks. Original certificate formats, protocol extensions and cryptographic constructions are evaluated through explicit assumptions, test vectors and independently implementable verification rules.

## Application scope

**Document trust processing** is the first complete specification baseline under development: personal signatures, organizational signatures and seals, document encryption, status and revocation, independent verification, and the time and historical evidence these operations require. S/MIME and standalone trusted timestamp services advance as separate application tracks built on the **same certificate trust core**.

EUDI, government mDL and photoID are optional interoperability environments and identity sources. An RA can validate an accepted identity credential before a CA issues a signing certificate. Identity-source acceptance and signing-issuer trust remain separate policy decisions. The framework supports independent issuers, wallets and verifiers.

## Start here

| Read                                                       | Purpose                                                                                    |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| [Architecture](spec/architecture.md)                       | Mission, boundaries, replaceable mechanisms and independent adoption                       |
| [Shared certificate trust core](spec/trust-core.md)        | Subject, key, purpose, authority, issuance, lifecycle and evidence                         |
| [Document baseline](spec/document-baseline.md)             | The complete first application and its explicit completion criteria                        |
| [MTC document validation](docs/mtc-document-validation.md) | Standalone certificates, offline evidence, independent monitoring and archival obligations |
| [Document preservation](docs/document-preservation.md)     | Executable MTC/PQC lifecycle, TSA and hash renewal, historical and current results         |
| [CAdES preservation](docs/cades-preservation.md)           | Selected standard B/T/LT/LTA path, direct-root CRLs and ATSv3 renewal                      |
| [PAdES preservation](docs/pades-preservation.md)           | Selected PDF B/T/LT/LTA path, revision-bound DSS and document timestamp renewal            |
| [Timestamp application](docs/timestamp-application.md)     | Standard RFC 3161 issuance, client requests, current trust decisions and durable recovery  |
| [mdoc certificates](spec/mdoc-certificates.md)             | Identity admission, native signing credentials and issuer trust separation                 |
| [Passkey credentials](spec/passkey-credentials.md)         | Authentication, signing extensions and experimental execution bindings                     |
| [Profiles and maturity](spec/profiles.md)                  | Which candidate bindings and external standards are selected                               |
| [Composition review](docs/composition-review.md)           | Standard reuse, additional semantics, dependency order and reductions                      |
| [Conformance and gaps](spec/conformance.md)                | Requirement-level evidence and work needed before stability                                |
| [Research and evolution](docs/research.md)                 | Private experiments, public proposals, review and version transitions                      |
| [Reference implementation](reference/README.md)            | Executable flows, tests, SDK and optional platform integrations                            |

## Independent drafts

The framework composes separately maintained [MTC document validation](https://github.com/CertConcord/mtc-document-validation), [mdoc signing certificates](https://github.com/CertConcord/mdoc-signing) and [ML-DSA-87 cosignature](https://github.com/CertConcord/tlog-cosignature-ml-dsa) drafts. Focused [signing-context](https://github.com/CertConcord/signing-context) and [PassSign evidence](https://github.com/CertConcord/passsign-evidence) amendments remain proposals.

The [component map](docs/components.md) identifies canonical ownership, exact commits, local snapshots and integration roles. Independent drafts do not require this framework's governance. All application tracks retain the same certificate trust core.

## Repository map

- **spec/**: current draft contracts, application scope, conformance, and detailed candidate bindings.
- **reference/**: executable reference flows, adapters, tests and synthetic vectors. Platform examples and proposed protocols state their limits.
- **docs/**: implementation explanations, optional ecosystem mappings, research process and evolution policy.
- **tools/**: draft integrity and publication checks.

A draft document can contain normative requirements without being a final standard. Passing the reference tests does not establish independent interoperability, production assurance, regulatory qualification, or patent clearance. [Conformance](spec/conformance.md) records these distinct questions and the current gaps.

MTC certificate/proof semantics, C2SP mirror/witness protocols and RRA governance have distinct origins. Their selection and combination here belong to CertConcord. The reference parsers and verifier SDK demonstrate protocol semantics; production implementations should use mature, independently evaluated parser/crypto stacks and enforce the [additional semantic checks](spec/bindings/SEP-draft-03.md#2-parser-and-execution-boundaries).

## Run the reference

Use Node.js 24.15 or later within the range in [package.json](package.json). Run commands from the repository root:

```sh
npm ci
npm run check
npm test
npm run demo -- --identity=custom --passkey
npm run demo:mtc -- --passkey
npm run demo:mtc -- --passkey --trusted-time
npm run demo -- --identity=custom --passkey --trusted-time
npm run demo:document
npm run demo:archive
npm run demo:passkey -- --v4 --split --mtc
npm run sdk:build
npm run sdk:test
```

The document example covers organizational authorization, MTC issuance, a seal with trusted-time evidence, certified ML-KEM recipients, encrypted delivery, verification after decryption, and two-operator encryption-key recovery. Its [binding](spec/bindings/DOCUMENT-draft-03.md) states the exact evidence and limitations. The [security-claim matrix](docs/security-claims.md) separates the assurance of each path.

The archive example retains the complete MTC document evidence package through TSA replacement, hash renewal and signer-certificate expiry. It separates preserved historical validation from current admissibility; stale current status cannot yield VALID. Second-implementation and external-assessment evidence belong to later stability gates, not prerequisites for this draft research.

The examples use generated software keys, synthetic identities and a synthetic clock. The raw Passkey signing example exercises a selected proposal through a software authenticator; it is not a claim that ordinary deployed Passkeys implement that extension. Independent CMS KEM exchange requires OpenSSL 3.6 or later; CI pins OpenSSL 3.6.5 and requires the check. Use OPENSSL_BIN to select a compatible executable. A 3.5 build can run the signature checks but cannot establish CMS KEM interoperability.

No stable tag, GitHub release or npm publication is part of draft 03. The manual draft-artifact workflow produces review artifacts only. Both npm packages remain private to prevent accidental registry publication; the repository itself is public.

## Participation and rights

Software and executable schemas use [Apache-2.0](LICENSE); original specifications and documentation use [CC BY 4.0](LICENSES/CC-BY-4.0.txt); original synthetic vectors use [CC0](LICENSES/CC0-1.0.txt). See [licensing](LICENSING.md), [contribution requirements](CONTRIBUTING.md) and [patent records](PATENTS.md). No executed specification patent commitment or conformance mark grant is recorded in the current register.

Report vulnerabilities through [private vulnerability reporting](https://github.com/CertConcord/framework/security/advisories/new). Use issues for draft questions and interoperable implementation feedback.
