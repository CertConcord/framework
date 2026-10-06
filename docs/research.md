# Research and specification development

Standards interoperability and original specification/technology development are parallel core work. Research addresses concrete gaps in the intended certificate and document applications, including new capabilities and constructions. It must state its actual security assumptions and observable behavior.

The [upstream source classification](upstream-baseline.md) distinguishes established specifications and ecosystems, working drafts, experimental proposals, and implementation references across the complete source registry. Mature dependencies are adapted and studied for design ideas; they are not extracted into replacement-standard projects or targeted with new upstream drafts. This applies to all mature standards and interfaces, including certificate and cryptographic RFCs, timestamp and archival formats, ETSI, ISO mdoc, final OpenID protocols, established WebAuthn, PKCS #11, CSC and EUDI. Original capabilities may use their extension points or draw on their designs without changing their claimed upstream meaning.

## Public and private repositories

The public CertConcord repository contains reviewable drafts, published proposals, reference implementations and conformance evidence. The separate private CertConcord Labs repository is the workspace for unpublished designs and experiments. It starts from the same public draft commit and adds research material on a private research branch. A public GitHub branch is public, and a fork of a public repository is public under GitHub's [fork visibility rules](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/about-permissions-and-visibility-of-forks).

Private work is not automatically published by synchronizing repositories. Labs fetches public main as its upstream base. Public promotion uses a reviewed, minimal change set or patch after source, rights, identity-data and test-fixture checks. Never push the research branch, an unreviewed merge, private history or a private repository bundle to the public remote. Do not configure an automated bidirectional mirror.

Private storage does not establish novelty, ownership or cryptographic assurance. Existing licenses and third-party restrictions continue to apply. Public draft requirements cannot depend on undisclosed behavior needed for independent implementation.

## Proposal content

Each proposal records:

1. The application problem, affected shared-core requirements and why current mechanisms are insufficient.
2. Standard/research references, precise deviations and claims of compatibility.
3. Roles, trust boundaries, threat model, security/privacy goals and assumptions.
4. Complete keys, encodings, signed/encrypted inputs, algorithms, lifecycle, error and verification semantics.
5. An executable experiment, positive and negative vectors, comparisons and failure observations.
6. Unresolved questions, limitations, independent review and a proposed publication scope.

An upstream contribution identifies a concrete change against the latest applicable draft or editor text. A separate specification repository requires an independently describable technical contract or a focused upstream amendment, not merely a feature family or existing module name. Shared certificate trust and framework composition remain coherent through explicit versioned dependencies.

Source classification is edition-specific. A final protocol edition remains an adaptation dependency while its separately identified successor draft can be studied and improved. A protocol family's existing Final edition does not exclude its current working drafts from the research baseline.

Initial research themes are native mdoc signing certificates, Passkey signing/execution capabilities, successors or improvements to MTC issuance/transparency, and cryptographic suite/composition evolution. Application tracks evaluate those mechanisms against document, email and timestamp requirements through the same core.

## Progression

Exploration produces hypotheses and prototypes. A proposed draft fixes enough detail for review and reproduction. A reviewed candidate resolves blocking semantics, publishes its evidence and exposes an independently implementable contract. Stability requires the gates in [conformance](../spec/conformance.md), explicit review of remaining risks and a deliberate version decision. There is no automatic promotion to 1.0 based on elapsed time, file count or passing local tests.

The [component map](components.md) identifies independently maintained public drafts and focused amendments. Unpublished experiments remain in the private Labs repository. A component repository is not evidence of upstream submission or adoption.
