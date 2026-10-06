# CertConcord draft verifier

Package: @certconcord/verifier, version 0.2.0-draft.1. The experimental API exports createVerifier and profiles. It evaluates the selected CMS/MTC/X.509 or native signer-mdoc/COSE evidence plan, including supported Passkey and execution-binding candidates. It is not a stable API or a complete independent conformance assessment.

This package demonstrates protocol semantics and supports interoperability testing. Its bundle includes custom DER, CBOR and CMS parsing from the reference implementation. It is not a recommended production verifier or parser security boundary. Production implementations SHOULD use mature, independently evaluated parser and cryptographic stacks for the enabled formats and algorithms, while enforcing CertConcord's additional semantic checks: exact original bytes, duplicate/critical-field handling, algorithm and key purpose, external trust, operation authorization, lifecycle, time and evidence completeness. See [the parser contract](../../spec/bindings/SEP-draft-02.md#2-parser-and-execution-boundaries). Worker isolation and passing the test suite do not replace that evaluation.

```js
import { createVerifier } from '@certconcord/verifier';
const verifier = createVerifier({ format: 'CMS', trust: relyingPartyTrust });
const result = verifier.verify(evidenceBytes);
if (result.overall === 'VALID') {
  // Apply the application's access and disclosure policy separately.
}
```

The trust argument comes from authenticated relying-party configuration. Issuer/root pins, MTC members and quorum, credential-seal and activation/receipt authorities, expected policy and trust domain must not be supplied by the evidence being checked. PSCP requires the authoritative passkeyStatus callback. A selected execution-binding policy additionally requires executionBindingCertificate and an executionStatus callback. Incorrect verifier configuration throws before input evaluation.

Selecting the [document evidence binding](../../spec/bindings/DOCUMENT-draft-02.md) additionally requires the RA certificate for CMS. Organizational seals require an externally configured organization-to-authority mapping. Required trusted time needs a TSA certificate, issuer key, policy OID and a status callback receiving generation time, proof upper bound and knowledge time. That callback must evaluate relying-party-authorized status information; an unconditional callback is appropriate only to an explicitly synthetic fixture.

## Results

| overall       | Meaning                                                                                                                                         |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| VALID         | The implemented checks for the selected policy succeeded. This does not independently grant application access or legal status.                 |
| INVALID       | Malformed encoding, inconsistent commitments, failed signatures or a failed applicable policy check.                                            |
| INDETERMINATE | Required evidence/accuracy is unavailable, selected CMS/organizational status is stale or unknown, or required trusted time is not established. |
| UNSUPPORTED   | The structurally checked envelope/plan revision or plan profile is not implemented by this verifier.                                            |

All non-VALID results prevent acceptance. Results include coreRevision and, after successful plan selection/evaluation, profile; reason and individual dimensions are present where evaluated. Fine-grained unsupported classification inside every algorithm/container remains incomplete. Low-level research modules retain their historical result strings; this SDK normalizes their successful result to VALID.

Verification is synchronous and does not fetch evidence URLs. Input is deterministic CBOR, limited to 16 MiB by default and at most 64 MiB by configuration. Use a resource-limited worker for hostile inputs. Deep imports, private-key custody, signing services, enrollment and storage are outside the API.

Build with npm run sdk:build from the repository root. Install the generated reference/dist/certconcord-verifier-0.2.0-draft.1.tgz locally. The package is private to prevent registry publication, while tarball installation is supported. The manual draft-artifact workflow produces review artifacts; no stable GitHub release or npm publication is configured. The package contains Apache-2.0 software and bundled dependency notices; original documentation is CC-BY-4.0.

The previous research SDK's VALID_UNDER_POLICY and REJECTED strings are not this draft API's contract. Consumers must explicitly handle all four values above. Historical protocol bytes are otherwise preserved unless a specific new binding is selected.
