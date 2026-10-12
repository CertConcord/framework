# MTC document validation in CertConcord

The independent [MTC Document Validation draft](../spec/external/mtc-document-validation/draft.md) defines preservation horizons, offline evidence closure, independent monitoring, issuer retirement and renewal ordering. Its [repository](https://github.com/CertConcord/mtc-document-validation) also contains the targeted deployment-use-case clarification. The exact selected commit and snapshot hashes are in [components.lock.json](../components.lock.json).

## Framework selection

CertConcord selects standalone MTC before document signing, the published draft-06 verifier and separately admitted issuer/cosigner policy. The latest MTC editor is a research comparison, not an advertised replacement wire profile. MTC, C2SP and Root Registration Authority governance remain separately sourced mechanisms in this composition.

The framework adds subject qualification, signing purpose, exact intent, activation, one-use authorization, organizational grants when required, and operation evidence. Those checks belong to the shared trust core and selected document binding. An issuance proof does not establish a later signing operation, and identity-source acceptance does not appoint a signing issuer.

## Evidence and reference implementation

The [preservation contract](document-preservation.md) maps the independent requirements to the existing CMS evidence package and RFC 4998 adapter. Its lifetime checker is imported from the pinned independent component; TSA verification and historical status resolution remain framework adapter responsibilities.

The offline SDK requires caller-provisioned trust and complete original evidence. Missing dependencies or stale required status cannot yield VALID. Historical replay and current admissibility retain distinct state and knowledge times. Archived evidence does not lower live trust watermarks.

PAdES, CAdES and JAdES remain adaptations of the selected ETSI editions. CMS evidence verification and detached ERS are implemented for the declared path. The separate selected [CAdES](cades-preservation.md) and [PAdES](pades-preservation.md) adapters implement ATSv3 and PDF DSS/document-timestamp renewal under explicit classical P-256/direct-root profiles. Those selections do not establish MTC/PQC AdES conformance. JAdES augmentation, broader algorithm/path coverage and operational archive assurance remain gaps; detached ERS alone does not establish an AdES LT/LTA level.

## Evaluation

Run the archive example and document/archival security tests through the [reference implementation](../reference/README.md). They cover signer-certificate expiry, issuer unavailability in the synthetic path, TSA and hash renewal, stale status and retrospective compromise. Independent operator deployment and a general historical trust resolver require further evidence.
