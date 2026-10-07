# Optional rights and conformance register

The register stores reviewed legal and assessment records independently of protocol credentials. It is available for explicitly selected agreement and assessment processes, not as a prerequisite for ordinary repository contributions. It contains no root keys, signatures made on behalf of unregistered parties or implicit awards. An empty collection means that no corresponding record is registered.

## Record model

[registry.json](registry.json) has schema version 1 and six collections. [registry.mjs](registry.mjs) is the strict executable schema: unknown fields, duplicate identifiers, broken references and invalid timing are rejected.

| Collection      | Required evidence and scope                                                                                                                                                |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `holders`       | Actual legal name, authority evidence and registrar review receipt                                                                                                         |
| `agreements`    | `OWFA_PATENT_ONLY_1_0` or `OWF_CLA_1_0`, holder, identified specification snapshot, executed instrument digest/URI, signing date, authorized contributor emails and review |
| `contributions` | Agreement, exact normative change digest, authoritative submission receipt date, review and any withdrawal notice                                                          |
| `marks`         | Exact designation, recorded holder, policy digest, authority instrument and ordered lifecycle events                                                                       |
| `plans`         | Mark, specification snapshot, role/profile, exact suite, eligible assessors/category and requirement-to-test mapping approved by review                                    |
| `grants`        | Plan, grantee, implementation/version/environment, source/configuration/manifest/report digests, executed grant, validity interval and lifecycle events                    |

Every evidence reference is an HTTPS URI plus a SHA-256 digest of the preserved original bytes. The URI may identify a public, redacted receipt whose digest commits to a private instrument. The signed review receipt identifies the private custodian, full-instrument digest, review method and authority decision. The registrar verifies authenticity and legal authority before accepting a record. The tool validates structure and relationships; an HTTPS address or a matching hash alone does not establish authenticity.

Dates use UTC with millisecond precision. Mark and grant events are strictly ordered `ACTIVE`, `SUSPENDED` or terminal `REVOKED` decisions. Expiration is automatic at `validUntil`. Reinstatement after suspension requires a new authenticated event; a revoked grant requires a new grant ID. Registry reviews and event receipts precede the decisions for which they are used.

## Registration and trust

1. The applicant completes the applicable [form](forms.md) and supplies execution/authority evidence to a designated custodian. Use the original agreement text and preserve its digest; do not publish signature credentials or unnecessary personal data.
2. A registrar verifies the actual holder, representative and scope, and records an authenticated decision. Initial registrar authority must itself be established by the rights holder; repository access alone confers no power to sign or grant that holder's rights.
3. Publish the non-sensitive record in a separate reviewed change to the protected register. Preserve earlier IDs, immutable instruments and corrections through source history. New commitments and replacement grants receive new IDs. Withdrawal and suspension records remain visible.
4. Consumers pin a trusted register snapshot through the protected repository revision or an authenticated distribution. The CLI requires its byte SHA-256 independently of the applicant's inputs. Do not accept the applicant's supplied register and digest as an authority source.
5. A dependent contribution or mark check uses that previously trusted snapshot. It cannot promote a record supplied inside the request into trusted authority.

Register maintenance is an administrative review, not a certification ceremony. A valid structure result does not mean that any mark, patent agreement or signatory exists. Updates affecting earlier rights require evidence of the applicable legal effect and retain the original executed instrument.

All direct commands below run from the reference directory; SOURCE_DIRECTORY for the complete specification is the repository root.

## Optional agreement-specific contribution checks

These commands implement a strict DCO/CLA registration profile for a process that explicitly selects it. They do not define the repository's ordinary contribution policy or impose a merge requirement. Routine contributions follow [CONTRIBUTING.md](../../CONTRIBUTING.md).

`SUBMISSION.json` has `files`, `commits` and `additionalNormativePaths`. A file has `path`, Git blob `sha`, `status` (`added`, `modified`, `removed`, `renamed`) and nullable `previousPath`. A commit has `sha`, `name`, `email` and complete `message`. Mixed changes containing software require matching DCO trailers for all authors and co-authors in the submitted commits. Contributors identify normative changes outside the default paths in `additionalNormativePaths`; GitHub pull requests use one `Normative-Path: relative/path` line per such file.

The normative digest is SHA-256 of canonical JSON for the path-sorted selected file records. Canonical JSON recursively sorts object keys and preserves array order, UTF-8 strings, integers, booleans and null without extra whitespace. It binds content and deletion/rename operations without depending on an incidental rebase commit ID. The registrar records that digest after observing the submission through its original channel. Every identified contributor requires coverage by a reviewed CLA registration. The check rejects withdrawn material and reports the 45-day window; `finalize` additionally rejects an open window. It does not report final OWFa coverage from a CLA.

```sh
node governance/cli.mjs validate governance/registry.json
node governance/cli.mjs contribution SUBMISSION.json TRUSTED-REGISTER.json TRUSTED_SHA256
node governance/cli.mjs finalize SUBMISSION.json TRUSTED-REGISTER.json TRUSTED_SHA256
```

The GitHub `review-contributions` job runs only when manually requested against `main`. Without a PR number it validates register structure. An explicitly supplied PR number selects the strict profile above and publishes an optional `contribution-policy` status on that head. It reads the protected base and PR metadata without executing PR source. Register entries proposed by that PR cannot satisfy its own check. Metadata changes during collection fail closed. No certification is inferred for historical commits.

## Specification snapshots

An OWFa identification schedule names an immutable snapshot and its conformance unit. `SELECTION.json` contains `name` (`CertConcord`), `edition`, a 40-character `sourceCommit`, arrays `roles`, `profiles`, `adapters`, and `requiredPortions`, each with `path` and nonempty `sections`. It also identifies `framework` with `edition` and `document`, and `composition` with `id`, `specification` and `conformance`. The referenced documents must be included in the required portions. Whole-file coverage uses `sections: ["all"]`.

For `certconcord-governed-draft-03`, use framework edition `draft-03` and document `spec/architecture.md`, composition specification `spec/bindings/DTI-draft-03.md` and conformance document `spec/conformance.md`; include `spec/bindings/COMMON-draft-03.md` and all other mandatory portions for the selected roles/capabilities. Another composition identifies its own normative and conformance documents; the command does not require RRA or MTC documents merely because it produces a CertConcord snapshot. A registrar verifies the composition's authenticity, applicability and complete requirement closure. The minimum path checks do not establish that a proposed profile is supported, conforming or patent-covered, and selecting fewer files cannot redefine OWFa's required-portions condition.

```sh
node governance/cli.mjs snapshot SELECTION.json SOURCE_DIRECTORY SNAPSHOT.json
```

The command hashes the exact source bytes, rejects path escapes and existing output files, and prints the snapshot digest. The registrar additionally verifies that source bytes match the identified revision, reviews required portions and settles contribution withdrawal periods before a final-specification commitment is executed. New source bytes create a different snapshot. An unsigned snapshot is an identification artifact, not an executed agreement.

## Mark evaluation

Import the assessment report and artifacts using the integrity rules in [ASSURANCE.md](../../docs/assurance.md). A trusted plan maps all applicable requirements to required test/review-result IDs and names the authorized assessor and exact suite. A grant records the report's canonical JSON SHA-256 and exact implementation/configuration. The administrator verifies report authenticity before execution of the grant.

```sh
node governance/cli.mjs mark GRANT_ID REPORT.json ARTIFACT_DIRECTORY TRUSTED-REGISTER.json TRUSTED_SHA256
```

The evaluator requires current mark and grant authority, a valid interval, an exact report/suite/assessor/scope binding, intact artifact bytes and PASS for every required ID. Missing, failed, indeterminate or inapplicable required results cannot pass. Its `ACTIVE_RECORDED_GRANT` conclusion is relative to the caller's authenticated register. It does not award new marks or authenticate a legal signature from its hash.

The optional `contribution-policy` status is not a required branch-protection check for routine contributions. Manual evaluation accepts an optional PR number only from `main`; an empty manual invocation validates register structure without granting a PR status. An optional agreement review does not replace technical checks or create a conformance grant.
