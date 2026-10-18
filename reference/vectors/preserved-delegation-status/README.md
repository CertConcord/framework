# Preserved external delegation status

This synthetic corpus contains 50 cases with exact public OrganizationDelegationStatus CMS and RFC 4998 bytes. It uses the existing organization-history encoding and public replay factories. The selected credential's CertificateStatus has a [separate corpus](../preserved-certificate-status/README.md).

```sh
node reference/verify-organization-vectors.mjs reference/vectors/preserved-delegation-status
node --test reference/preserved-delegation-status.test.mjs
```

The cases distinguish original package proof P, signed status publication S, independent complete-CMS proof P_status and selected knowledge K. Positive cases cover GRANT, APPROVER_REGISTRATION and FINAL_AUTHORIZATION. Negative cases exercise exact target and signer bindings, scoped roles, exclusive protection and renewal deadlines, future proof bounds, stale GOOD, retrospective incidents, conflicts and invalid supplied proofs.

An external CMS that also appears in the original package retains both obligations: its attached status ERS must validate, and its original status authority must still be admitted at P. The retirement counterexample includes fresh successor status, so stale positive coverage cannot mask a missing P check. Duplicate bytes are merged only after their applicable proof and authority checks.

The manifest inventories original packages, exact status CMS and ERS bytes, public relying-party configuration, signed authority history and complete expected results. Replay performs no signing, key generation, timestamp issuance, network access or wall-clock reads. Expected results are compared after verification and cannot establish trust.

`tools/freeze-preserved-delegation-status-vectors.mjs` constructs public inputs with ephemeral synthetic keys. Its capture function refuses an existing manifest and requires the exact digest of `reference/preserved-delegation-status-semantics.mjs`. That oracle fixes the result dimensions, primary reasons and package-proof bounds before capture. Provenance hashes describe construction sources; they are not authority signatures or executing-code attestations.

The durable tests retain the original evidence pair needed to admit organization targets and the exact separately preserved status bytes. Fresh processes reauthenticate that material, preserve compromise across newer GOOD and reject an altered ERS even when content hashes are recomputed. A separate status proof cannot create an organization target without a valid original package proof, extend current positive coverage or replace original-package authority admission. The v2 durable capability rejects v1 bindings rather than silently changing their meaning.

This is a bounded draft selection. Organizational mdoc, arbitrary delegation graphs, per-object proofs replacing the first complete-package proof, operational custody assurance and complete-database rollback detection without an external anchor remain outside its claims. Historical verification grants no current execution permission.
