# Preserved external certificate status

This separate synthetic corpus contains exact public CMS and RFC 4998 bytes for the selected credential's external CertificateStatus. It uses the existing organization-history corpus encoding and replay runner. The original organization-history corpus remains separate.

```sh
node reference/verify-organization-vectors.mjs reference/vectors/preserved-certificate-status
node --test reference/preserved-certificate-status.test.mjs
```

The cases distinguish original document proof P, signed status publication S, independent status proof P_status and selected knowledge K. They cover valid preserved status, ordinary post-P revocation, retrospective compromise, exclusive protection and renewal deadlines, exact CMS binding, signer role and scope, later authority incidents, missing current coverage, conflicting status and invalid supplied ERS under an otherwise current signer. Original package authorization and preservation remain separate result dimensions.

The manifest inventories original bytes, exact status CMS and ERS material, public relying-party configuration, signed authority history and complete expected results. Replay performs no signing, key generation, timestamp issuance, repair or network access. It does not use the wall clock. Expected results are compared after verification and cannot supply an authority decision.

`tools/freeze-preserved-certificate-status-vectors.mjs` constructs inputs with ephemeral synthetic keys and writes only public data. Its separate capture function refuses an existing manifest and requires the exact reviewed digest of `reference/preserved-certificate-status-semantics.mjs`. The oracle fixes result states, primary rejection reasons and temporal distinctions before complete-result capture. Input and source hashes describe construction; they are not authority signatures or executing-code attestation.

The dedicated durable tests admit preserved compromise without a valid original, reopen in fresh guarded processes, and verify that later GOOD cannot erase applicable negative knowledge. A retained positive status cannot replace missing current coverage. These checks establish bounded draft reference behavior, not operational custody, independent implementation conformance, complete-store rollback detection or current execution permission. Separate ERS for organization delegation status remains outside this selection.
