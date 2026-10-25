# Fixed CMS issuer-retirement lifecycle

This packet retains one original document evidence package and its existing RFC 4998 records. It adds a distinct status signer under an explicitly selected synthetic governance policy. The original CMS signature is not regenerated. The new governance policy is not represented as a continuation signed by the original fixture roots.

The original package SHA-256 is `09e93450939c93b3dce9daa2ab8f278a357701b46d2d93f0c4fba3c9a0839133`; the timely ERS SHA-256 is `148c25cb9fb9c16846eb14ece6bc8927bdf442444d7ff76168b680236b343050`. The original package contains the ordinary WebAuthn authorization of a separate ML-DSA document key, standalone MTC, exact intent and scope, signed operation controls, status and a document timestamp.

The fixed seconds are S=1792454400, P=H=1792454402, R=1792454502 and K=1792627202. S is the original claimed status publication time; P is the verified first complete-package upper bound; H and K are historical and current knowledge cutoffs; R is the end of the selected old ISSUER and STATUS_AUTHORITY appointments. P precedes R. This does not infer an exact real signing instant from a claimed time. Other roles retain their independently stated intervals.

The manifest contains one original-document case and fourteen retained cases. Each retained case reports preservation, historical authorization and current admissibility separately. The positive case requires all three VALID under the explicit test policy. Missing current authority or stale current status remains INDETERMINATE. Wrong role, scope, target or operation is INVALID. Missing first proof cannot yield historical authorization. Missing or late renewal fails preservation even when the intact first proof still establishes historical authorization. Later applicable compromise survives a later GOOD entry. An authenticated fork cannot provide current authority or current archive-TSA admission.

All signatures and times are synthetic fixtures. Replay uses stored public inputs, fixed knowledge times and existing verification entry points; it requires no private keys, signing operation, network access or present wall-clock value. Full production trust, operational archive availability and hardware custody are separate claims. Detached ERS does not establish PAdES-LTA or MTC/PQC AdES conformance.

A second implementation must consume these same bytes and state its independently verified results and unsupported or unavailable conditions. A Framework VALID is not evidence that another implementation has accepted the complete policy.

## Offline replay

The corpus uses the existing `certconcord-document-acceptance-vectors-draft-03-mtc07-rar2-mdoc2` schema. Run from the repository root:

```sh
node reference/verify-vectors.mjs reference/vectors/cms-retirement-mtc07-rar2
node --test reference/cms-retirement-vectors.test.mjs
```

The manifest records encoded and decoded lengths and SHA-256 hashes. Its 53 files contain public keys, certificates, signed inputs and closed data-only configuration. The original package, original trust configuration and archive records are byte-identical to the matching entries in [the document acceptance corpus](../document-acceptance-mtc07-rar2-mdoc2/README.md). Supplemental current status and authenticated histories are separately signed fixtures; they neither rewrite the archived original nor repair an expired preservation interval.
