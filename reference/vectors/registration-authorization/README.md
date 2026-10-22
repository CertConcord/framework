# Registration authorization boundary bytes

`contract.json` contains six fixed, public input records: X509, MTC and MDOC qualification binding with schema 2 and authenticated schema 1. Each `material` is base64 deterministic CBOR containing exact signed CMS bytes, the corresponding certificate commitment or MDOC claims, and separate public trust inputs. The scenario time is 1800000000 Unix seconds.

Authorization bodies were authored explicitly without `RegistrationAuthority` or `issueRAR`, using shared reference PKI primitives. Schema 1 inputs have matching commitments; they fail because the selected contract requires schema 2. The MDOC boundary records assume an already authenticated credential; the separate document corpus exercises complete native MDOC verification. These are synthetic contract vectors, not a second implementation or security assessment.

Run `node --test reference/registration-authorization.test.mjs` from the repository root. Replay verifies existing bytes and does not re-sign the stored controls.
