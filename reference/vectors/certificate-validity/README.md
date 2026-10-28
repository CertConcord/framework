# Certificate validity Time vectors

These public synthetic DER certificates cover 1949 compatibility, the 1950 UTCTime pivot, negative Unix seconds, the 2000 pivot, the current era, leap day, 2049, the 2050 transition, 2050, and year 9999. Each period includes a retained GeneralizedTime certificate and a certificate emitted with the issuer Time choice. The certificates use fresh P-256 keys and signatures; no private keys are included.

The MTC cases use a synthetic ML-DSA-65 subject, an ML-DSA-87 authority, and three ML-DSA-87 independent cosigners. They retain exact TBSCertificate, log-entry, tree-root, standalone-proof and landmark-proof bytes for current-era, mixed UTCTime/GeneralizedTime, and post-2049 certificates. The two-leaf mixed log commits an older GeneralizedTime leaf followed by a new UTCTime leaf, retaining the earlier prefix root.

Replaying the corpus verifies signatures, raw time fields, instants, certificate IDs and proof modes without regenerating signed inputs. Paired substitutions in both directions demonstrate that equal validity instants do not make differently encoded TBS bytes, leaves, roots, or proofs interchangeable. Pre-1950 encodings document reference compatibility; they are not a new issuer-profile qualification.

Run `node --test reference/certificate-validity-vectors.test.mjs` from the repository root.
