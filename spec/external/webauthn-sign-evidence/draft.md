# WebAuthn sign extension evidence research — draft 01

Status: experimental application research. W3C WebAuthn PR #2078 is an open draft, and the later YubicoLabs text calls itself `previewSign5` version 6-SNAPSHOT. Neither source is represented here as an adopted standard or a demonstrated browser/authenticator implementation.

## 1. Source boundary

The W3C `sign-extension` branch proposes an authenticator-held asymmetric signing key associated with, but distinct from, a WebAuthn credential key. The proposed extension signs caller-supplied data unaltered. That signature is distinct from an ordinary WebAuthn assertion signature over authenticator data and hashed client data. The W3C branch describes key generation at registration and at most one signing key per credential. The later YubicoLabs draft uses `previewSign5`, permits key generation during registration or authentication, and describes zero or more signing keys per credential. An implementation must select one exact draft state rather than silently combine their identifiers and output structures.

The inspected sign-extension sections do not define an application evidence container, timestamp target or AdES document container. Any such object requires a separately specified application profile and is not a claimed output of the extension.

## 2. Evidence needed for one signing operation

An application must retain the exact bytes it chose as the algorithm-specific `to-be-signed` input (`tbs`) before invoking the extension. Its evidence also needs the selected signing public key, signing-algorithm identifier, key handle or equivalent reference, returned signature bytes, associated credential and WebAuthn result, and the key-generation attestation and presence/verification policy when those properties are claimed. The signing-algorithm identifier and the COSE public key's verification-algorithm identifier serve different roles and may differ. Attestation is returned at key generation, is not cryptographically tied to the parent credential, and does not reappear as a new attestation for every signature. The signed `tbs` bytes and their algorithm convention must be checked independently of client-supplied labels. A valid signature alone does not prove attestation, user presence, user verification, transaction display or identity. `vectors/operation-evidence.json` records these fields in an explicitly synthetic instance, with absence marked rather than invented WebAuthn output. `reference/evidence.mjs` checks signature mathematics and externally supplied verifier findings separately; it does not authenticate those findings itself.

The proposed extension adds no domain separation to arbitrary payloads. The selected COSE signing algorithm may define some separation; an application profile must specify any remaining purpose and context framing of `tbs` before asking for a signature. It cannot assume the WebAuthn origin binding of the distinct credential key automatically constrains signatures made by this signing key.

For document-signature interoperability, a later profile must identify the exact signing input, algorithm and signature encoding expected by one chosen container. A direct signature over arbitrary bytes does not by itself establish PAdES, CAdES or JAdES validity. The YubicoLabs explainer illustrates that a split signing algorithm may pass a digest as `tbs`, whereas another algorithm may take the original bytes; the chosen algorithm's convention must be explicit. Container construction and validation remain open work, not a result of these synthetic vectors.

## 3. Synthetic byte vectors and limits

`vectors/direct-input.json` contains an original synthetic binary `tbs` with a non-UTF-8 octet, one Ed25519 signature and public key, and three adverse inputs. The positive vector verifies over the exact original bytes. Changing one byte, using a different key or passing SHA-256(`tbs`) in place of `tbs` must fail against that signature. A UTF-8 decode/re-encode is also not byte preserving. `vectors/assertion-shape.json` uses a separate synthetic credential key and signs assertion-shaped bytes; its valid signature cannot substitute for the direct signing-key signature, and its challenge bytes are not the extension's `tbs`. A mathematically valid direct signature also cannot satisfy a policy that requires absent attestation or user-verification evidence. Ed25519 is used only for deterministic direct-input and assertion-shaped examples; these vectors do not establish a WebAuthn extension algorithm profile, authenticator behavior or attestation.

The extension does not choose a timestamp target. Before a timestamp profile is proposed, the application must select the final signed artifact and specify exactly which retained bytes are covered, the order of container construction and time evidence, and the verification of the time authority and later augmentation. No timestamp coverage rule is selected by this draft.

## 4. Open review questions

1. Which exact W3C or Yubico draft state and extension identifier should a first implementation target?
2. Which signing algorithm and document container should be the first bounded interoperability profile, and what are its exact `tbs` and signature encoding rules?
3. What attestation and presence/verification evidence is available from a real supported browser and authenticator, and which claims can a verifier check offline?
4. What final artifact should an optional RFC 3161 timestamp cover after the selected container is complete?

Until those questions have source-backed answers and real implementation evidence, the repository remains an experimental evidence research package.
