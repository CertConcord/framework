# Passkey credentials and operations — draft 03

Expanding Passkey use beyond account login is a core research direction. The framework separates actual deployed authentication capabilities from proposed signing interfaces so that an implementation can state exactly what it supports.

| Path                                     | Meaning                                                                                                                                                                                     | Candidate                               |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| Existing WebAuthn activation             | A verified assertion authorizes a bound request to a separately selected document key/provider. The assertion is authorization evidence, not the document signature.                        | DSCP and COMMON                         |
| Certified Passkey-associated signing key | A selected authenticator signing extension generates or exposes a precisely admitted document key, certifies its relation to the subject/authenticator and produces the required signature. | PSCP and versioned raw-signing adapters |
| Execution binding                        | An admitted execution component binds authorization, provider/key admission, dispatch and result evidence, with durable replay/uncertainty behavior.                                        | EBP experimental proposal               |

The document baseline MUST support the existing WebAuthn activation path without a raw-signing extension, ARKG, WebKit Remote CryptoKeys or EBP. This path authorizes a separately admitted document key through ordinary WebAuthn; it does not ask the Passkey authentication key to sign arbitrary document bytes. Proposed interfaces and their device support MUST NOT be hard dependencies of a stable document baseline. They remain optional, explicitly selected experimental capabilities with their own conformance evidence.

CC-PASSKEY-01: A path MUST declare the selected API/proposal revision, algorithms, key arrangement, platform support, exact operation input and proof semantics. It MUST NOT imply that an unmodified ordinary Passkey supports raw document signing.

CC-PASSKEY-02: Key admission and certification MUST bind the exact key and its permitted operation. Origin/RP, session, user authorization, key custody, recovery and device changes MUST be evaluated under explicit rules. Certificate issuance must not turn an unrelated login key into a document key by association alone.

CC-PASSKEY-03: Missing capabilities MUST fail explicitly. A path MUST NOT silently switch algorithms, keys, extensions or evidence plans to retain a stronger assurance claim. A broker receipt is not proof of hardware enforcement unless independently supported by the declared evidence and assumptions.

The [PSCP candidate](bindings/PSCP-draft-03.md), [EBP proposal](bindings/EBP-draft-03.md), [implementation guide](../docs/passkey-signing.md) and [WebAuthn edition comparison](../docs/webauthn-evolution.md) contain published technical work. New interfaces and original mechanisms remain open research; accepting an existing standard does not forbid proposing a better contract for the application.
