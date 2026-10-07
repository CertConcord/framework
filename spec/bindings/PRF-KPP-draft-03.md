# CertConcord WebAuthn PRF Key Protection Profile — draft 03

> Candidate binding for CertConcord draft 03. This is a working draft, not a final standard. Its requirements apply only when this binding is selected. The [draft architecture](../architecture.md) defines framework scope; the [profile catalog](../profiles.md) records applicability. The draft 03 namespace and wire domain identify experimental formats. Object schema numbers describe field layouts and do not indicate a stable edition.

Status: draft 03. Normative language: English. COMMON-draft-03 is an integral normative part of this specification.

## 1. Scope

This profile protects local account roots, software signing/encryption vaults, private evidence, receipts and purpose-separated capability keys with the WebAuthn PRF extension. It applies to the DTI infrastructure independently of the selected MTC or mdoc credential representation. PRF output is a local secret, not a signature, a proof of user intent, an authentication assertion or evidence of hardware custody. DSCP governs signing authority; DCP governs native mdoc holders. Those controls remain necessary when PRF protection is present.

In the DTI native-holder flow, PRF protection MAY cover wallet metadata, a credential cache, retained presentation evidence and separately enrolled activation capabilities. The native non-exportable mdoc key stays in its platform keystore. A PRF vault unlock is neither OpenID4VCI holder proof nor OpenID4VP device authentication. Recovering vault data does not reactivate a revoked DeviceBinding or transfer a document key to a replacement device. Those operations require the RA authorization and fresh possession checks in DTI section 4 and DCP section 3.

## 2. Security boundary

The authenticator evaluates PRF under its credential boundary. The browser application handles the returned secret and decrypted data. A compromised authorized origin can therefore use an unlocked secret. User verification, content security controls and short secret lifetime reduce exposure but do not create a trusted display. A non-extractable WebCrypto key does not prove hardware isolation.

## 3. PRF capability

Enrollment MUST verify actual PRF support and successful evaluation for the selected credential. Extension presence or an advertised capability alone is insufficient. Unsupported credentials remain usable for independently authorized WebAuthn authentication but MUST NOT be registered as PRF protectors. A remote-signing PRF capability is a separate randomly generated signing key encrypted in the local vault; its public key is enrolled with fresh authorization and an explicit credential/key/purpose binding.

## 4. Credential record

The server record contains credential ID, public key, RP ID, allowed origins, SubjectID, sign counter policy, backup eligibility/state, attestation assessment, registration evidence commitment, status and permitted purposes. PRF support and wrapper references are explicit. A record does not contain PRF outputs, derived wrapping keys, plaintext roots or capability private keys. Revocation disables new authorization before deleting optional ciphertext.

## 5. PRF input namespace

The input to WebAuthn `prf.eval.first` or the selected `evalByCredential` entry is exactly:

```
D("PRFInput", {
  schemaVersion, trustDomainID, subjectID, credentialIDHash,
  rpID, purpose, epoch, contextID, prfSalt
})
```

These are RRA input bytes to the WebAuthn API. The browser/authenticator's WebAuthn domain separation MUST NOT be duplicated or bypassed by pre-applying its internal hash. CredentialIDHash is SHA-256 of the credential ID. Domain, subject, context and salt are independent 32-byte values. PRF salt is public, random and unique for a new wrapper epoch.

## 6. Purpose identifiers

The registered purposes are ACCOUNT_WRAP, SIGNING_VAULT_WRAP, ENCRYPTION_VAULT_WRAP, RECEIPT_WRAP, TRANSACTION_SECRET, LOCAL_VAULT, RECOVERY_STATE, KEY_TRANSITION and PRIVATE_EVIDENCE. Their byte strings are case-sensitive. An encryption recovery path cannot unwrap a signing root. Application-specific data belongs inside its purpose-separated vault and does not redefine this registry.

## 7. WebAuthn domain separation

The RP ID, approved origin and exact credential are validated for every assertion. The challenge is fresh and single-use. `crossOrigin=true` requires a separately declared and verified embedding policy; it is rejected by the reference profile. A different site, RP or credential cannot be accepted because its displayed account name matches.

## 8. PRF output

The selected output MUST be exactly 32 bytes. `first` and `second` are independent named outputs corresponding to their respective inputs. Missing, malformed or unexpected output fails the operation. An application MUST NOT substitute a password hash, credential ID, assertion signature, server nonce or random bytes when PRF is unavailable.

## 9. Server boundary

Only whitelisted public WebAuthn assertion fields are serialized to the server. PRF extension results are removed from that representation. A server receives authenticated ciphertext wrappers and public metadata, never an evaluation result. Server-side evaluation of a software fixture is limited to isolated conformance tests and cannot be advertised as authenticator PRF.

## 10. Key derivation

The full WrapperHeader contains schemaVersion, trustDomainID, subjectID, credentialIDHash, rpID, purpose, epoch, contextID, prfSalt, wrapperID, kdfSalt, kdf, aead and amkVersion. All identifiers and salts listed in COMMON or section 5 are 32 bytes; wrapperID and kdfSalt are also 32 bytes. Epoch starts at zero; amkVersion starts at one. `kdf="HKDF-SHA-256"`.

```
KEK = HKDF-SHA-256(PRF, kdfSalt, D("WrapperKDF", WrapperHeader), 32)
```

Derivation includes the complete authenticated header. Public metadata is not secret, but changing it MUST prevent successful unwrapping. Integer overflow, unknown fields and unsupported algorithm names are rejected.

## 11. Account Master Key

An AMK is an independent 32-byte random root. It is not used directly as a document signing key or reused as a KEM secret. Different purposes use separate roots or explicit domain-separated subkeys. A server account recovery procedure cannot recreate an AMK unless a declared recovery graph explicitly permits that result.

## 12. Credential wrapper

For AES-256-GCM, a fresh 12-byte nonce encrypts the 32-byte root under KEK with `AAD=D("WrapperAAD", WrapperHeader)` and a 16-byte tag. Plaintext is not released before authentication completes. The nonce MUST NOT repeat under a KEK. Fresh wrapperID and kdfSalt produce a new derived key for every rewrap.

## 13. Wrapper object

The GCM envelope is `{schemaVersion:1, header, nonce, ciphertext, tag}`. The KW/KWP envelope is `{schemaVersion:1, header, ciphertext, tag}` and MUST NOT contain a nonce. RFC 3394 AES-256-KW and RFC 5649 AES-256-KWP are retained adapters with a required independent metadata MAC:

```
MK = HKDF-SHA-256(PRF, kdfSalt, D("WrapperMACKey", header), 32)
tag = HMAC-SHA-256(MK, D("WrapperMAC", {header, ciphertext}))
```

The MAC is verified before unwrap. Bare KW integrity is not sufficient to authenticate the RRA header. Algorithms cannot be changed in place without a new wrapper and verified transition.

## 14. Multiple credentials

Each credential has a separate wrapper for the same authorized root, its own PRF namespace and its own lifecycle. Multiple wrappers constitute an OR recovery path. Policy and RCG evaluation MUST account for every wrapper, including old devices, synced copies and recovery credentials. Removing a wrapper from a database does not erase a previously copied ciphertext or compromised root.

## 15. evalByCredential

The application supplies the PRF input under the base64url credential ID it intends to use. It verifies that the returned credential matches that entry. A returned credential without a matching input is rejected. The API's actual output is used; iteration over candidate credentials does not authorize transmitting those outputs or decrypted roots.

## 16. Dual inputs

Dual inputs permit old and new epoch evaluation in one authorized ceremony. `first` always corresponds to the explicitly supplied old input and `second` to the new input for that transaction. Either may be evaluated separately when the authenticator requires it. No transition can be committed merely because two byte arrays were returned.

## 17. Rotation transaction

The durable states are PREPARED, COMMITTED and OLD_RETIRED. The new epoch is exactly old+1, with fresh PRF and KDF salts; trust domain, subject, context, purpose, RP and AMK version remain equal for a rewrap. Verification unwraps both envelopes, compares the actual root bytes in constant time and commits the verified pair in one transaction. There is no externally consumed intermediate verification state. Compare-and-swap protects each transition. A failure before commit leaves PREPARED and retains the working old wrapper; a restart after commit reads COMMITTED and may retire using its stored revision. Retirement records policy state and does not erase previously copied ciphertext.

The reference API is `EpochTransition.commit(id, newPRF, oldPRF)` followed by `retire(id, committedRevision)`. A stored legacy NEW_WRAPPER_VERIFIED record is not accepted as a completed verification: it requires an explicit state migration to PREPARED and fresh evaluation of both original wrappers. Wire encodings and root derivation are unchanged.

## 18. Local vault

Each object uses a random 32-byte DEK wrapped under a root-derived key. The authenticated header binds objectID/version, rootID/version, purpose, media type, exact length, chunk size, chunk count and random salt. The reference chunk size is 1 MiB. Each chunk's AAD binds the header hash, zero-based index and total count. Reordering, omission, duplication and truncation fail. Decryption releases the object only after every chunk and final length validate. A streaming consumer MUST quarantine unverified plaintext and commit atomically after final verification.

## 19. Signer receipts

Receipt encryption protects confidentiality and cannot create or replace an ExecutionReceipt signature. The receipt's original signed bytes and evidence links are preserved. Losing a private receipt wrapper may reduce available evidence; it cannot retroactively change a provider's execution history.

## 20. Transaction-specific secrets

Transaction secrets use TRANSACTION_SECRET and an independently random ContextID. Their derivation commits to the exact activation or protocol transaction. A secret from one transaction cannot authorize another. Expiry, subject and one-use state are checked by the consuming protocol, even if the secret can still be recomputed locally.

## 21. Remote signing enhancement

A PRF-unlocked capability key signs the exact DSCP ActivationContext binding under its registered domain separator. A fresh verified WebAuthn assertion remains required when the policy declares HUMAN_WEBAUTHN. The capability record binds trust domain, subject, credential, document KeyID, purpose, public key, epoch and expiry. Enrollment requires existing authorized control of that binding; revocation and epoch changes invalidate outstanding capabilities. Possession of PRF ciphertext alone grants no signing authority.

The reference capability registry is local to the authorization service. Enrollment returns unsigned public metadata; authorization reads the current authenticated journal record. No independent relying party consumes a signed CapabilityRegistration object. A returned record cannot replace that lookup or convey portable signing authority. Remote capability delegation is outside this local interface.

## 22. Local signing

An exportable local signing key may be encrypted in a dedicated SIGNING_VAULT_WRAP vault with KAL1 unless stronger evidence is established. A native Secure Enclave/Keystore/TPM key stays in its native provider and is referenced by immutable public-key binding. PRF does not convert an exportable key into a non-exportable key. The experimental WebAuthn raw-sign adapter uses its locked proposal encoding and rejects absent algorithm support.

## 23. Encryption keys

Encryption keys and recovery roots remain separate from signature keys. ML-KEM keys may use a purpose-bound encrypted PKCS#8 vault when export is policy-authorized, or an opaque provider handle when supported. Decryption policy identifies allowed recipients and purposes, and authenticated decryption quarantines plaintext. A restored encryption root does not recover a signing key.

## 24. Rebinding

Rebinding adds a new wrapper or device mapping through an authenticated, auditable ceremony. It records old/new credential and wrapper commitments, authority, subject, purpose and epoch. It does not silently copy a deleted passkey's signing authority to a newly registered passkey. Existing document keys retain their prior custody history.

## 25. Strong rebinding

Rebinding that affects signing authority requires fresh qualifying activation, explicit user confirmation of the new device/key, RA policy where required, and a signed transition record. A session cookie, emailed link or support agent account alone is insufficient. If the original key is lost, replacement issuance uses a new key and preserves the old key's status and evidence.

## 26. Synced passkeys

Backup eligibility/state and authenticator/provider evidence are recorded without inferring synchronization behavior not established by that evidence. A synced credential may make additional copies of an effective recovery path. Assurance policy evaluates that custody model explicitly. A zero sign counter can be legitimate for a declared counterless credential; a decreasing positive counter requires investigation and the configured rejection policy.

## 27. Portability

Exportable encrypted vault objects are portable when the destination implements the exact schema and purpose policy. Authenticator PRF portability is not assumed across providers or RP IDs. Native non-exportable keys cannot be migrated by exporting a wrapper. A platform transition uses a new DeviceBinding and, where needed, replacement document keys.

## 28. Credential loss

Loss disables the affected credential for future use and invokes the declared recovery graph. A surviving authorized wrapper may recover only the root it protects. No recovery path means the protected data or non-exportable key may be unrecoverable; the system MUST report that state rather than invent a successful reset. Historical signed documents remain independently verifiable when their public evidence is available.

## 29. Credential compromise

Compromise assessment considers copied wrapper ciphertext, PRF output, AMK, DEKs, plaintext and capability keys separately. Rewrapping the same AMK does not evict an adversary who knows that AMK. The response may require new roots, new DEKs and re-encryption, capability revocation, credential revocation and document-key replacement. The compromise start interval is retained for historical validation.

## 30. AMK rotation

AMK rotation increments amkVersion and generates a new independent root. It is a distinct operation from section 17 rewrap. Every retained DEK/root dependency is inventoried, reprotected and verified before the old root is retired. An interrupted migration retains a durable per-object version map. Mixed-version reads use explicit versions; they do not try arbitrary keys until one decrypts.

## 31. Server storage

Stored wrappers, credential records, transitions and public capability records use authorized subject-scoped access, version checks and rollback detection. The server may deny or withhold data and cannot be assumed honest merely because it cannot decrypt it. Trusted State Continuity protects policy/wrapper epoch watermarks; a restored database cannot silently re-enable revoked credentials.

## 32. Client memory

Derived keys and plaintext buffers are short-lived and overwritten where the runtime permits. JavaScript garbage collection, string copies and platform key APIs limit guaranteed erasure; software MUST NOT claim complete memory erasure from a best-effort buffer overwrite. Persistent plaintext caches, debug logs and extension-result dumps are prohibited.

## 33. Error privacy

Public errors do not reveal whether an unknown subject, credential or wrapper exists. Authenticated diagnostics may distinguish corruption, unsupported capability, stale epoch and revoked authority without including secrets. Failed unwrap attempts do not trigger automatic fallback to a weaker custody path.

## 34. Origin policy

Production origins are explicit HTTPS origins with exact RP policy. RP migration is a new enrollment/rebinding ceremony. Loopback HTTP is confined to local development and testing and is never included in production trust policy. Untrusted cross-origin frames cannot request decryption or activate document signing without an explicitly implemented origin delegation profile.

## 35. Logging

Audit records contain public object hashes, version/state transitions and authorized result codes. They exclude PRF results, KEKs, AMKs, DEKs, capability private keys, biometric data and decrypted document contents. Public evidence commitments do not automatically authorize public distribution of their private source objects.

This confidentiality boundary includes authenticator extension outputs inside signed `authenticatorData`, not only `getClientExtensionResults()`. A selected client/authenticator MUST keep PRF results confidential in accordance with the pinned WebAuthn Level 4 section 10.1.4 requirement. Before public serialization, the browser driver rejects a returned PRF result appearing as cleartext bytes inside authenticator data or an attestation object. This check is defense in depth for the actual returned values; it does not prove that an untrusted client has no other disclosure channel. Signed data MUST be preserved exactly or rejected, never edited and forwarded. Encrypted CTAP `hmac-secret` output is distinct from the local decrypted PRF result.

## 36. Assurance

Identity, key isolation, activation, recovery and custody are assessed independently under COMMON. PRF availability can be reported as a capability but cannot raise IAL, KAL or SAL by itself. Hardware claims require validated device evidence and a declared trust policy. Evidence provenance and assessment expiry accompany every elevated claim.

## 37. MTC relationship

PRF protects local secrets; MTC proves certificate inclusion and required cosigning. A successful unwrap cannot override a revoked certificate, log interval or trust manifest. Conversely, valid MTC inclusion does not prove the key remained secret or that the signer authorized a particular document.

## 38. Long-term verification

Verification preserves certificate, container, activation, status, log and archival evidence independently of local PRF state. Expired or lost credentials do not require rewriting historical signed bytes. Private evidence may need separate authorized recovery; absent evidence is reported as unavailable, not silently reconstructed.

## 39. Mandatory 1.1 profile

An implementation claiming PRF-KPP draft 03 implements real PRF capability detection, credential-specific input routing, AES-256-GCM wrappers, complete metadata binding, purpose separation, verified epoch transitions, vault authentication, private assertion serialization, rollback-aware state and explicit loss/compromise handling. KW, KWP, local exportable signing, capability keys and raw signing are selectable adapters; each enabled adapter implements all of its declared requirements.

## 40. Security invariants

Tests reject wrong PRF, credential, RP, subject, purpose, epoch, root version, header, nonce/tag, chunk order and final length. Rotation tests prove root continuity and crash-safe state ordering. Recovery tests prove that no declared encryption or account path reaches a signing target. Server records and network messages are checked for prohibited secret fields.

## 41. Reference architecture

Browser and native adapters obtain real platform capabilities. The local protection layer manages purpose-separated roots and ciphertext. The registration/activation service manages public bindings and durable one-use state. The signer enforces DSCP permits. The evidence verifier independently evaluates the resulting ECP. DCP's native mdoc holder key remains in its platform provider; it is linked to, and never confused with, the document signing key.

## Native-key profile binding

DCP key admission and document_key_mode apply before a native holder key is associated with a protected vault. PRF wrapping MUST NOT convert an unattested key into a hardware-attested key. For DEVICE_KEY, recovery or replacement affects both holder and document-key roles and requires new issuance. For INDEPENDENT_PQ, hardware attestation of the holder does not attest the ML-DSA secret protected by this profile. Each key retains its own custody and recovery assessment.

## Passkey-associated signing credentials

[PSCP-draft-03](PSCP-draft-03.md) defines PASSKEY_KEY and the certificate/credential binding for an independently attested signing key. Its parent authentication key and child signing key are not PRF output or vault roots. PRF-KPP MAY protect private evidence, handles and local metadata, while the signer retains its hardware key and fixed UV policy. A raw-key handle, ARKG ticket or nonextractable browser handle MUST NOT be used as a wrapping key.

PRF synchronization or account recovery does not establish child-key recovery. Loss of a parent or its authenticator follows PSCP revocation and RA re-enrollment; restoring encrypted metadata cannot restore signing authority. The existing independent ML-DSA activation/vault path remains available under its original custody and recovery claims. The algorithms, key identities and assurances of those paths MUST NOT be merged.
