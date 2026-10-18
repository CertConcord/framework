# S/MIME application

The selected application protects and processes complete RFC 5322 messages as byte buffers. It signs the complete MIME entity, including its content headers, multipart structure and attachments. Its encrypted mode signs first and then encrypts the signed MIME entity for explicitly admitted recipients. It uses the same certificate, full-CRL and authority engine as the document and timestamp applications.

## Selected format and algorithms

The format follows [RFC 8551](https://www.rfc-editor.org/rfc/rfc8551.html) and the certificate rules of [RFC 8550](https://www.rfc-editor.org/rfc/rfc8550.html), with narrower explicit local choices. It supports opaque `application/pkcs7-mime` SignedData and sign-then-AuthEnvelopedData. CMS content OIDs determine the operation; a MIME `smime-type` label alone never establishes protection.

Signatures select one ECDSA P-256/SHA-256 signer, issuer-and-serial identification, embedded content and SHA-256 SigningCertificateV2. The signature covers the exact finalized MIME bytes. Claimed CMS signingTime is informational and supplies neither actual observation time nor historical proof.

Outbound SignedData embeds the exact signer leaf certificate. Auxiliary path and status material comes from the core's explicit current context; the backend does not embed a supplied root chain or rewrite signed CMS to reorder certificates.

Encryption selects RSA 3072- or 4096-bit recipient keys with RSAES-OAEP using SHA-256, MGF1-SHA-256 and an empty label. AuthEnvelopedData uses AES-256-GCM with a 12-byte nonce and a 16-byte tag. The encrypted plaintext is the complete signed MIME entity. One to 32 unique, explicitly admitted recipient keys are supported. A sender copy requires explicit inclusion of a separately admitted encryption credential.

The selected certificate path is a direct P-256/SHA-256 issuer/root with authenticated full issuer CRLs. Mail certificates require explicit emailProtection and a critical KeyUsage permitting the particular signing or encryption operation without CA signing bits. Additional well-formed EKUs confer no additional application permission. The existing document signer and exclusive critical TSA EKU rules remain unchanged.

Other signature/key-management suites, intermediate paths, OCSP, indirect/delta CRLs, multipart/signed, compression and additional nested security layers are outside this selection. This is not a claim to implement every mandatory receiving capability of a full S/MIME 4.0 client.

## API and trusted configuration

`SmimeApplication` binds `readContext` and the selected MIME/CMS backend at construction. Its asynchronous methods are:

```js
import { SmimeApplication } from '../reference/smime.mjs';
import { createSmimeBackend } from '../reference/smime-backend.mjs';

const backend = createSmimeBackend({
  opensslPath,
  opensslConfig,
  keyMap: { sender: senderPrivateKey, recipient: recipientPrivateKey },
});
const application = new SmimeApplication({ readContext, backend });

await application.protectSmimeMessage({
  message,
  mode: 'SIGNED_AND_ENCRYPTED',
  senderMailbox,
  signer: { certificate, keyRef },
  recipients: [{ mailbox, certificate }],
});

await application.processSmimeMessage({
  message,
  requiredProtection: 'SIGNED_AND_ENCRYPTED',
  expectedSenderMailbox,
  recipient: { mailbox, certificate, keyRef },
});
```

Both methods also support `SIGNED`. `requiredProtection` selects the exact mode. Message inputs cannot override trust roots, policy or knowledge time. Private-key references are configured backend handles; message contents and attached certificates cannot install a key or choose a provider.

`createSmimeBackend` selects explicit absolute OpenSSL executable and configuration paths and an optional provider module path. The selected executable is OpenSSL 3.6.5. Its constructor copies the own string entries of `keyMap`, importing private Node `KeyObject` values or unencrypted PKCS8 PEM buffers. Each `keyRef` names one of those fixed entries. Signing and decryption bind the actual private-key snapshot to the admitted certificate's exact SPKI; an earlier key description cannot authorize a later replacement. The backend invokes the executable with argument arrays and no shell, uses private temporary files, and removes them after each operation. It supplies no system trust-root or network-discovery fallback.

The selected private-file backend requires POSIX directory/file permission semantics, with a private directory mode of 0700 and exclusive file mode of 0600. Native Windows signing and decryption return UNSUPPORTED until a dedicated ACL implementation is selected. MIME processing and public cryptographic inspection are separate capabilities. Linux/WSL validation does not establish native Windows private-operation support.

The synchronous trusted `readContext()` returns `{knowledgeTime, policy}`. Knowledge time is the actual integral observation time. The policy supplies explicit roots, scoped authority and mailbox resolvers, current material, and finite algorithm/hash/key deadlines. The scope contains a 32-byte `trustDomainID`, `issuerID`, `representation: 'X509'`, `profileID: 'certconcord-smime-application-v1'` and `purpose: 'SMIME_APPLICATION'`. The application derives `SMIME_SIGNING` or `SMIME_RECIPIENT_ENCRYPTION` for each decision.

Construction requires an available valid initial context and fixes its namespace, root bytes, and authority/mailbox resolver function identities. An unavailable initial context throws a typed INDETERMINATE error. Subsequent calls can observe updated decisions through those same resolver functions, along with updated material and deadlines. Replacing a resolver requires a new application instance. Temporary context unavailability after construction prevents acceptance without suppressing independently available cryptographic failures.

The mailbox resolver authenticates one exact mailbox/certificate/key/purpose association through trusted configuration. A successful binding repeats the canonical mailbox, SHA-256 certificate hash, framework key identifier, purpose and scope, together with finite `knownAt`, `validFrom` and `validUntil`. A bare boolean or a matching display name is insufficient. Multiple independently admitted keys can belong to one mailbox; a missing or contradictory decision does not grant access.

Addresses use one ASCII addr-spec. Comparison lowercases the domain and preserves the local part. The application does not infer aliases, remove plus suffixes or dots, or use a certificate CN. Typed SAN rfc822Name values constrain the expected mailbox when present. A certificate without an email name still requires the exact external association. Legacy DN-only email names, internationalized mailbox names and unimplemented critical name semantics are nonselected.

## Time, key use and acceptance

All material and authorization decisions use current actual knowledge time. Date and signingTime cannot recover a revoked credential or an expired protection interval. Incoming ordinary signer/root expiry without historical proof can be indeterminate; this limited result does not permit new signing, encryption or private decryption with an expired credential. Known revocation, bad cryptography, wrong purpose or mailbox, and crossed explicit protection cutoffs remain invalid.

The application copies operation inputs before asynchronous work. It checks the backend key's exact public-key representation against the selected certificate before private use. After MIME preparation it reads fresh context and admits the credentials needed by the next operation. After signing, encryption, decryption or final serialization it checks fresh context again before the next effect or successful release. A previous positive decision does not survive a new unavailable or withdrawn decision.

Receipt first admits the local recipient before private decryption. It authenticates GCM before releasing plaintext, verifies the exact inner SignedData bytes, and checks the sender's current certificate, status, authority and mailbox association. Decoded content and attachments are returned only when every selected requirement is VALID.

Results retain separate cryptographic, material, authority, mailbox and MIME checks. Known INVALID takes precedence over UNSUPPORTED, then INDETERMINATE. Safely available bad cryptography is not hidden by missing policy evidence. The application does not invoke an unauthorized private key merely to inspect otherwise unavailable inner content.

Public inspection also checks common nonselected RSA PKCS#1 signatures with SHA-256 or SHA-512 when OpenSSL can verify their exact bytes. Valid mathematics leaves those signature suites UNSUPPORTED; an established mathematical failure is INVALID. This does not authorize RSA signing or broaden the selected P-256 signature profile.

## MIME bytes and outer headers

The selected MIME subset includes UTF-8/US-ASCII text, multipart/mixed, multipart/alternative and declared-type binary attachments. The mature MIME tree writer finishes outbound text normalization and CRLF framing before signing. Binary attachment bytes remain unchanged after transfer decoding. `canonicalMimeHash` is SHA-256 of the exact SignedData eContent MIME entity, not of a display rendering or the SignedData wrapper. Receipt verifies those original bytes before parsing or decoding them.

Complete header occurrence lists are checked before convenience parser fields. Ambiguous From/Sender and duplicate security-sensitive content fields or parameters are rejected. Missing Content-Type uses the standard text/plain; charset=us-ascii default; a filename cannot silently change it to another media type. Attachment filenames are inert labels. HTML is returned as bytes without rendering, sanitization, script execution or resource fetching.

An incoming inner MIME entity may contain one `MIME-Version: 1.0` field as inert version metadata. It does not establish an author or become an outer header. Duplicate or unsupported versions and actual outer identity headers remain nonaccepting. The inner writer adds no MIME-Version, Date or Message-ID, and receipt never removes such bytes from signed content before verification.

From, Sender, Subject, To, Cc, Date, Message-ID and trace headers remain UNPROTECTED. Exactly one From mailbox must match the expected author and admitted signing credential; Sender is absent or names that same mailbox. This separate comparison does not sign the literal outer header bytes. A Subject edit can leave the protected body valid.

Explicit recipient arguments determine encryption targets. To/Cc remain informational routing claims, and nonempty Bcc input is rejected during outbound protection. No hidden-recipient or immutable signed-recipient-list claim is made. [RFC 9788](https://www.rfc-editor.org/rfc/rfc9788.html) protected-header semantics are recognized as nonselected; they are not silently interpreted as ordinary content parameters.

## Operation and assurance boundaries

This is a local byte transformation. Each explicit invocation performs each selected private cryptographic action at most once. It does not retry automatically, switch keys or algorithms after failure, drop an unavailable recipient, or send mail. A timeout can occur after key use; a non-VALID result then reports that an effect may have occurred and returns no protected message or authenticated plaintext. A second explicit invocation is a separate attempt. There is no durable exactly-once, cross-call deduplication, delivery receipt or Message-ID replay-prevention claim.

The trusted context provider owns authenticated state history and rollback protection across process restarts. The application rejects decreasing observation time within an instance and never substitutes cached GOOD decisions for unavailable current evidence.

Inputs are bounded to 32 MiB, with 16 MiB finalized MIME and aggregate decoded-content limits, 128 MIME parts, depth 16 with the root at depth one, and 128 headers/64 KiB of header bytes per entity. Each complete CMS DER object also has a 16 MiB limit. These are separate ceilings: MIME transfer encoding and CMS wrapper overhead can put a message over one limit even when its original content is below another. Certificate and CRL collections are bounded to 32 each. MIME parsing and CMS execution require the selected bounded backend. MIME metadata cannot cause file or network retrieval.

The MIME worker has a 10-second deadline, a 128 MiB old-generation heap limit and a 16 MiB young-generation heap limit. OpenSSL operations have a 10-second deadline, 64 KiB of captured diagnostic output and 32 MiB of output. MIME serialization consumes a bounded output stream. These engineering limits do not establish protection against every native or parser resource failure.

The selected MIME parser is `@zone-eu/mailsplit` 5.4.20 under its MIT license option; the address parser and MIME writer use Nodemailer 10.1.0 under MIT-0. Exact direct and transitive tarballs are identified in [source-lock.json](../reference/source-lock.json), and their installation graph is fixed by [package-lock.json](../package-lock.json). Their original license files remain authoritative. The application applies additional framing, parameter, transfer-encoding and semantic checks to the libraries' parsed data; permissive recovery does not create an accepted identity or authenticated message.

The software profile does not establish operational mailbox qualification, hardware key custody, qualified signature/seal status, historical S/MIME preservation or universal mail-client compatibility. Comparing an OpenSSL-backed adapter with the OpenSSL CLI establishes file/API interoperability, not a second independent cryptographic implementation. The [draft stability gates](../spec/conformance.md) remain applicable.
