# Standalone timestamp application

The selected application issues, requests and verifies standard RFC 3161 timestamp responses through `TimestampService`, `TimestampClient` and `TimestampResponseVerifier`. It shares certificate, CRL, authority and durable-operation validation with the document applications. Its wire objects are DER `TimeStampReq`, `TimeStampResp` and CMS timestamp tokens; operation identifiers and storage records remain local application data.

## Selected profile

The format follows [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html) with the [RFC 5816](https://www.rfc-editor.org/rfc/rfc5816.html) certificate-identifier update. The selected signature is ECDSA P-256/SHA-256 with one issuer-and-serial SignerInfo and SHA-256 SigningCertificateV2. Requests select SHA-256 or SHA-512 imprints. Tokens have integral UTC seconds, a positive serial of at most 160 value bits, explicit microsecond accuracy and an optional nonce of at most 256 value bits.

The TSU certificate has a critical, exclusive timeStamping EKU and a direct P-256/SHA-256 root. Validation uses full direct issuer CRLs, externally admitted roots, scoped authority decisions and finite algorithm/key protection deadlines. Intermediate paths, OCSP, indirect or delta CRLs, other signature suites, fractional generation times, ordering claims and additional timestamp extensions are outside this profile. Missing accuracy is indeterminate, not zero uncertainty.

`certReq=true` requires the actual token to contain its ESS-bound signer certificate. With `certReq=false`, the certificates field is absent and the verifier uses externally configured candidates. External candidates never become embedded certificates. The issuer rejects all unselected request extensions, including noncritical extensions.

Reception also accepts the optional signed CMS signingTime attribute under the existing [RFC 5652 validation rules](https://www.rfc-editor.org/rfc/rfc5652.html#section-11.3). Its claimed value never determines the timestamp interval, authority state, actual knowledge time or proof of existence. The service emits only content-type, message-digest and SigningCertificateV2 attributes.

## Public interfaces

The codec lives in [timestamp-protocol.mjs](../reference/timestamp-protocol.mjs). It copies byte inputs and returns DER buffers or parsed records. Parsing alone grants no trust.

| Export                    | Input and result                                                                |
| ------------------------- | ------------------------------------------------------------------------------- |
| `encodeTimestampRequest`  | `{imprint, hashAlgorithm='sha256', policyOID?, nonce?, certReq=true}` to DER    |
| `parseTimestampRequest`   | DER to `{raw, hashOID, imprint, policyOID?, nonce?, certReq, extensions}`       |
| `encodeTimestampResponse` | `{status, tokenDER?, statusStrings=[], failureBits=[]}` to DER                  |
| `parseTimestampResponse`  | DER to `{raw, status, statusStrings, failureBits, tokenDER?, diagnostics}`      |
| `encodeTSTInfo`           | `{policyOID, hashOID, imprint, serial, genTime, accuracyMicros, nonce?}` to DER |

An omitted request-builder nonce generates a fresh positive 128-bit value; `nonce:null` deliberately omits it. Failure values are numeric bit positions: 0, 2, 5, 14, 15, 16, 17 and 25. Limits are 64 KiB per request, 1 MiB per response and eight status strings of at most 1,024 UTF-8 bytes each. Failure-bit decoding has a fixed capacity; a large field cannot allocate an array proportional to every encoded bit. Typed codec errors provide `overall`, `code`, `failureInfo` and `failureBit`. A safely extracted bounded token can accompany a response error in `partial` so that the verifier can still establish a signature failure.

The application classes live in [timestamp-service.mjs](../reference/timestamp-service.mjs):

| Class                       | Constructor dependencies                                                                    | Methods                                                                                              |
| --------------------------- | ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `TimestampResponseVerifier` | `{readContext}`                                                                             | `verify({requestDER, responseDER})`                                                                  |
| `TimestampService`          | `{journal, serviceID, certificate, certificates=[], signer, policyOID, clock, readContext}` | `issue({operationID, requestDER})`, `reconcile({operationID, signature?})`, `result(operationID)`    |
| `TimestampClient`           | `{journal, clientID, send, readContext, maxResponseDelaySeconds=15}`                        | `request({operationID, requestDER})`, `reconcile({operationID, responseDER})`, `result(operationID)` |

`operationID` is a 32-byte Buffer. Reusing an identifier with different request bytes is an idempotency conflict. `signer` supplies `{publicKeyDER, sign}`; its public key must match the configured TSU certificate. The signing callback receives a copy of the exact CMS signed-attribute bytes and operation metadata. `send` receives a copy of the exact request and its local operation identifier. The transport adapter is responsible for endpoint configuration, authentication and bounded network I/O; no HTTP server or automatic polling is included.

## External trust and time

`readContext` is fixed at construction and returns `{knowledgeTime, policy, clockAdmission?}`. `knowledgeTime` is the actual trusted observation time, in integral Unix seconds. There is no per-message override. A context retains the same roots and scope throughout an instance, and the journal retains that binding and its observation-time floor across service/client restarts.

The policy supplies these values:

| Field                                                 | Meaning                                                                                                                                |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `trustedRoots`                                        | Exact externally admitted DER roots                                                                                                    |
| `scope`                                               | `{trustDomainID, issuerID, representation:'X509', purpose:'TIMESTAMP_APPLICATION'}`; the domain identifier is 32 bytes                 |
| `authorityResolver`                                   | Synchronous shared authority resolver for the exact certificate, role, scope, state time and actual knowledge time                     |
| `timestampPolicies`                                   | Accepted timestamp policy OIDs                                                                                                         |
| `maxAccuracyMicros`                                   | Maximum accepted uncertainty, an integer from 0 through 60,000,000                                                                     |
| `currentMaterial`                                     | Explicit certificate and full-CRL candidates; no automatic network discovery                                                           |
| `algorithmDeadlines`, `hashDeadlines`, `keyDeadlines` | Finite exclusive cryptographic protection cutoffs, using the [shared material policy](cades-preservation.md#authority-status-and-time) |

The certificate path and authenticated CRLs must establish the selected TSU and issuer at the timestamp interval. The TSU requires TIMESTAMP_AUTHORITY, its root requires ISSUER, and the CRL signer requires STATUS_AUTHORITY at CRL publication. A certificate pin does not confer these roles. All decisions use the same actual knowledge time, including later-known revocation and compromise information.

Accuracy is represented using integer microseconds. Certificate and protection bounds must contain the complete interval. Shared authority event times are integral seconds; verification checks every intersected second, at most 121, so a gap between two valid appointments cannot be hidden by valid endpoints. Only times already observable at the actual knowledge time are queried. A token whose upper bound is still in the future remains indeterminate until actual time advances.

The service independently calls `clock.read()` for `{sourceID, genTime, accuracyMicros, synchronized:true}`. Its external clock admission contains `{sourceID, validFrom, validUntil, knownAt, maxAccuracyMicros, policyOID, status:'ADMITTED'}`. The generation interval must fit this admission and its accuracy limits. Unsynchronized, withdrawn or mismatched sources prevent issuance. Knowledge and source-clock rollback are rejected; values are never clamped or replaced with an invented future observation.

After the asynchronous clock read, the service obtains fresh context before signing. It checks authority again at actual time after the signing callback returns, before releasing a new response. A historical token interval cannot authorize a service whose current issuing rights have ended.

The public verifier accepts a standard nonce-free proof and reports `nonceBound:false`; it supplies no request-freshness claim. The client requires a nonce, checks the exact response binding and enforces its persisted response-delay limit. It preserves the first trustworthy receipt time for the exact response across completion recovery. Later verification still uses fresh authority and status context.

Standalone verification does not invent proof that a token existed at its claimed generation time. The [shared TSU revocation rules](cades-preservation.md) distinguish absent reasonCode from explicit reason zero and require independent prior token proof for applicable key-risk revocation recovery. This application supplies no such historical proof. CAdES/PAdES preservation has separate evidence composition.

## Durable operations and results

The selected Journal reserves exact request bytes before external work. The issuer commits a serial, clock reading, TSTInfo and CMS signing input before calling the signer. It retains returned signatures, candidate tokens and final response bytes. The client commits the dispatch record before sending and retains a received response before invoking post-receive validation callbacks. No external callback runs inside a database transaction.

| Operation state     | Caller behavior                                                                                                                               |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `PENDING`           | Retain the operation; later explicit reconciliation can use newly available context or the terminal response to an earlier waiting status     |
| `UNKNOWN_EXECUTION` | The signing, transport or persistence outcome is uncertain; reconcile the original result without automatically repeating the external action |
| `COMPLETED`         | Exact final bytes and a stored verification result are available; inspect that result before acceptance                                       |

Completion is a storage state. It can contain a rejection or a non-VALID verification. `result()` and repeated completed requests return retained results, including their original observation time. Use `TimestampResponseVerifier.verify()` for a fresh trust decision.

A completion-write failure can report completion only after an exact durable readback. Otherwise the operation stays uncertain. Reconciliation checks the reserved signing input or response bytes; it cannot substitute another request, signature or completed response. Concurrent duplicate calls do not allocate another serial or repeat signing/sending. Serial state is checked against retained reservations before allocation. These consistency checks assume a trustworthy journal; restoring an entire database and all its counters to an older mutually consistent snapshot requires an external rollback anchor or operator recovery procedure.

Storage unavailability before external dispatch raises `INDETERMINATE/TSP_PERSISTENCE_UNAVAILABLE` with the operation identifier. Retain that identifier for result lookup and recovery. Failures after an external action produce an uncertain outcome unless exact durable completion can be established.

Verification returns `overall`, `reason`, individual `checks`, protocol status, actual observation time, timestamp interval and the material used. Known invalid signatures, bindings or authenticated applicable revocations are INVALID. Unselected capabilities are UNSUPPORTED; missing evidence or unavailable decisions are INDETERMINATE. INVALID takes precedence over UNSUPPORTED, then INDETERMINATE. Every non-VALID result prevents acceptance.

Unsigned response status text is informational. A waiting or rejection response supplies no timestamp proof, and revocationWarning/revocationNotification do not establish a certificate revocation fact. Such facts require separately authenticated status evidence.

## Validation and assurance

The protocol, verifier, service and client tests cover exact request bindings, certificate presence, current authority decisions, uncertainty intervals, missing evidence, storage failures, restarts and reconciliation. Tests use generated software credentials and controlled time/authority dependencies. Run the selected suite from `reference` with Node.js 24.15 or later and the selected OpenSSL fixture environment:

```sh
node --test --test-concurrency=1 timestamp-application-api.test.mjs timestamp-protocol.test.mjs timestamp-verifier.test.mjs timestamp-service.test.mjs timestamp-client.test.mjs timestamp-durability.test.mjs
```

Normal service/client exchanges with SHA-256 and SHA-512 imprints and both `certReq` values were independently checked with OpenSSL 3.6.5, including the original request, original data, explicit root and full CRL. Unmodified OpenSSL `ts -reply` output was also accepted with an external TSU certificate and with only the TSU certificate embedded. Its optional CMS signingTime remains informational. These checks establish selected wire and cryptographic interoperability; the externally configured framework authority policy remains a separate decision.

An OpenSSL response containing an additional root certificate passed OpenSSL verification but failed this application's strict DER set-order check. The original response was retained unchanged. This profile does not accept every encoding produced by OpenSSL or implement general BER reception.

This is a bounded software application profile. The external clock admission is an operational assumption, not proof of UTC accuracy. Qualified TSA operation, assessed key custody, distributed storage, production parser assurance, archival status service and a second complete independent implementation remain outside this evidence. SHA-512 imprints do not make P-256 timestamp signatures post-quantum secure. The [draft stability gates](../spec/conformance.md) remain applicable.
