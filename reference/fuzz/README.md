# Fuzzing and differential verification

`npm run fuzz:seed` materializes synthetic seed bytes in the ignored runtime directory. `npm run fuzz:replay` replays the parser corpus. `npm run fuzz -- parsers 60` and `npm run fuzz -- containers 60` run Jazzer.js/libFuzzer coverage-guided campaigns. All process arguments are passed without a shell; corpus and artifact directories are explicit. CI runs a bounded campaign per change and a longer scheduled campaign.

The parser target covers deterministic RRA CBOR, DER framing, ISO CBOR, MTC proof framing, WebAuthn client data, C2SP checkpoints and duplicate-rejecting JSON. Accepted RRA CBOR values are compared with `cbor-x`; valid differences in JavaScript representation of exact safe integers are normalized. Resource budget failures and documented protocol/syntax rejections are expected. Unexpected exceptions, timeout, excessive memory, assertion failures and independent-decoder disagreements fail the target.

The container target changes authenticated inputs in CMS, COSE, JOSE, KEM/CMS and ECDSA. Any acceptance of the altered authenticated value fails. JOSE acceptance is compared with the independent `jose` package. These structured mutations exercise authentication properties; they are separate from arbitrary-byte parser coverage.

`node fuzz/differential.mjs` requires independent OpenSSL and checks a valid ML-DSA CMS baseline plus 160 reproducible byte mutations. Every CERTCONCORD-accepted mutation must pass independent CMS verification; RRA may reject inputs outside its stricter subset. The tool records per-case digests and both outcomes. `openssl.test.mjs` additionally covers PKCS10, CRLs, ECDSA CMS and external TSA verification.

`npm run fuzz -- documents 60` mutates bytes covered by a signed PDF ByteRange, substitutes content under fixed RFC 4998 and RFC 6283 evidence, and generates forbidden XML entity declarations. It exercises complete container verification with fresh synthetic signing and TSA keys. This target tests authenticated coverage and entity rejection; it does not cover every possible third-party PDF or XML grammar.

PDF structure parsing executes behind the reference worker deadline and heap limit. Jazzer instruments the calling verification boundary; the worker's internal parser counters are outside that coverage map. The retained `wiIiLg==` mutation regression also checks that the caller event loop remains responsive. These bounds do not make the experimental parser a recommended production verification boundary.

A campaign result records its actual targets and duration; a short CI budget does not establish exhaustive parser coverage. Add minimized synthetic reproducers to the corpus and a boundary-specific regression before closing a finding.
