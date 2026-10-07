# Benchmarks and synthetic privacy experiments

The reproducible measurements inform [SEP draft 03](../spec/bindings/SEP-draft-03.md). The published performance dataset remains a historical draft-02 run, not a measurement of the new draft-03 evidence layout. All identities, identifiers, keys and documents used by the generators are synthetic.

## Performance and evidence size

Run `npm run benchmark -- output-directory`. [The published software baseline](../reference/datasets/benchmarks-draft02/results.json) includes Node/OpenSSL versions, CPU, platform, sample counts and timing method; [raw timing samples](../reference/datasets/benchmarks-draft02/samples.csv) support independent aggregation. Primitive measurements use a 4 KiB input, five warmups and forty samples per signing or verification algorithm. Indexed proof measurements use twenty samples at each tree size. Full loopback exchanges have one sample per mode and report evidence-object sizes; those observations are sizing examples, not latency distributions.

Compare P-256, ML-DSA-65 and ML-DSA-87 by exact public-key and signature encodings. DER ECDSA signature size can vary between operations. Merkle authentication path bytes exclude certificate fields, the CA signature and mirror cosignatures; total proof/evidence sizes must retain those distinctions. The tree benchmark uses indexed SQLite in memory and does not establish PostgreSQL, HSM or multi-host capacity.

The retained draft-02 run includes the then-selected execution-binding and ordinary modes in one recorded environment. Complete CMS/MTC evidence measured 90,097 bytes without execution binding and 103,880 bytes with it; independent-PQ mdoc evidence measured 76,249 and 90,056 bytes; DEVICE_KEY evidence measured 71,136 and 84,953 bytes. These are historical observations for the recorded synthetic examples, not draft-03 sizes, universal overhead constants or latency distributions. The run metadata and raw samples identify the actual environment.

## Linkability and status traffic

Run `npm run privacy -- output-directory`. The default [privacy dataset](../reference/datasets/privacy-v1/config.json) contains 64 synthetic subjects, four verifiers and three visits per scenario. [Event records](../reference/datasets/privacy-v1/events.jsonl) separate synthetic subject ground truth from observer-visible key, credential, status, issuer and type handles. [Results](../reference/datasets/privacy-v1/results.json) report true/false positives, false negatives, precision, recall and false-positive rates over cross-verifier pairs.

| Scenario                       | Independent key scope  | Credential scope       | Status model                                      |
| ------------------------------ | ---------------------- | ---------------------- | ------------------------------------------------- |
| REUSED_KEY                     | Global subject         | Global subject         | Per-subject URL, each presentation fetches        |
| PAIRWISE_KEY_STABLE_CREDENTIAL | Per verifier           | Global subject         | Per-subject URL, each presentation fetches        |
| PAIRWISE_CREDENTIAL            | Per verifier           | Per verifier           | Per-subject URL, each presentation fetches        |
| ONE_USE_BATCHED                | Per verifier and visit | Per verifier and visit | Shared cohort URLs, cached per verifier and visit |

These identifiers model observable equality; they are not private keys or issued production credentials. The first comparison isolates the fact that changing only the device key leaves the global credential correlatable. The third scenario removes that handle while preserving a uniquely identifying status URL. The final scenario measures residual cohort/metadata correlation and reduced network requests. Its 24-hour lifetime and one-use allocation are model inputs, not empirical wallet behavior.

The equality attacker assumes colluding verifiers. Status URL equality models what an observer of status requests could link; it is not a credential-identity test. The experiment excludes IP addresses, request timing, browser fingerprints, names, biometrics and device telemetry. Real ecosystems may expose all of these. Metadata collisions produce false positives and reduce precision; low precision is not proof of anonymity. A document signature may intentionally retain a stable, accountable signer identity, so its disclosure policy must be evaluated separately from identity presentation.

## Publication and reproduction

The deterministic privacy seed and dimensions are in the dataset configuration. Cryptographic benchmarks generate fresh software keys and timing results vary by environment. Publish new runs in separate versioned directories, retain the method and raw samples, and compare like environments. Documentation and original synthetic datasets use CC BY 4.0; executable generators use Apache-2.0.
