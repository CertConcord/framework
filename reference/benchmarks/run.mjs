import { performance } from 'node:perf_hooks';
import os from 'node:os';
import { mkdir, writeFile } from 'node:fs/promises';
import { generate, sign, verify, spki, dcbor } from '../core.mjs';
import { Journal } from '../state.mjs';
import { IndexedMerkleLog } from '../storage/merkle.mjs';
import { runDemo } from '../demo.mjs';
import { runFoundationDemo } from '../foundation-demo.mjs';
import { parseCertificate } from '../pki.mjs';
import { decodeProof } from '../mtc.mjs';
import { readControl } from '../state.mjs';
const output = process.argv[2] ?? '.runtime/benchmarks';
await mkdir(output, { recursive: true });
const samples = [];
function measure(name, fn, n = 40) {
  for (let i = 0; i < 5; i++) fn();
  let value;
  const times = [];
  for (let i = 0; i < n; i++) {
    const at = performance.now();
    value = fn();
    const ms = performance.now() - at;
    times.push(ms);
    samples.push({ name, sample: i, ms });
  }
  times.sort((a, b) => a - b);
  return {
    name,
    samples: n,
    p50Ms: times[Math.floor(n * 0.5)],
    p95Ms: times[Math.min(n - 1, Math.floor(n * 0.95))],
    value,
  };
}
const algorithm = [];
for (const alg of ['ec', 'ml-dsa-65', 'ml-dsa-87']) {
  const key = generate(alg),
    document = Buffer.alloc(4096, 7),
    sig = sign(document, key.privateKey);
  for (const op of ['sign', 'verify']) {
    const { value, ...r } = measure(alg + '-' + op, () =>
      op === 'sign' ? sign(document, key.privateKey) : verify(document, sig, key.publicKey),
    );
    algorithm.push({
      ...r,
      documentBytes: document.length,
      spkiBytes: spki(key.publicKey).length,
      signatureBytes: sig.length,
    });
  }
}
const merkle = [],
  journal = new Journal(),
  log = new IndexedMerkleLog(journal, 'benchmark');
let inserted = 0;
for (const size of [1, 16, 256, 4096, 16384]) {
  const at = performance.now();
  while (inserted < size) {
    log.append(Buffer.from('synthetic-entry-' + inserted), String(inserted));
    inserted++;
  }
  const appendMs = performance.now() - at;
  const { value, ...timing } = measure(
    'proof-' + size,
    () => log.inclusion(Math.floor(size / 2), size),
    20,
  );
  merkle.push({
    ...timing,
    treeSize: size,
    proofNodes: value.length,
    proofBytes: value.length * 32,
    appendBatchMs: appendMs,
  });
}
journal.close();
const evidence = [];
for (const format of [
  'CMS',
  'MDOC_PQ',
  'MDOC_DEVICE',
  'MDOC_PASSKEY',
  'CMS_EXECUTION',
  'MDOC_PQ_EXECUTION',
  'MDOC_DEVICE_EXECUTION',
]) {
  const baseFormat = format.replace(/_EXECUTION$/, ''),
    executionBinding = format.endsWith('_EXECUTION');
  const at = performance.now();
  const r =
    baseFormat === 'CMS'
      ? await runDemo({ executionBinding })
      : await runFoundationDemo({
          executionBinding,
          documentKeyMode:
            baseFormat === 'MDOC_DEVICE'
              ? 'DEVICE_KEY'
              : baseFormat === 'MDOC_PASSKEY'
                ? 'PASSKEY_KEY'
                : 'INDEPENDENT_PQ',
          activationMode: baseFormat === 'MDOC_PASSKEY' ? 'HUMAN_WEBAUTHN' : 'HUMAN_MDOC',
        });
  const exchangeMs = performance.now() - at,
    object = (type) => r.bundle.objects.find((o) => o.type === type)?.payload;
  let proof;
  if (baseFormat === 'CMS') {
    const bytes = parseCertificate(object('Certificate')).signature,
      parsed = decodeProof(bytes);
    proof = {
      format: 'MTC_DRAFT_06',
      totalBytes: bytes.length,
      authenticationPathBytes: parsed.inclusion.length * 32,
      signatures: parsed.signatures.map((s) => ({
        algorithm: 'ML-DSA-87',
        bytes: s.signature.length,
      })),
    };
  } else {
    const seal = readControl(
      object('CredentialSeal'),
      'MdocCredentialSeal',
      r.trust.sealCertificate,
    );
    proof = {
      format: 'CERTCONCORD_MDOC_ISSUANCE_LOG',
      totalBytes: dcbor(seal.logProof).length,
      authenticationPathBytes: seal.logProof.path.length * 32,
      checkpointBytes: Buffer.byteLength(seal.logProof.checkpoint),
      mirrorReceiptBytes: seal.logProof.receipts.map((s) => Buffer.byteLength(s.note)),
    };
  }
  evidence.push({
    format,
    fullExchangeMs: exchangeMs,
    evidenceBytes: dcbor(r.bundle).length,
    proof,
    objects: r.bundle.objects.map((o) => ({ type: o.type, bytes: o.payload.length })),
    result: r.verification.overall,
  });
}
const environment = {
  node: process.version,
  openssl: process.versions.openssl,
  platform: process.platform,
  arch: process.arch,
  cpu: os.cpus()[0]?.model,
  logicalCPUs: os.cpus().length,
  totalMemory: os.totalmem(),
  timestamp: new Date().toISOString(),
};
const report = {
  schemaVersion: 1,
  synthetic: true,
  environment,
  method: {
    warmup: 5,
    algorithmSamples: 40,
    proofSamples: 20,
    evidenceSamples: 1,
    clock: 'performance.now',
    storage: 'SQLite in-memory indexed rows',
    network: 'loopback only',
    keys: 'fresh synthetic software keys',
  },
  algorithm,
  merkle,
  evidence,
};
await writeFile(output + '/results.json', JSON.stringify(report, null, 2) + '\n');
await writeFile(
  output + '/samples.csv',
  'name,sample,ms\n' + samples.map((r) => `${r.name},${r.sample},${r.ms}`).join('\n') + '\n',
);
console.log(
  JSON.stringify({
    algorithms: algorithm.length,
    treeSizes: merkle.map((x) => x.treeSize),
    evidence: evidence.map((x) => ({ format: x.format, bytes: x.evidenceBytes })),
    output,
  }),
);
