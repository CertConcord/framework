import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import crypto from 'node:crypto';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import dgram from 'node:dgram';
import childProcess from 'node:child_process';
import { registerHooks, syncBuiltinESMExports } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { basename } from 'node:path';

const [publicEntry, installedBundle, databasePath, phase] = process.argv.slice(2);
assert(publicEntry && installedBundle && databasePath && process.argv.length === 6);
assert(
  ['record-compromise', 'reopen-compromise', 'record-positive', 'reopen-missing'].includes(phase),
);
assert.equal(existsSync(databasePath), phase.startsWith('reopen-'));
const hash = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const corpus = new URL('../vectors/organization-history/', import.meta.url);
const manifestBytes = readFileSync(new URL('manifest.json', corpus));
const manifest = JSON.parse(manifestBytes);
assert(Array.isArray(manifest.files) && manifest.files.length <= 512);
for (const file of manifest.files)
  assert(/^files\/[a-f0-9]{64}\.[a-z0-9.]+$/.test(file.path) && file.path.length <= 240);
const before = new Map(
  ['manifest.json', ...manifest.files.map((file) => file.path)].map((path) => [
    path,
    hash(readFileSync(new URL(path, corpus))),
  ]),
);

// These guards precede both the installed package and corpus runner imports.
// They constrain this replay process; they are not a hostile-code sandbox.
const forbiddenCalls = [];
const deny = (name) => () => {
  forbiddenCalls.push(name);
  throw Error('SDK_OFFLINE_FORBIDDEN: ' + name);
};
globalThis.fetch = deny('fetch');
net.Socket.prototype.connect = deny('socket.connect');
for (const [module, names] of [
  [net, ['connect', 'createConnection']],
  [http, ['get', 'request']],
  [https, ['get', 'request']],
  [dgram, ['createSocket']],
  [crypto, ['generateKey', 'generateKeySync', 'generateKeyPair', 'generateKeyPairSync', 'sign']],
  [childProcess, ['exec', 'execSync', 'execFile', 'execFileSync', 'fork', 'spawn', 'spawnSync']],
])
  for (const name of names) module[name] = deny(name);
crypto.Sign.prototype.sign = deny('Sign.sign');
crypto.webcrypto.subtle.generateKey = deny('subtle.generateKey');
crypto.webcrypto.subtle.sign = deny('subtle.sign');
Date.now = deny('Date.now');
syncBuiltinESMExports();
registerHooks({
  resolve(specifier, context, nextResolve) {
    const resolved = nextResolve(specifier, context);
    if (
      resolved.url.startsWith('file:') &&
      /(?:fixture|freeze-organization-vectors|organization-history-vector-semantics)/i.test(
        basename(fileURLToPath(resolved.url)),
      )
    )
      deny('authoring import')();
    return resolved;
  },
});

const sdk = await import(pathToFileURL(publicEntry));
const { loadOrganizationHistoryVectorCorpus } = await import('../organization-vector-corpus.mjs');
const vectors = loadOrganizationHistoryVectorCorpus();
const entry = (id) => {
  const value = vectors.manifest.cases.find((candidate) => candidate.id === id);
  assert(value, id);
  return value;
};
const positiveEntry = entry('expired-issuer-scoped-successor');
const negativeEntry = entry('retrospective-compromise-grant');
const missingEntry = entry('missing-current-both');
for (const value of [negativeEntry, missingEntry]) {
  assert.equal(value.originalBytes, positiveEntry.originalBytes);
  assert.equal(value.evidenceRecord, positiveEntry.evidenceRecord);
}
const positive = vectors.input(positiveEntry);
const negative = vectors.input(negativeEntry);
const missing = vectors.input(missingEntry);
assert.deepEqual(negative.configuration, positive.configuration);
assert.deepEqual(missing.configuration, positive.configuration);
const input = { originalBytes: positive.originalBytes, evidenceRecord: positive.evidenceRecord };
let selected =
  phase === 'record-compromise'
    ? negative.knowledge
    : phase === 'reopen-missing'
      ? missing.knowledge
      : positive.knowledge;
let expected;
if (phase === 'reopen-compromise') {
  let memoryKnowledge = negative.knowledge;
  const memorySource = sdk.createOrganizationHistorySource({
    configuration: positive.configuration,
    readKnowledge: () => memoryKnowledge,
  });
  try {
    const memoryVerifier = sdk.createOrganizationHistoryVerifier({ source: memorySource });
    assert.deepEqual(memoryVerifier.verify(input), vectors.expected(negativeEntry));
    memoryKnowledge = positive.knowledge;
    expected = memoryVerifier.verify(input);
    assert.equal(expected.overall, 'INVALID');
    assert.equal(expected.currentAdmissibility.overall, 'INVALID');
  } finally {
    memorySource.close();
  }
} else
  expected = vectors.expected(
    phase === 'record-compromise'
      ? negativeEntry
      : phase === 'reopen-missing'
        ? missingEntry
        : positiveEntry,
  );
const source = sdk.createOrganizationHistorySource({
  configuration: positive.configuration,
  readKnowledge: () => selected,
  databasePath,
});
let actual, receipt;
try {
  const verifier = sdk.createOrganizationHistoryVerifier({ source });
  const result = verifier.verify(input);
  ({ knowledgeReceipt: receipt, ...actual } = result);
  // The SQLite receipt is the only additional result field in this comparison.
  assert.deepEqual(actual, expected);
  assert.equal(receipt.mode, 'SQLITE');
  assert.equal(receipt.state, 'COMMITTED');
  assert(/^[a-f0-9]{128}$/.test(receipt.scopeID));
  assert(/^[a-f0-9]{128}$/.test(receipt.configurationID));
  assert(/^[a-f0-9]{64}$/.test(receipt.evidenceID));
  assert(Number.isSafeInteger(receipt.revision) && receipt.revision > 0);
  const saved = source.readEvidence(receipt.evidenceID);
  assert.deepEqual(Object.keys(saved).sort(), [
    'classification',
    'evidenceRecord',
    'originalBytes',
  ]);
  assert.equal(saved.classification, 'UNVERIFIED_BYTES');
  assert.deepEqual(saved.originalBytes, input.originalBytes);
  assert.deepEqual(saved.evidenceRecord, input.evidenceRecord);
  saved.originalBytes[0] ^= 1;
  saved.evidenceRecord[0] ^= 1;
  const reread = source.readEvidence(receipt.evidenceID);
  assert.deepEqual(reread.originalBytes, input.originalBytes);
  assert.deepEqual(reread.evidenceRecord, input.evidenceRecord);
} finally {
  source.close();
}
assert.deepEqual(forbiddenCalls, []);
for (const [path, expectedHash] of before)
  assert.equal(hash(readFileSync(new URL(path, corpus))), expectedHash, path);
console.log(
  JSON.stringify({
    phase,
    pid: process.pid,
    overall: actual.overall,
    currentAdmissibility: actual.currentAdmissibility.overall,
    completeResultSHA256: hash(Buffer.from(JSON.stringify(actual))),
    receipt,
    installedBundleSHA256: hash(readFileSync(installedBundle)),
    unchangedFiles: before.size,
    forbiddenCalls,
  }),
);
