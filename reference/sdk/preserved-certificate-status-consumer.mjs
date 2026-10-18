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
const directory = new URL('../vectors/preserved-certificate-status/', import.meta.url);
const manifestBytes = readFileSync(new URL('manifest.json', directory));
const manifest = JSON.parse(manifestBytes);
assert(Array.isArray(manifest.files) && manifest.files.length <= 512);
for (const file of manifest.files)
  assert(/^files\/[a-f0-9]{64}\.[a-z0-9.]+$/.test(file.path) && file.path.length <= 240);
const before = new Map(
  ['manifest.json', ...manifest.files.map((file) => file.path)].map((path) => [
    path,
    hash(readFileSync(new URL(path, directory))),
  ]),
);

// These replay guards precede the installed package and public-byte loader.
// They are test instrumentation, not a hostile-code sandbox.
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
      /(?:fixture|freeze-.*vectors|(?:history-vector|certificate-status)-semantics)/i.test(
        basename(fileURLToPath(resolved.url)),
      )
    )
      deny('authoring import')();
    return resolved;
  },
});

const sdk = await import(pathToFileURL(publicEntry));
const { loadOrganizationHistoryVectorCorpus } = await import('../organization-vector-corpus.mjs');
const corpus = loadOrganizationHistoryVectorCorpus(fileURLToPath(directory));
const entry = (id) => {
  const value = corpus.manifest.cases.find((candidate) => candidate.id === id);
  assert(value, id);
  return value;
};
const positiveEntry = entry('preserved-good');
const positive = corpus.input(positiveEntry);
const incident = corpus.input(entry('compromise-before-document-proof'));
const successor = corpus.input(entry('unpreserved-current-successor'));
assert.deepEqual(incident.configuration, positive.configuration);
assert.deepEqual(successor.configuration, positive.configuration);
const input = { originalBytes: positive.originalBytes, evidenceRecord: positive.evidenceRecord };
let selected = phase === 'record-compromise' ? incident.knowledge : positive.knowledge;
if (phase === 'reopen-compromise') {
  const control = sdk.createOrganizationHistorySource({
    configuration: successor.configuration,
    readKnowledge: () => successor.knowledge,
  });
  try {
    assert.equal(
      sdk.createOrganizationHistoryVerifier({ source: control }).verify(input).overall,
      'VALID',
    );
  } finally {
    control.close();
  }
  selected = { ...successor.knowledge, authorityHistory: [] };
} else if (phase === 'reopen-missing')
  selected = { ...positive.knowledge, authorityHistory: [], certificateStatusMaterial: [] };
const selectedInput =
  phase === 'record-compromise'
    ? { originalBytes: Buffer.from([0xff]), evidenceRecord: Buffer.from([0xff]) }
    : input;
let reads = 0;
const source = sdk.createOrganizationHistorySource({
  configuration: positive.configuration,
  readKnowledge: () => {
    reads++;
    return selected;
  },
  databasePath,
});
let actual, receipt;
try {
  const result = sdk.createOrganizationHistoryVerifier({ source }).verify(selectedInput);
  ({ knowledgeReceipt: receipt, ...actual } = result);
  assert.equal(reads, 1);
  assert.equal(receipt.mode, 'SQLITE');
  assert.equal(receipt.state, 'COMMITTED');
  assert(/^[a-f0-9]{128}$/.test(receipt.scopeID));
  assert(/^[a-f0-9]{128}$/.test(receipt.configurationID));
  assert(Number.isSafeInteger(receipt.revision) && receipt.revision > 0);
  if (phase === 'record-compromise') {
    assert.equal(actual.overall, 'INVALID');
    assert.equal(receipt.evidenceID, null);
  } else {
    assert(/^[a-f0-9]{64}$/.test(receipt.evidenceID));
    const retained = source.readEvidence(receipt.evidenceID);
    assert.equal(retained.classification, 'UNVERIFIED_BYTES');
    assert.deepEqual(retained.originalBytes, input.originalBytes);
    assert.deepEqual(retained.evidenceRecord, input.evidenceRecord);
    assert.equal(actual.historicalAuthorization.overall, 'VALID');
    assert.equal(actual.preservation.overall, 'VALID');
    if (phase === 'record-positive') assert.deepEqual(actual, corpus.expected(positiveEntry));
    else if (phase === 'reopen-compromise') {
      assert.equal(actual.overall, 'INVALID');
      assert.equal(actual.currentAdmissibility.overall, 'INVALID');
      assert.equal(actual.currentAdmissibility.reason, 'STATUS_REVOKED');
    } else {
      assert.equal(actual.overall, 'INDETERMINATE');
      assert.equal(actual.currentAdmissibility.overall, 'INDETERMINATE');
      assert.equal(actual.currentAdmissibility.reason, 'STATUS_STALE');
    }
  }
} finally {
  source.close();
}
assert.deepEqual(forbiddenCalls, []);
for (const [path, expectedHash] of before)
  assert.equal(hash(readFileSync(new URL(path, directory))), expectedHash, path);
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
