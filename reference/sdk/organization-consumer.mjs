import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import crypto from 'node:crypto';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import dgram from 'node:dgram';
import childProcess from 'node:child_process';
import { registerHooks, syncBuiltinESMExports } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { basename } from 'node:path';

const [publicEntry, installedBundle] = process.argv.slice(2);
assert(publicEntry && installedBundle && process.argv.length === 4);
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
const { runOrganizationHistoryVectors } = await import('../verify-organization-vectors.mjs');
const sources = new WeakSet();
const calls = { source: 0, verifier: 0, verify: 0 };
const results = runOrganizationHistoryVectors({
  createOrganizationHistorySource(options) {
    assert.deepEqual(Object.keys(options).sort(), ['configuration', 'readKnowledge']);
    const source = sdk.createOrganizationHistorySource(options);
    sources.add(source);
    calls.source++;
    return source;
  },
  createOrganizationHistoryVerifier(options) {
    assert.deepEqual(Object.keys(options), ['source']);
    assert(sources.has(options.source));
    const verifier = sdk.createOrganizationHistoryVerifier(options);
    calls.verifier++;
    return Object.freeze({
      verify(input) {
        assert.deepEqual(Object.keys(input).sort(), ['evidenceRecord', 'originalBytes']);
        assert(Buffer.isBuffer(input.originalBytes) && Buffer.isBuffer(input.evidenceRecord));
        calls.verify++;
        return verifier.verify(input);
      },
    });
  },
});
assert(manifest.cases.length > 0);
assert.deepEqual(
  results.map(({ id }) => id),
  manifest.cases.map(({ id }) => id),
);
assert.deepEqual(calls, {
  source: manifest.cases.length,
  verifier: manifest.cases.length,
  verify: manifest.cases.length,
});
assert.deepEqual(forbiddenCalls, []);
for (const [path, expectedHash] of before)
  assert.equal(hash(readFileSync(new URL(path, corpus))), expectedHash, path);
console.log(
  JSON.stringify({
    cases: results.length,
    calls,
    corpusSHA256: hash(manifestBytes),
    installedBundleSHA256: hash(readFileSync(installedBundle)),
    unchangedFiles: before.size,
    forbiddenCalls,
  }),
);
