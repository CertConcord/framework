import fs from 'node:fs';
import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import dgram from 'node:dgram';
import childProcess from 'node:child_process';
import { deserialize, serialize } from 'node:v8';
import { registerHooks, syncBuiltinESMExports } from 'node:module';

const [requestPath, responsePath] = process.argv.slice(2);
const request = deserialize(fs.readFileSync(requestPath));
let forbiddenActions = 0;
const forbidden = () => {
  forbiddenActions++;
  throw new Error('INDEPENDENT_HISTORY_REPLAY_FORBIDDEN_ACTION');
};
for (const [module, names] of [
  [crypto, ['sign', 'generateKeyPair', 'generateKeyPairSync', 'createPrivateKey']],
  [http, ['request', 'get']],
  [https, ['request', 'get']],
  [net, ['connect', 'createConnection', 'createServer']],
  [dgram, ['createSocket']],
  [childProcess, ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']],
])
  for (const name of names) module[name] = forbidden;
globalThis.fetch = forbidden;
let clockReads = 0;
Date.now = () => {
  clockReads++;
  return forbidden();
};
syncBuiltinESMExports();
registerHooks({
  resolve(specifier, context, next) {
    const resolved = next(specifier, context);
    if (
      resolved.url.includes('fixtures-') ||
      resolved.url.includes('freeze-organization-vectors') ||
      resolved.url.includes('vector-semantics') ||
      resolved.url.endsWith('.test.mjs')
    )
      forbidden();
    return resolved;
  },
});
const { createOrganizationHistorySource, createOrganizationHistoryVerifier } = await import(
  './sdk/index.mjs'
);
let reads = 0,
  writes = 0,
  outerTransactions = 0,
  source;
function publishMarker(path, marker) {
  const temporaryPath = path + '.tmp';
  fs.writeFileSync(temporaryPath, JSON.stringify(marker));
  fs.renameSync(temporaryPath, path);
}
const blocked = (name) => {
  publishMarker(request.readyPath, { pid: process.pid, name, writes, reads, outerTransactions });
  const wait = new Int32Array(new SharedArrayBuffer(4));
  while (!request.releasePath || !fs.existsSync(request.releasePath)) Atomics.wait(wait, 0, 0, 20);
};
try {
  source = createOrganizationHistorySource({
    configuration: request.configuration,
    readKnowledge() {
      reads++;
      if (request.seam === 'after-snapshot') blocked('after-snapshot');
      return request.knowledge;
    },
    ...(request.databasePath ? { databasePath: request.databasePath } : {}),
  });
  if (request.onlyReadEvidence) {
    const retainedEvidence = source.readEvidence(request.readEvidenceID);
    fs.writeFileSync(
      responsePath,
      serialize({ pid: process.pid, reads, clockReads, forbiddenActions, retainedEvidence }),
    );
  } else {
    if (request.seam) {
      const { Journal } = await import('./state.mjs');
      const originalPut = Journal.prototype.put,
        originalTransaction = Journal.prototype.transaction;
      Journal.prototype.put = function (...args) {
        if (request.seam === 'before-append' && writes === 0) blocked('before-append');
        if (request.seam === 'write-failure')
          throw Object.assign(new Error('simulated write failure'), { overall: 'VALID' });
        const result = originalPut.apply(this, args);
        writes++;
        return result;
      };
      Journal.prototype.transaction = function (callback) {
        const outer = !this.depth;
        if (outer) outerTransactions++;
        if (outer && request.beginPath)
          publishMarker(request.beginPath, {
            pid: process.pid,
            name: 'before-begin',
            reads,
            outerTransactions,
          });
        const result = originalTransaction.call(this, () => {
          const value = callback();
          if (outer && request.seam === 'before-commit') blocked('before-commit');
          return value;
        });
        if (outer && request.seam === 'after-commit') blocked('after-commit');
        if (outer && request.seam === 'lost-commit-ack')
          throw new Error('simulated acknowledgement loss');
        return result;
      };
    }
    const result = createOrganizationHistoryVerifier({ source }).verify(request.input);
    let evidence, followup, retainedEvidence;
    if (
      !request.deferEvidence &&
      result.knowledgeReceipt?.state === 'COMMITTED' &&
      result.knowledgeReceipt.evidenceID
    )
      evidence = source.readEvidence(result.knowledgeReceipt.evidenceID);
    if (request.seam === 'lost-commit-ack')
      followup = createOrganizationHistoryVerifier({ source }).verify(request.input);
    if (request.readEvidenceID) retainedEvidence = source.readEvidence(request.readEvidenceID);
    const response = {
      pid: process.pid,
      reads,
      clockReads,
      forbiddenActions,
      result,
      ...(evidence ? { evidence } : {}),
      ...(followup ? { followup } : {}),
      ...(retainedEvidence ? { retainedEvidence } : {}),
    };
    source.close();
    source = null;
    fs.writeFileSync(responsePath, serialize(response));
  }
} catch (error) {
  fs.writeFileSync(
    responsePath,
    serialize({
      pid: process.pid,
      reads,
      clockReads,
      forbiddenActions,
      error: { name: error.name, code: error.code ?? null, message: error.message },
    }),
  );
  process.exitCode = 1;
} finally {
  source?.close();
}
