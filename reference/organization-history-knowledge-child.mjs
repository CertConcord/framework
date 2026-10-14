// Test process: consumes public bytes only. No fixture, issuance, or signer import.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { decodeCBOR, sha256 } from './core.mjs';
import { Journal } from './state.mjs';
import {
  createOrganizationHistorySource,
  createOrganizationHistoryVerifier,
} from './sdk/index.mjs';

const [dataPath, databasePath, output, seam = 'none'] = process.argv.slice(2);
const data = decodeCBOR(readFileSync(dataPath));
const source = createOrganizationHistorySource({
  configuration: data.configuration,
  readKnowledge: () => data.knowledge,
  databasePath,
});
const pause = () => {
  writeFileSync(output + '.ready', JSON.stringify({ pid: process.pid, seam }));
  const signal = new Int32Array(new SharedArrayBuffer(4));
  while (!existsSync(output + '.release')) Atomics.wait(signal, 0, 0, 50);
};
let armed = true;
const transaction = Journal.prototype.transaction,
  put = Journal.prototype.put;
if (seam === 'before-append')
  Journal.prototype.put = function (...args) {
    if (armed) {
      armed = false;
      pause();
    }
    return put.apply(this, args);
  };
if (seam === 'before-commit' || seam === 'after-commit')
  Journal.prototype.transaction = function (fn) {
    const outer = !this.depth;
    const result = transaction.call(this, () => {
      const value = fn();
      if (outer && armed && seam === 'before-commit') {
        armed = false;
        pause();
      }
      return value;
    });
    if (outer && armed && seam === 'after-commit') {
      armed = false;
      pause();
    }
    return result;
  };
if (seam === 'lock') {
  const lock = new Journal(databasePath);
  lock.transaction(pause);
  lock.close();
} else {
  const input = data.evidenceID ? source.readEvidence(data.evidenceID) : data.input;
  const result = createOrganizationHistoryVerifier({ source }).verify({
    originalBytes: input.originalBytes,
    evidenceRecord: input.evidenceRecord,
  });
  writeFileSync(
    output,
    JSON.stringify({
      pid: process.pid,
      result,
      originalHash: sha256(input.originalBytes).toString('hex'),
      evidenceRecordHash: sha256(input.evidenceRecord).toString('hex'),
    }),
  );
}
source.close();
