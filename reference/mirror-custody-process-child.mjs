import { readFileSync, writeSync } from 'node:fs';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { Journal } from './state.mjs';
import { TlogMirror } from './transparency.mjs';

const input = JSON.parse(readFileSync(0, 'utf8'));
const log = { ...input.log, publicKey: createPublicKey(input.log.publicKey) };
const signer = { ...input.signer, privateKey: createPrivateKey(input.signer.privateKey) };
const journal = new Journal(input.path);
const mirror = new TlogMirror({ journal, signer, logs: new Map([[log.name, log]]) });
const put = journal.put.bind(journal);
function terminate(namespace, when) {
  if (input.fault?.namespace !== namespace || input.fault.when !== when) return;
  writeSync(1, JSON.stringify({ reached: input.fault }) + '\n');
  process.kill(process.pid, 'SIGKILL');
  throw new Error('Process survived SIGKILL');
}
journal.put = (namespace, ...args) => {
  terminate(namespace, 'before');
  const result = put(namespace, ...args);
  terminate(namespace, 'after');
  return result;
};
try {
  let result;
  try {
    if (input.action === 'admit') result = mirror.addCheckpoint(input.request);
    else if (input.action === 'upload')
      result = mirror.addEntries(Buffer.from(input.upload, 'base64'));
    else if (input.action !== 'inspect') throw new Error('Unknown process action');
  } catch (error) {
    if (!error.code) throw error;
    result = { error: error.code };
  }
  const store = mirror.store(log.name);
  const snapshot = {
    pending: journal.get('mirror-pending', log.name) ?? null,
    history: journal
      .list('mirror-checkpoint-history')
      .map(({ id }) => [id, journal.get('mirror-checkpoint-history', id)]),
    published: journal.get('mirror-data', log.name) ?? null,
    storedSize: store.head().size,
    storedRoot: store.root().toString('hex'),
    entries: Array.from({ length: store.head().size }, (_, index) =>
      store.entry(index).toString('base64'),
    ),
  };
  writeSync(1, JSON.stringify({ result, snapshot }) + '\n');
} finally {
  journal.close();
}
