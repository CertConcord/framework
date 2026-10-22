import test from 'node:test';
import assert from 'node:assert/strict';
import { generate } from './core.mjs';
import { Journal } from './state.mjs';
import { consistencyProof, treeHash } from './mtc.mjs';
import * as tlog from './transparency.mjs';

function fixture(t, algorithm = 'ed25519') {
  const journal = new Journal();
  t.after(() => journal.close());
  const log = { ...generate('ed25519'), name: 'log.example/root', scheme: 'ed25519-log' };
  const signer = {
    ...generate(algorithm),
    name: 'mirror.example/root',
    scheme: algorithm === 'ed25519' ? 'ed25519-cosign' : 'CERTCONCORD-MLDSA87-SUBTREE-v1',
  };
  const mirror = new tlog.TlogMirror({ journal, signer, logs: new Map([[log.name, log]]) });
  return { journal, log, signer, mirror };
}

for (const algorithm of ['ed25519', 'ml-dsa-87']) {
  test(`mirror rejects a retained noncanonical empty root before issuing a ${algorithm} receipt`, (t) => {
    const { journal, log, mirror } = fixture(t, algorithm);
    const body = tlog.checkpointBody(log.name, 0, Buffer.alloc(32, 9));
    const checkpoint = body + '\n' + tlog.noteSignature(body, log);
    assert.equal(tlog.verifyPublishedCheckpoint(checkpoint, log).size, 0n);
    // Preserve the custody guard for records admitted before empty-root validation.
    journal.put('mirror-pending', log.name, {
      size: 0n,
      root: Buffer.alloc(32, 9),
      note: checkpoint,
      cosignature: '',
    });
    journal.put('mirror-checkpoint-history', log.name + ':0', { note: checkpoint });
    const pending = journal.get('mirror-pending', log.name);
    const history = journal.get('mirror-checkpoint-history', log.name + ':0');
    assert.throws(() => mirror.addEntries(tlog.mirrorUpload(log.name, [])), {
      code: 'MIRROR_CHECKPOINT_ROOT',
    });
    assert.equal(mirror.storedSize(log.name), 0);
    assert.deepEqual(mirror.store(log.name).root(), treeHash([]));
    assert.equal(journal.get('mirror-data', log.name), undefined);
    assert.deepEqual(journal.get('mirror-pending', log.name), pending);
    assert.deepEqual(journal.get('mirror-checkpoint-history', log.name + ':0'), history);
    assert.throws(() => mirror.checkpoint(log.name), { code: 'MIRROR_UNCOMMITTED' });
  });

  test(`mirror signs the canonical empty root and repeats its ${algorithm} receipt`, (t) => {
    const { log, signer, mirror } = fixture(t, algorithm);
    const checkpoint = tlog.signedCheckpoint({ origin: log.name, entries: [], signer: log });
    assert.equal(mirror.addCheckpoint(tlog.witnessRequest(0, [], checkpoint)).status, 200);
    for (let i = 0; i < 2; i++) {
      const result = mirror.addEntries(tlog.mirrorUpload(log.name, []));
      assert.equal(result.status, 200);
      const verified = tlog.verifyNote(checkpoint + result.body, signer);
      assert.equal(verified.size, 0n);
      assert.deepEqual(verified.root, treeHash([]));
      assert.equal(mirror.checkpoint(log.name), checkpoint + result.body);
    }
  });
}

test('mirror completion binds the selected historical prefix while a larger upload is pending', (t) => {
  const { log, signer, mirror } = fixture(t);
  const entries = Array.from({ length: 300 }, (_, i) => Buffer.from('entry ' + i));
  const prefix = entries.slice(0, 256);
  const first = tlog.signedCheckpoint({ origin: log.name, entries: prefix, signer: log });
  const last = tlog.signedCheckpoint({ origin: log.name, entries, signer: log });
  assert.equal(mirror.addCheckpoint(tlog.witnessRequest(0, [], first)).status, 200);
  assert.equal(
    mirror.addCheckpoint(tlog.witnessRequest(256, consistencyProof(entries, 0, 256), last)).status,
    200,
  );
  assert.deepEqual(mirror.addEntries(tlog.mirrorUpload(log.name, entries, 0, { maxPackages: 1 })), {
    status: 202,
    type: 'text/x.tlog.mirror-info',
    body: '300\n256\n\n',
  });
  assert.throws(() => mirror.checkpoint(log.name), { code: 'MIRROR_UNCOMMITTED' });
  assert.equal(mirror.addEntries(tlog.mirrorUpload(log.name, prefix, 256)).status, 200);
  assert.deepEqual(tlog.verifyNote(mirror.checkpoint(log.name), signer).root, treeHash(prefix));
  assert.equal(mirror.addEntries(tlog.mirrorUpload(log.name, entries, 256)).status, 200);
  assert.deepEqual(tlog.verifyNote(mirror.checkpoint(log.name), signer).root, treeHash(entries));
  const repeated = mirror.addEntries(tlog.mirrorUpload(log.name, entries, 300));
  assert.equal(repeated.status, 200);
  assert.equal(tlog.verifyNote(last + repeated.body, signer).size, 300n);
  assert.equal(mirror.storedSize(log.name), 300);
});
