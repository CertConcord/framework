import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { generate } from './core.mjs';
import { Journal } from './state.mjs';
import { consistencyProof } from './mtc.mjs';
import * as tlog from './transparency.mjs';

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'certconcord mirror checkpoint '));
  const file = join(directory, 'mirror.sqlite');
  const log = { ...generate('ed25519'), name: 'log.example/atomic', scheme: 'ed25519-log' };
  const signer = {
    ...generate('ed25519'),
    name: 'mirror.example/atomic',
    scheme: 'ed25519-cosign',
  };
  const logs = new Map([[log.name, log]]);
  let journal = new Journal(file);
  t.after(() => {
    journal.close();
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    assert(basename(directory).startsWith('certconcord mirror checkpoint '));
    rmSync(directory, { recursive: true, force: true });
  });
  return {
    log,
    signer,
    get journal() {
      return journal;
    },
    get mirror() {
      return new tlog.TlogMirror({ journal, signer, logs });
    },
    reopen() {
      journal.close();
      journal = new Journal(file);
    },
    snapshot() {
      return ['mirror-pending', 'mirror-checkpoint-history', 'mirror-data'].map((namespace) =>
        journal.list(namespace).map(({ id }) => [id, journal.get(namespace, id)]),
      );
    },
  };
}

for (const priorSize of [0, 3]) {
  for (const fault of ['after-pending', 'before-history', 'after-history']) {
    test(`mirror checkpoint admission rolls back ${fault} with prior size ${priorSize}`, (t) => {
      const f = fixture(t);
      const entries = Array.from({ length: 4 }, (_, i) => Buffer.from('entry ' + i));
      if (priorSize) {
        const prior = tlog.signedCheckpoint({
          origin: f.log.name,
          entries: entries.slice(0, priorSize),
          signer: f.log,
        });
        assert.equal(f.mirror.addCheckpoint(tlog.witnessRequest(0, [], prior)).status, 200);
        assert.equal(
          f.mirror.addEntries(tlog.mirrorUpload(f.log.name, entries.slice(0, priorSize))).status,
          200,
        );
      }
      const checkpoint = tlog.signedCheckpoint({ origin: f.log.name, entries, signer: f.log });
      const proof = priorSize ? consistencyProof(entries, 0, priorSize) : [];
      const request = tlog.witnessRequest(priorSize, proof, checkpoint);
      const before = f.snapshot();
      const put = f.journal.put.bind(f.journal);
      const failure = new Error('injected checkpoint write failure');
      f.journal.put = (namespace, ...args) => {
        if (fault === 'before-history' && namespace === 'mirror-checkpoint-history') throw failure;
        const result = put(namespace, ...args);
        if (
          (fault === 'after-pending' && namespace === 'mirror-pending') ||
          (fault === 'after-history' && namespace === 'mirror-checkpoint-history')
        )
          throw failure;
        return result;
      };
      assert.throws(
        () => f.mirror.addCheckpoint(request),
        (error) => error === failure,
      );
      assert.deepEqual(f.snapshot(), before);
      f.reopen();
      assert.deepEqual(f.snapshot(), before);
      assert.equal(f.mirror.storedSize(f.log.name), priorSize);
      assert.deepEqual(f.mirror.addCheckpoint(request), {
        status: 200,
        type: 'text/plain',
        body: '',
      });
      assert.equal(f.journal.get('mirror-pending', f.log.name).value.note, checkpoint);
      assert.equal(
        f.journal.get('mirror-checkpoint-history', f.log.name + ':4').value.note,
        checkpoint,
      );
      assert.equal(
        f.mirror.addEntries(tlog.mirrorUpload(f.log.name, entries, priorSize)).status,
        200,
      );
      assert.equal(tlog.verifyNote(f.mirror.checkpoint(f.log.name), f.signer).size, 4n);
    });
  }
}

test('mirror rejects a noncanonical empty fork without changing an admitted checkpoint', (t) => {
  const f = fixture(t);
  const checkpoint = tlog.signedCheckpoint({ origin: f.log.name, entries: [], signer: f.log });
  assert.equal(f.mirror.addCheckpoint(tlog.witnessRequest(0, [], checkpoint)).status, 200);
  const before = f.snapshot();
  const body = tlog.checkpointBody(f.log.name, 0, Buffer.alloc(32, 9));
  const conflicting = body + '\n' + tlog.noteSignature(body, f.log);
  assert.throws(() => f.mirror.addCheckpoint(tlog.witnessRequest(0, [], conflicting)), {
    code: 'WITNESS_EMPTY_ROOT',
  });
  assert.deepEqual(f.snapshot(), before);
  f.reopen();
  assert.deepEqual(f.snapshot(), before);
  assert.equal(f.mirror.addCheckpoint(tlog.witnessRequest(0, [], checkpoint)).status, 200);
  assert.equal(f.mirror.addEntries(tlog.mirrorUpload(f.log.name, [])).status, 200);
  assert.equal(tlog.verifyNote(f.mirror.checkpoint(f.log.name), f.signer).size, 0n);
});

test('mirror checkpoint size conflict leaves pending and historical state unchanged', (t) => {
  const f = fixture(t);
  const checkpoint = tlog.signedCheckpoint({
    origin: f.log.name,
    entries: [Buffer.from('one')],
    signer: f.log,
  });
  const request = tlog.witnessRequest(0, [], checkpoint);
  assert.equal(f.mirror.addCheckpoint(request).status, 200);
  const before = f.snapshot();
  assert.deepEqual(f.mirror.addCheckpoint(request), {
    status: 409,
    type: 'text/x.tlog.size',
    body: '1\n',
  });
  f.reopen();
  assert.deepEqual(f.snapshot(), before);
});

test('a conflicting legacy empty history row remains protected by atomic admission', (t) => {
  const f = fixture(t);
  const root = Buffer.alloc(32, 9);
  const body = tlog.checkpointBody(f.log.name, 0, root);
  const note = body + '\n' + tlog.noteSignature(body, f.log);
  // Reproduce conflicting history retained before pending/history writes were atomic.
  const canonical = tlog.signedCheckpoint({ origin: f.log.name, entries: [], signer: f.log });
  f.journal.put('mirror-pending', f.log.name, {
    size: 0n,
    root: tlog.parseCheckpoint(canonical).root,
    note: canonical,
    cosignature: '',
  });
  f.journal.put('mirror-checkpoint-history', f.log.name + ':0', { note });
  const before = f.snapshot();
  for (let attempt = 0; attempt < 2; attempt++) {
    assert.throws(() => f.mirror.addCheckpoint(tlog.witnessRequest(0, [], canonical)), {
      code: 'MIRROR_CHECKPOINT_FORK',
    });
    assert.deepEqual(f.snapshot(), before);
    f.reopen();
    assert.deepEqual(f.snapshot(), before);
    assert.throws(() => f.mirror.checkpoint(f.log.name), { code: 'MIRROR_UNCOMMITTED' });
  }
});
