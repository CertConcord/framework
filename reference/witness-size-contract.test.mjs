import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { generate } from './core.mjs';
import { Journal } from './state.mjs';
import * as tlog from './transparency.mjs';

function fixture(t, kind) {
  const directory = mkdtempSync(join(tmpdir(), 'certconcord witness size '));
  const file = join(directory, 'state.sqlite');
  const log = { ...generate('ed25519'), name: 'log.example/size', scheme: 'ed25519-log' };
  const signer = { ...generate('ed25519'), name: 'witness.example/size', scheme: 'ed25519-cosign' };
  const logs = new Map([[log.name, log]]);
  let journal = new Journal(file);
  t.after(() => {
    journal.close();
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    assert(basename(directory).startsWith('certconcord witness size '));
    rmSync(directory, { recursive: true, force: true });
  });
  return {
    log,
    signer,
    get service() {
      return kind === 'witness'
        ? new tlog.TlogWitness({ journal, signer, logs })
        : new tlog.TlogMirror({ journal, signer, logs });
    },
    snapshot() {
      return ['witness', 'mirror-pending', 'mirror-checkpoint-history', 'mirror-data'].map(
        (namespace) => journal.list(namespace).map(({ id }) => [id, journal.get(namespace, id)]),
      );
    },
    reopen() {
      journal.close();
      journal = new Journal(file);
    },
  };
}

for (const kind of ['witness', 'mirror']) {
  for (const size of [0x7fffffffffffffffn, 0x8000000000000000n, 0xffffffffffffffffn]) {
    test(kind + ' repeats a declared uint64 checkpoint of size ' + size + ' after reopen', (t) => {
      const f = fixture(t, kind);
      // These signed declarations exercise numeric transport; no enormous tree is materialized.
      const root = Buffer.alloc(32, 8);
      const body = tlog.checkpointBody(f.log.name, size, root);
      const checkpoint = body + '\n' + tlog.noteSignature(body, f.log);
      assert.equal(tlog.parseCheckpoint(checkpoint).size, size);
      assert.equal(f.service.addCheckpoint(tlog.witnessRequest(0, [], checkpoint)).status, 200);
      const before = f.snapshot();
      f.reopen();
      assert.deepEqual(f.snapshot(), before);
      assert.deepEqual(f.service.addCheckpoint(tlog.witnessRequest(0, [], checkpoint)), {
        status: 409,
        type: 'text/x.tlog.size',
        body: size + '\n',
      });
      assert.deepEqual(f.snapshot(), before);
      const repeated = f.service.addCheckpoint(tlog.witnessRequest(size, [], checkpoint));
      assert.equal(repeated.status, 200);
      if (kind === 'witness') {
        const verified = tlog.verifyNote(checkpoint + repeated.body, f.signer);
        assert.equal(verified.size, size);
        assert.deepEqual(verified.root, root);
      } else {
        assert.equal(repeated.body, '');
        assert.equal(f.service.storedSize(f.log.name), 0);
        assert.throws(() => f.service.checkpoint(f.log.name), { code: 'MIRROR_UNCOMMITTED' });
      }
      const after = f.snapshot();
      f.reopen();
      assert.deepEqual(f.snapshot(), after);
    });
  }

  test(
    kind + ' rejects noncanonical and overflowing sizes without changing retained state',
    (t) => {
      const f = fixture(t, kind);
      const checkpoint = tlog.signedCheckpoint({ origin: f.log.name, entries: [], signer: f.log });
      assert.equal(f.service.addCheckpoint(tlog.witnessRequest(0, [], checkpoint)).status, 200);
      const before = f.snapshot();
      for (const text of ['-1', '+1', '01', '1.0', ' 1'])
        assert.throws(() => f.service.addCheckpoint('old ' + text + '\n\n' + checkpoint), {
          code: 'NOTE_DECIMAL',
        });
      assert.throws(() => f.service.addCheckpoint(tlog.witnessRequest(1n << 64n, [], checkpoint)), {
        code: 'NOTE_SIZE',
      });
      const body = tlog.checkpointBody(f.log.name, 1n << 64n, Buffer.alloc(32, 8));
      const overflow = body + '\n' + tlog.noteSignature(body, f.log);
      assert.throws(() => f.service.addCheckpoint(tlog.witnessRequest(0, [], overflow)), {
        code: 'SUBTREE_RANGE',
      });
      const excessiveProof = Array(64).fill(Buffer.alloc(32).toString('base64')).join('\n');
      assert.throws(
        () => f.service.addCheckpoint('old 0\n' + excessiveProof + '\n\n' + checkpoint),
        {
          code: 'WITNESS_PROOF',
        },
      );
      assert.deepEqual(f.snapshot(), before);
      f.reopen();
      assert.deepEqual(f.snapshot(), before);
      assert.equal(f.service.addCheckpoint(tlog.witnessRequest(0, [], checkpoint)).status, 200);
    },
  );
}
