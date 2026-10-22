import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { generate } from './core.mjs';
import { Journal } from './state.mjs';
import { treeHash } from './mtc.mjs';
import * as tlog from './transparency.mjs';

function fixture(t, algorithm) {
  const directory = mkdtempSync(join(tmpdir(), 'certconcord witness empty '));
  const file = join(directory, 'witness.sqlite');
  const log = { ...generate('ed25519'), name: 'log.example/empty', scheme: 'ed25519-log' };
  const signer = {
    ...generate(algorithm),
    name: 'witness.example/empty',
    scheme: algorithm === 'ed25519' ? 'ed25519-cosign' : 'CERTCONCORD-MLDSA87-SUBTREE-v1',
  };
  const logs = new Map([[log.name, log]]);
  let journal = new Journal(file);
  t.after(() => {
    journal.close();
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    assert(basename(directory).startsWith('certconcord witness empty '));
    rmSync(directory, { recursive: true, force: true });
  });
  return {
    log,
    signer,
    get journal() {
      return journal;
    },
    get witness() {
      return new tlog.TlogWitness({ journal, signer, logs });
    },
    get mirror() {
      return new tlog.TlogMirror({ journal, signer, logs });
    },
    reopen() {
      journal.close();
      journal = new Journal(file);
    },
  };
}

for (const algorithm of ['ed25519', 'ml-dsa-87']) {
  for (const prior of ['none', 'canonical']) {
    test(`a ${algorithm} witness rejects an invalid empty root with ${prior} prior state`, (t) => {
      const f = fixture(t, algorithm);
      const canonical = tlog.signedCheckpoint({ origin: f.log.name, entries: [], signer: f.log });
      if (prior === 'canonical')
        assert.equal(f.witness.addCheckpoint(tlog.witnessRequest(0, [], canonical)).status, 200);
      const before = f.journal.get('witness', f.log.name);
      const body = tlog.checkpointBody(f.log.name, 0, Buffer.alloc(32, 9));
      const invalid = body + '\n' + tlog.noteSignature(body, f.log);
      assert.equal(tlog.verifyPublishedCheckpoint(invalid, f.log).size, 0n);
      const request = tlog.witnessRequest(0, [], invalid);
      for (let attempt = 0; attempt < 2; attempt++) {
        assert.throws(() => f.witness.addCheckpoint(request), { code: 'WITNESS_EMPTY_ROOT' });
        assert.deepEqual(f.journal.get('witness', f.log.name), before);
        f.reopen();
        assert.deepEqual(f.journal.get('witness', f.log.name), before);
      }
      const accepted = f.witness.addCheckpoint(tlog.witnessRequest(0, [], canonical));
      assert.equal(accepted.status, 200);
      assert.deepEqual(tlog.verifyNote(canonical + accepted.body, f.signer).root, treeHash([]));
      const entries = [Buffer.from('first leaf')];
      const next = tlog.signedCheckpoint({ origin: f.log.name, entries, signer: f.log });
      const grown = f.witness.addCheckpoint(tlog.witnessRequest(0, [], next));
      assert.equal(grown.status, 200);
      assert.deepEqual(tlog.verifyNote(next + grown.body, f.signer).root, treeHash(entries));
      f.reopen();
      assert.equal(BigInt(f.journal.get('witness', f.log.name).value.size), 1n);
      assert.equal(f.journal.get('witness', f.log.name).value.note, next);
    });
  }
}

test('invalid empty mirror admission leaves no history and permits a canonical retry after reopen', (t) => {
  const f = fixture(t, 'ml-dsa-87');
  const body = tlog.checkpointBody(f.log.name, 0, Buffer.alloc(32, 9));
  const invalid = body + '\n' + tlog.noteSignature(body, f.log);
  assert.throws(() => f.mirror.addCheckpoint(tlog.witnessRequest(0, [], invalid)), {
    code: 'WITNESS_EMPTY_ROOT',
  });
  f.reopen();
  for (const namespace of ['mirror-pending', 'mirror-checkpoint-history', 'mirror-data'])
    assert.deepEqual(f.journal.list(namespace), []);
  assert.equal(f.mirror.storedSize(f.log.name), 0);
  assert.throws(() => f.mirror.checkpoint(f.log.name), { code: 'MIRROR_UNCOMMITTED' });
  const canonical = tlog.signedCheckpoint({ origin: f.log.name, entries: [], signer: f.log });
  assert.equal(f.mirror.addCheckpoint(tlog.witnessRequest(0, [], canonical)).status, 200);
  assert.equal(f.mirror.addEntries(tlog.mirrorUpload(f.log.name, [])).status, 200);
  f.reopen();
  const verified = tlog.verifyNote(f.mirror.checkpoint(f.log.name), f.signer);
  assert.equal(verified.size, 0n);
  assert.deepEqual(verified.root, treeHash([]));
});
