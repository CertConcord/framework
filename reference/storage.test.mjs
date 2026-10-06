import test from 'node:test';
import assert from 'node:assert/strict';
import { Journal } from './state.mjs';
import { IndexedMerkleLog, migrateArrayLog, migrateMirrorLog } from './storage/merkle.mjs';
import { treeHash, inclusionProof, consistencyProof, verifyConsistency } from './mtc.mjs';

test('indexed Merkle storage matches independent recursive proofs at power and tile boundaries', () => {
  const journal = new Journal(),
    log = new IndexedMerkleLog(journal, 'test');
  const entries = Array.from({ length: 513 }, (_, i) => Buffer.from('synthetic-' + i));
  try {
    for (const [i, e] of entries.entries()) assert.equal(log.append(e, String(i)), i);
    for (const size of [0, 1, 2, 3, 7, 8, 9, 255, 256, 257, 512, 513]) {
      const prefix = entries.slice(0, size);
      assert.deepEqual(log.root(size), treeHash(prefix));
      for (const index of new Set([0, Math.floor(size / 2), size - 1]))
        if (index >= 0 && index < size) {
          assert.deepEqual(log.inclusion(index, size), inclusionProof(prefix, index));
        }
      for (const end of [0, 1, 3, 128, 256, size].filter((x) => x <= size)) {
        const proof = log.consistency(0, end, size);
        assert.deepEqual(proof, consistencyProof(prefix, 0, end));
        verifyConsistency({
          start: 0,
          end,
          size,
          node: log.root(end),
          root: log.root(size),
          proof,
        });
      }
    }
    for (const [start, end] of [
      [0, 256],
      [256, 512],
      [512, 513],
    ]) {
      assert.deepEqual(log.consistency(start, end, 513), consistencyProof(entries, start, end));
    }
    assert.equal(log.append(entries[0], '0'), 0);
    assert.throws(() => log.append(Buffer.from('changed'), '0'), /LOG_ID_CONFLICT/);
    assert.throws(() => log.entries(0, 513), /LOG_RANGE/);
    assert(!journal.list(log.ns).some((row) => row.id === 'entries'));
  } finally {
    journal.close();
  }
});

test('legacy log migration is explicit, repeatable and rejects divergent prefixes', () => {
  const j = new Journal();
  try {
    j.put('legacy', 'log', { entries: [Buffer.from('a'), Buffer.from('b')], ids: ['a', 'b'] });
    const options = { namespace: 'legacy', id: 'log', origin: 'test' };
    assert.equal(migrateArrayLog(j, options).size, 2);
    assert.equal(migrateArrayLog(j, options).size, 2);
    assert.equal(j.get('legacy', 'log').value.entries.length, 2);
    j.put('legacy', 'log', { entries: [Buffer.from('changed')] }, 0);
    assert.throws(() => migrateArrayLog(j, options), /MIGRATION_CONFLICT/);
  } finally {
    j.close();
  }
});

test('mirror migration preserves authenticated roots, archives source rows and rolls back divergence', () => {
  const j = new Journal(),
    entries = [Buffer.from('one'), Buffer.from('two')];
  try {
    j.put('mirror-data', 'example/log', {
      entries,
      size: 2n,
      note: 'example/log\n2\n' + treeHash(entries).toString('base64') + '\n\nsignature',
    });
    assert.equal(migrateMirrorLog(j, { kind: 'tlog', origin: 'example/log' }).size, 2);
    assert.equal(migrateMirrorLog(j, { kind: 'tlog', origin: 'example/log' }).size, 2);
    assert.equal(j.get('mirror-data', 'example/log').value.entries, undefined);
    assert.deepEqual(j.get('log-migration-archive', 'tlog:example/log').value.entries, entries);
    const log = new IndexedMerkleLog(j, 'tlog:example/log');
    assert.equal(log.append(entries[1], '1'), 1);
    j.put('mirror', 'bad/log', { entries, size: 2, root: Buffer.alloc(32) });
    assert.throws(
      () => migrateMirrorLog(j, { kind: 'mtc-mirror', origin: 'bad/log' }),
      /LOG_MIGRATION_ROOT/,
    );
    assert.equal(new IndexedMerkleLog(j, 'mtc-mirror:bad/log').head().size, 0);
    assert.deepEqual(j.get('mirror', 'bad/log').value.entries, entries);
  } finally {
    j.close();
  }
});
