import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { generate, random, equal } from './core.mjs';
import { Journal } from './state.mjs';
import { consistencyProof, treeHash } from './mtc.mjs';
import * as t from './transparency.mjs';
test('C2SP checkpoint, witness conflict, durable mirror prefix upload and ML-DSA subtree', () => {
  const journal = new Journal(),
    log = { ...generate('ed25519'), name: 'log.example/test', scheme: 'ed25519-log' },
    witness = { ...generate('ed25519'), name: 'witness.example/test', scheme: 'ed25519-cosign' },
    mirrorSigner = {
      ...generateKeyPairSync('ml-dsa-44'),
      name: 'mirror.example/test',
      scheme: 'mldsa44-cosign',
    },
    logs = new Map([[log.name, log]]),
    entries = Array.from({ length: 300 }, (_, i) => Buffer.from('entry ' + i)),
    cp = t.signedCheckpoint({ origin: log.name, entries, signer: log }),
    request = t.witnessRequest(0, [], cp),
    w = new t.TlogWitness({ journal, signer: witness, logs }),
    mirror = new t.TlogMirror({ journal, signer: mirrorSigner, logs });
  try {
    const signed = w.addCheckpoint(request);
    t.verifyNote(cp + signed.body, witness);
    assert.equal(w.addCheckpoint(request).status, 409);
    assert.equal(mirror.addCheckpoint(request).body, '');
    assert.throws(() => mirror.checkpoint(log.name), /UNCOMMITTED/);
    const part = mirror.addEntries(
      gzipSync(t.mirrorUpload(log.name, entries, 0, { maxPackages: 1 })),
      { gzip: true },
    );
    assert.equal(part.status, 202);
    assert.equal(part.body, '300\n256\n\n');
    const complete = mirror.addEntries(t.mirrorUpload(log.name, entries, 256));
    assert.equal(complete.status, 200);
    t.verifyNote(mirror.checkpoint(log.name), mirrorSigner);
    assert(mirror.entryBundle(log.name, 1, { width: 44 }).length > 0);
    const subtree = mirror.signSubtree({
      origin: log.name,
      start: 256,
      end: 300,
      proof: consistencyProof(entries, 256, 300),
      checkpoint: mirror.checkpoint(log.name),
    });
    assert(equal(subtree.root, treeHash(entries.slice(256))));
    const forged = [...entries];
    forged[0] = Buffer.from('fork');
    const bad = t.signedCheckpoint({ origin: log.name, entries: forged, signer: log });
    assert.throws(() => w.addCheckpoint(t.witnessRequest(300, [], bad)), /HASH/);
  } finally {
    journal.close();
  }
});
test('RRA ML-DSA-87 C2SP transport extension has a distinct key identifier and signature', () => {
  const signer = {
      ...generate('ml-dsa-87'),
      name: 'mirror.example/rra87',
      scheme: 'CERTCONCORD-MLDSA87-SUBTREE-v1',
    },
    body = t.checkpointBody('log.example/test', 1, random()),
    note = body + '\n' + t.noteSignature(body, signer);
  assert.equal(t.verifyNote(note, signer).size, 1n);
  assert.throws(() => t.verifyNote(note, { ...signer, name: 'mirror.example/other' }), /SIGNATURE/);
});
