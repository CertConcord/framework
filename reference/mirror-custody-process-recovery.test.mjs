import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generate } from './core.mjs';
import { consistencyProof, treeHash } from './mtc.mjs';
import * as tlog from './transparency.mjs';

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'certconcord mirror process '));
  t.after(() => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    assert(basename(directory).startsWith('certconcord mirror process '));
    rmSync(directory, { recursive: true, force: true });
  });
  const log = { ...generate('ed25519'), name: 'log.example/process', scheme: 'ed25519-log' };
  const signer = {
    ...generate('ml-dsa-87'),
    name: 'mirror.example/process',
    scheme: 'CERTCONCORD-MLDSA87-SUBTREE-v1',
  };
  const input = {
    path: join(directory, 'mirror.sqlite'),
    log: {
      name: log.name,
      scheme: log.scheme,
      publicKey: log.publicKey.export({ type: 'spki', format: 'pem' }),
    },
    signer: {
      name: signer.name,
      scheme: signer.scheme,
      privateKey: signer.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    },
  };
  const run = (action, values = {}) => {
    const child = spawnSync(
      process.execPath,
      [fileURLToPath(new URL('./mirror-custody-process-child.mjs', import.meta.url))],
      {
        cwd: directory,
        input: JSON.stringify({ ...input, action, ...values }),
        encoding: 'utf8',
        windowsHide: true,
        timeout: 15000,
        maxBuffer: 2 * 1024 * 1024,
      },
    );
    assert.ifError(child.error);
    if (values.fault) {
      assert.deepEqual(JSON.parse(child.stdout.trim()), { reached: values.fault });
      assert(
        child.status !== 0 || child.signal !== null,
        'fault process must terminate abnormally',
      );
      if (process.platform !== 'win32') assert.equal(child.signal, 'SIGKILL');
      return;
    }
    assert.equal(child.status, 0, child.stderr);
    assert.equal(child.signal, null);
    return JSON.parse(child.stdout.trim());
  };
  const checkpoint = (entries) => tlog.signedCheckpoint({ origin: log.name, entries, signer: log });
  const admit = (entries, priorSize = 0, fault) =>
    run('admit', {
      request: tlog.witnessRequest(
        priorSize,
        priorSize ? consistencyProof(entries, 0, priorSize) : [],
        checkpoint(entries),
      ),
      fault,
    });
  const upload = (entries, start = 0, fault) =>
    run('upload', {
      upload: tlog.mirrorUpload(log.name, entries, start).toString('base64'),
      fault,
    });
  const verify = (snapshot, entries) => {
    assert.equal(snapshot.storedSize, entries.length);
    assert.deepEqual(
      snapshot.entries,
      entries.map((entry) => entry.toString('base64')),
    );
    assert.equal(snapshot.storedRoot, treeHash(entries).toString('hex'));
    const receipt = tlog.verifyNote(snapshot.published.value.note, signer);
    assert.equal(receipt.size, BigInt(entries.length));
    assert.deepEqual(receipt.root, treeHash(entries));
    tlog.verifyPublishedCheckpoint(snapshot.published.value.note, log);
  };
  return { log, signer, run, admit, upload, checkpoint, verify };
}

for (const priorSize of [0, 3]) {
  for (const fault of [
    { namespace: 'mirror-pending', when: 'after' },
    { namespace: 'mirror-checkpoint-history', when: 'before' },
    { namespace: 'mirror-checkpoint-history', when: 'after' },
  ]) {
    test(`mirror process death ${fault.when} ${fault.namespace} preserves prior size ${priorSize}`, (t) => {
      const f = fixture(t);
      const entries = Array.from({ length: 4 }, (_, i) => Buffer.from('entry ' + i));
      if (priorSize) {
        assert.equal(f.admit(entries.slice(0, priorSize)).result.status, 200);
        f.verify(f.upload(entries.slice(0, priorSize)).snapshot, entries.slice(0, priorSize));
      }
      const before = f.run('inspect').snapshot;
      f.admit(entries, priorSize, fault);
      assert.deepEqual(f.run('inspect').snapshot, before);
      assert.equal(f.admit(entries, priorSize).result.status, 200);
      assert.equal(f.upload(entries, priorSize).result.status, 200);
      f.verify(f.run('inspect').snapshot, entries);
    });
  }
}

for (const when of ['before', 'after']) {
  test(`mirror process death ${when} receipt persistence rolls back new entries and preserves the prior receipt`, (t) => {
    const f = fixture(t);
    const entries = Array.from({ length: 300 }, (_, i) => Buffer.from('entry ' + i));
    const prefix = entries.slice(0, 256);
    assert.equal(f.admit(prefix).result.status, 200);
    f.verify(f.upload(prefix).snapshot, prefix);
    assert.equal(f.admit(entries, 256).result.status, 200);
    const before = f.run('inspect').snapshot;
    f.upload(entries, 256, { namespace: 'mirror-data', when });
    assert.deepEqual(f.run('inspect').snapshot, before);
    f.verify(before, prefix);
    assert.equal(f.upload(entries, 256).result.status, 200);
    f.verify(f.run('inspect').snapshot, entries);
  });
}

test('a four-entry mirror header carrying only three leaves remains uncommitted after restart', (t) => {
  const f = fixture(t);
  const entries = [Buffer.from('one'), Buffer.from('two'), Buffer.from('three')];
  const body = tlog.checkpointBody(f.log.name, 4, treeHash(entries));
  const request = tlog.witnessRequest(0, [], body + '\n' + tlog.noteSignature(body, f.log));
  assert.equal(f.run('admit', { request }).result.status, 200);
  const before = f.run('inspect').snapshot;
  const upload = tlog.mirrorUpload(f.log.name, entries);
  upload.writeBigUInt64BE(4n, 1 + Buffer.byteLength(f.log.name) + 8);
  assert.deepEqual(f.run('upload', { upload: upload.toString('base64') }).result, {
    error: 'MIRROR_TRUNCATED',
  });
  assert.deepEqual(f.run('inspect').snapshot, before);
  assert.equal(before.storedSize, 0);
  assert.equal(before.published, null);
  const control = fixture(t);
  const complete = [...entries, Buffer.from('four')];
  assert.equal(control.admit(complete).result.status, 200);
  assert.equal(control.upload(complete).result.status, 200);
  control.verify(control.run('inspect').snapshot, complete);
});

test('a truncated second mirror bundle retains only its verified prefix across restart and resumes once valid', (t) => {
  const f = fixture(t);
  const entries = Array.from({ length: 300 }, (_, i) => Buffer.from('entry ' + i));
  assert.equal(f.admit(entries).result.status, 200);
  const complete = tlog.mirrorUpload(f.log.name, entries);
  const partial = f.run('upload', { upload: complete.subarray(0, -17).toString('base64') });
  assert.deepEqual(partial.result, {
    status: 202,
    type: 'text/x.tlog.mirror-info',
    body: '300\n256\n\n',
  });
  const retained = f.run('inspect').snapshot;
  assert.equal(retained.storedSize, 256);
  assert.deepEqual(
    retained.entries,
    entries.slice(0, 256).map((entry) => entry.toString('base64')),
  );
  assert.equal(retained.storedRoot, treeHash(entries.slice(0, 256)).toString('hex'));
  assert.equal(retained.published, null);
  const malformed = tlog.mirrorUpload(f.log.name, entries, 256);
  malformed[malformed.length - 1] ^= 1;
  assert.deepEqual(f.run('upload', { upload: malformed.toString('base64') }).result, {
    error: 'CONSISTENCY_HASH',
  });
  assert.deepEqual(f.run('inspect').snapshot, retained);
  assert.equal(f.upload(entries, 256).result.status, 200);
  f.verify(f.run('inspect').snapshot, entries);
});

test('an invalid empty checkpoint never acquires a durable mirror receipt across restart', (t) => {
  const f = fixture(t);
  const body = tlog.checkpointBody(f.log.name, 0, Buffer.alloc(32, 9));
  const request = tlog.witnessRequest(0, [], body + '\n' + tlog.noteSignature(body, f.log));
  const before = f.run('inspect').snapshot;
  assert.deepEqual(f.run('admit', { request }).result, { error: 'WITNESS_EMPTY_ROOT' });
  assert.deepEqual(f.run('inspect').snapshot, before);
  assert.deepEqual(f.upload([]).result, { error: 'MIRROR_NO_CHECKPOINT' });
  assert.deepEqual(f.run('inspect').snapshot, before);
  assert.equal(before.pending, null);
  assert.deepEqual(before.history, []);
  assert.equal(before.storedSize, 0);
  assert.equal(before.published, null);
  assert.equal(f.admit([]).result.status, 200);
  assert.equal(f.upload([]).result.status, 200);
  f.verify(f.run('inspect').snapshot, []);
});
