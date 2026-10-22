import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { generate, sha256 } from './core.mjs';
import { Journal } from './state.mjs';
import { consistencyProof, treeHash } from './mtc.mjs';
import * as tlog from './transparency.mjs';

async function fixture(t, kind) {
  const directory = mkdtempSync(join(tmpdir(), 'certconcord witness http '));
  const file = join(directory, 'state.sqlite');
  const log = { ...generate('ed25519'), name: 'log.example/http', scheme: 'ed25519-log' };
  const signer = {
    ...generate('ml-dsa-87'),
    name: 'witness.example/http',
    scheme: 'CERTCONCORD-MLDSA87-SUBTREE-v1',
  };
  const logs = new Map([[log.name, log]]);
  let journal = new Journal(file),
    server;
  const start = async () => {
    const service =
      kind === 'witness'
        ? new tlog.TlogWitness({ journal, signer, logs })
        : new tlog.TlogMirror({ journal, signer, logs });
    server = createServer(tlog.createTransparencyHandler(service));
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  };
  const stop = async () => {
    if (server?.listening)
      await new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    journal.close();
  };
  t.after(async () => {
    await stop();
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    assert(basename(directory).startsWith('certconcord witness http '));
    rmSync(directory, { recursive: true, force: true });
  });
  await start();
  return {
    log,
    signer,
    get journal() {
      return journal;
    },
    get base() {
      return 'http://127.0.0.1:' + server.address().port;
    },
    async post(body, path = '/add-checkpoint') {
      const response = await fetch(this.base + path, { method: 'POST', body });
      return {
        status: response.status,
        type: response.headers.get('content-type'),
        body: await response.text(),
      };
    },
    checkpoint(entries) {
      return tlog.signedCheckpoint({ origin: log.name, entries, signer: log });
    },
    async published(entries) {
      const response = await fetch(
        this.base + '/' + sha256(Buffer.from(log.name)).toString('hex') + '/checkpoint',
      );
      assert.equal(response.status, 200);
      const checkpoint = await response.text();
      const verified = tlog.verifyNote(checkpoint, signer);
      tlog.verifyPublishedCheckpoint(checkpoint, log);
      assert.equal(verified.size, BigInt(entries.length));
      assert.deepEqual(verified.root, treeHash(entries));
    },
    snapshot() {
      return ['witness', 'mirror-pending', 'mirror-checkpoint-history', 'mirror-data'].map(
        (namespace) => journal.list(namespace).map(({ id }) => [id, journal.get(namespace, id)]),
      );
    },
    async reopen() {
      await stop();
      journal = new Journal(file);
      await start();
    },
  };
}

function forgedSignature(checkpoint) {
  const start = checkpoint.lastIndexOf(' ') + 1;
  const bytes = Buffer.from(checkpoint.slice(start).trimEnd(), 'base64');
  bytes[bytes.length - 1] ^= 1;
  return checkpoint.slice(0, start) + bytes.toString('base64') + '\n';
}

const rejections = [
  {
    name: 'malformed decimal',
    status: 400,
    code: 'NOTE_DECIMAL',
    request: (f) => 'old 01\n\n' + f.checkpoint([]),
  },
  {
    name: 'unknown origin',
    status: 404,
    code: 'WITNESS_UNKNOWN_LOG',
    request: (f) =>
      tlog.witnessRequest(
        0,
        [],
        tlog.signedCheckpoint({ origin: 'unknown.example/log', entries: [], signer: f.log }),
      ),
  },
  {
    name: 'missing trusted log signature',
    status: 403,
    code: 'CHECKPOINT_LOG_SIGNATURE_REQUIRED',
    request: (f) => {
      const body = tlog.checkpointBody(f.log.name, 0, treeHash([]));
      return tlog.witnessRequest(0, [], body + '\n' + tlog.noteSignature(body, f.signer));
    },
  },
  {
    name: 'invalid trusted log signature',
    status: 403,
    code: 'NOTE_UNTRUSTED_SIGNATURE',
    request: (f) => tlog.witnessRequest(0, [], forgedSignature(f.checkpoint([]))),
  },
  {
    name: 'nonempty zero-old proof',
    status: 422,
    code: 'WITNESS_ZERO_PROOF',
    request: (f) => tlog.witnessRequest(0, [Buffer.alloc(32)], f.checkpoint([Buffer.from('one')])),
  },
  {
    name: 'noncanonical empty root',
    status: 422,
    code: 'WITNESS_EMPTY_ROOT',
    request: (f) => {
      const body = tlog.checkpointBody(f.log.name, 0, Buffer.alloc(32, 9));
      return tlog.witnessRequest(0, [], body + '\n' + tlog.noteSignature(body, f.log));
    },
  },
  {
    name: 'reversed size range before stored-size conflict',
    status: 400,
    code: 'WITNESS_ROLLBACK',
    request: (f) => tlog.witnessRequest(2, [], f.checkpoint([Buffer.from('one')])),
  },
  {
    name: 'malformed proof hash',
    status: 400,
    code: 'WITNESS_PROOF',
    request: (f) => 'old 0\nAA==\n\n' + f.checkpoint([]),
  },
];

for (const kind of ['witness', 'mirror']) {
  for (const example of rejections) {
    test(
      kind + ' HTTP classifies ' + example.name + ' and permits a canonical retry after reopen',
      async (t) => {
        const f = await fixture(t, kind);
        const before = f.snapshot();
        assert.deepEqual(await f.post(example.request(f)), {
          status: example.status,
          type: 'text/plain',
          body: example.code,
        });
        assert.deepEqual(f.snapshot(), before);
        await f.reopen();
        assert.deepEqual(f.snapshot(), before);
        const canonical = f.checkpoint([]);
        const result = await f.post(tlog.witnessRequest(0, [], canonical));
        assert.equal(result.status, 200);
        if (kind === 'mirror') {
          assert.equal(result.body, '');
          assert.equal(
            (await f.post(tlog.mirrorUpload(f.log.name, []), '/add-entries')).status,
            200,
          );
        } else assert.equal(tlog.verifyNote(canonical + result.body, f.signer).size, 0n);
        await f.published([]);
      },
    );
  }

  test(
    kind + ' HTTP preserves conflicts and rejects forks before valid growth and restart',
    async (t) => {
      const f = await fixture(t, kind);
      const entries = [Buffer.from('one'), Buffer.from('two')];
      const first = f.checkpoint(entries.slice(0, 1));
      assert.equal((await f.post(tlog.witnessRequest(0, [], first))).status, 200);
      const before = f.snapshot();
      assert.deepEqual(await f.post(tlog.witnessRequest(0, [], first)), {
        status: 409,
        type: 'text/x.tlog.size',
        body: '1\n',
      });
      assert.deepEqual(await f.post(tlog.witnessRequest(1, [], f.checkpoint([]))), {
        status: 400,
        type: 'text/plain',
        body: 'WITNESS_ROLLBACK',
      });
      assert.deepEqual(
        await f.post(tlog.witnessRequest(1, [], f.checkpoint([Buffer.from('fork')]))),
        {
          status: 422,
          type: 'text/plain',
          body: 'CONSISTENCY_HASH',
        },
      );
      const last = f.checkpoint(entries);
      assert.deepEqual(await f.post(tlog.witnessRequest(1, [Buffer.alloc(32)], last)), {
        status: 422,
        type: 'text/plain',
        body: 'CONSISTENCY_HASH',
      });
      assert.deepEqual(f.snapshot(), before);
      await f.reopen();
      assert.deepEqual(f.snapshot(), before);
      const result = await f.post(tlog.witnessRequest(1, consistencyProof(entries, 0, 1), last));
      assert.equal(result.status, 200);
      if (kind === 'mirror')
        assert.equal(
          (await f.post(tlog.mirrorUpload(f.log.name, entries), '/add-entries')).status,
          200,
        );
      else assert.equal(tlog.verifyNote(last + result.body, f.signer).size, 2n);
      await f.reopen();
      await f.published(entries);
    },
  );
}

for (const size of [0x8000000000000000n, 0xffffffffffffffffn]) {
  test(
    'witness HTTP client recovers an exact declared uint64 conflict of size ' + size,
    async (t) => {
      const f = await fixture(t, 'witness');
      // This is a transport boundary declaration, not a materialized large log.
      const body = tlog.checkpointBody(f.log.name, size, Buffer.alloc(32, 8));
      const checkpoint = body + '\n' + tlog.noteSignature(body, f.log);
      const request = tlog.witnessRequest(0, [], checkpoint);
      assert.equal((await f.post(request)).status, 200);
      await f.reopen();
      const before = f.snapshot();
      const options = { signer: f.signer, checkpoint, allowLoopback: true };
      const conflict = await tlog.submitWitness(f.base, request, options);
      assert.deepEqual(conflict, { status: 'CONFLICT', size });
      assert.deepEqual(f.snapshot(), before);
      const retried = await tlog.submitWitness(
        f.base,
        tlog.witnessRequest(conflict.size, [], checkpoint),
        options,
      );
      assert.equal(retried.status, 'SIGNED');
      const verified = tlog.verifyNote(retried.checkpoint, f.signer);
      tlog.verifyPublishedCheckpoint(retried.checkpoint, f.log);
      assert.equal(verified.size, size);
      assert.deepEqual(verified.root, Buffer.alloc(32, 8));
    },
  );
}

test('witness HTTP retains a legacy empty-root conflict across restart before valid growth', async (t) => {
  const f = await fixture(t, 'witness');
  const root = Buffer.alloc(32, 9);
  const body = tlog.checkpointBody(f.log.name, 0, root);
  const note = body + '\n' + tlog.noteSignature(body, f.log);
  const cosignature = tlog.noteSignature(body, f.signer);
  f.journal.put('witness', f.log.name, { size: 0n, root, note, cosignature });
  const before = f.snapshot();
  const canonical = f.checkpoint([]);
  for (let attempt = 0; attempt < 2; attempt++) {
    assert.deepEqual(await f.post(tlog.witnessRequest(0, [], canonical)), {
      status: 422,
      type: 'text/plain',
      body: 'CONSISTENCY_HASH',
    });
    assert.deepEqual(f.snapshot(), before);
    await f.reopen();
    assert.deepEqual(f.snapshot(), before);
  }
  const entries = [Buffer.from('first leaf')];
  const next = f.checkpoint(entries);
  const grown = await f.post(tlog.witnessRequest(0, [], next));
  assert.equal(grown.status, 200);
  assert.deepEqual(tlog.verifyNote(next + grown.body, f.signer).root, treeHash(entries));
  await f.reopen();
  await f.published(entries);
});
