import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { generate, sha256 } from './core.mjs';
import { Journal } from './state.mjs';
import { consistencyProof, treeHash } from './mtc.mjs';
import * as tlog from './transparency.mjs';

async function fixture(
  t,
  kind,
  { keyType = 'ml-dsa-87', scheme = 'CERTCONCORD-MLDSA87-SUBTREE-v1' } = {},
) {
  const directory = mkdtempSync(join(tmpdir(), 'certconcord witness http '));
  const file = join(directory, 'state.sqlite');
  const log = { ...generate('ed25519'), name: 'log.example/http', scheme: 'ed25519-log' };
  const signer = {
    ...generateKeyPairSync(keyType),
    name: 'witness.example/http',
    scheme,
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
    async reopen({ signer: nextSigner } = {}) {
      await stop();
      if (nextSigner) Object.assign(signer, nextSigner);
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

for (const failure of [
  {
    name: 'unknown origin',
    origin: 'unknown.example/upload',
    status: 404,
    code: 'MIRROR_UNKNOWN_LOG',
  },
  { name: 'missing pending checkpoint', status: 422, code: 'MIRROR_NO_CHECKPOINT' },
]) {
  test(
    'mirror HTTP upload rejects ' + failure.name + ' without state changes across restart',
    async (t) => {
      const f = await fixture(t, 'mirror');
      const request = tlog.mirrorUpload(failure.origin ?? f.log.name, []);
      const snapshot = () =>
        f.journal.db.prepare('SELECT * FROM state ORDER BY namespace, id').all();
      const before = snapshot();
      for (let attempt = 0; attempt < 2; attempt++) {
        assert.deepEqual(await f.post(request, '/add-entries'), {
          status: failure.status,
          type: 'text/plain',
          body: failure.code,
        });
        assert.deepEqual(snapshot(), before);
        await f.reopen();
        assert.deepEqual(snapshot(), before);
      }
      const entries = [Buffer.from('valid upload after rejection')];
      const note = f.checkpoint(entries);
      assert.equal((await f.post(tlog.witnessRequest(0, [], note))).status, 200);
      const uploaded = await f.post(tlog.mirrorUpload(f.log.name, entries), '/add-entries');
      assert.equal(uploaded.status, 200);
      assert.deepEqual(tlog.verifyNote(note + uploaded.body, f.signer).root, treeHash(entries));
      await f.reopen();
      await f.published(entries);
    },
  );
}

test('mirror HTTP upload keeps malformed headers at 400 before checkpoint lookup', async (t) => {
  const f = await fixture(t, 'mirror');
  for (const [request, code] of [
    [Buffer.from([4, 97]), 'MIRROR_TRUNCATED'],
    [tlog.mirrorUpload(f.log.name, [], 1), 'MIRROR_HEADER'],
  ]) {
    assert.deepEqual(await f.post(request, '/add-entries'), {
      status: 400,
      type: 'text/plain',
      body: code,
    });
    assert.deepEqual(f.journal.db.prepare('SELECT * FROM state').all(), []);
  }
});

function additionalSignatures(f, note) {
  const body = tlog.parseCheckpoint(note).body;
  const rotated = { ...generate('ed25519'), name: f.signer.name, scheme: 'ed25519-cosign' };
  const other = {
    ...generate('ed25519'),
    name: 'other.example/cosigner',
    scheme: 'ed25519-cosign',
  };
  return note + tlog.noteSignature(body, rotated) + tlog.noteSignature(body, other);
}

function assertMergedCheckpoint(note, original, signer, log) {
  const cp = tlog.verifyNote(note, signer);
  tlog.verifyPublishedCheckpoint(note, log);
  const expected = tlog.parseCheckpoint(original);
  assert.equal(cp.body, expected.body);
  const id = tlog.noteKeyID(signer.name, signer.publicKey, signer.scheme);
  const selected = (s) => s.name === signer.name && s.keyID.equals(id);
  assert.equal(cp.signatures.filter(selected).length, 1);
  assert.deepEqual(
    cp.signatures.filter((s) => !selected(s)),
    expected.signatures.filter((s) => !selected(s)),
  );
}

async function publishedNote(f) {
  const response = await fetch(
    f.base + '/' + sha256(Buffer.from(f.log.name)).toString('hex') + '/checkpoint',
  );
  assert.equal(response.status, 200, await response.clone().text());
  return response.text();
}

for (const algorithm of [
  { keyType: 'ed25519', scheme: 'ed25519-cosign' },
  { keyType: 'ml-dsa-44', scheme: 'mldsa44-cosign' },
  { keyType: 'ml-dsa-87', scheme: 'CERTCONCORD-MLDSA87-SUBTREE-v1' },
]) {
  test(
    algorithm.keyType + ' witness publication merges its repeated cosignature across restart',
    async (t) => {
      const f = await fixture(t, 'witness', algorithm);
      const entries = [Buffer.from('cosigned publication')];
      const original = additionalSignatures(f, f.checkpoint(entries));
      assert.equal((await f.post(tlog.witnessRequest(0, [], original))).status, 200);
      const first = await publishedNote(f);
      assertMergedCheckpoint(first, original, f.signer, f.log);
      const repeated = await f.post(tlog.witnessRequest(1, [], first));
      assert.equal(repeated.status, 200);
      assert.equal(tlog.verifyNote(original + repeated.body, f.signer).size, 1n);
      const last = await publishedNote(f);
      assertMergedCheckpoint(last, first, f.signer, f.log);
      await f.reopen();
      assert.equal(await publishedNote(f), last);
      const before = f.snapshot();
      assert.deepEqual(await f.post(tlog.witnessRequest(1, [], first + repeated.body)), {
        status: 400,
        type: 'text/plain',
        body: 'CHECKPOINT_DUPLICATE_SIGNATURE',
      });
      assert.deepEqual(f.snapshot(), before);
      assert.equal(await publishedNote(f), last);
    },
  );

  test(
    algorithm.keyType +
      ' witness publication retains its issued signature after key rotation and reopen',
    async (t) => {
      const f = await fixture(t, 'witness', algorithm);
      const original = additionalSignatures(f, f.checkpoint([Buffer.from('retained issuer')]));
      const oldSigner = { ...f.signer };
      assert.equal((await f.post(tlog.witnessRequest(0, [], original))).status, 200);
      const first = await publishedNote(f);
      assert.equal((await f.post(tlog.witnessRequest(1, [], first))).status, 200);
      const issued = await publishedNote(f);
      const retained = f.snapshot();
      await f.reopen({ signer: { ...generateKeyPairSync(algorithm.keyType) } });
      assert.deepEqual(f.snapshot(), retained);
      assert.equal(await publishedNote(f), issued);
      assertMergedCheckpoint(issued, original, oldSigner, f.log);
      assert.throws(() => tlog.verifyNote(issued, f.signer), { code: 'NOTE_UNTRUSTED_SIGNATURE' });
      assert.deepEqual(f.snapshot(), retained);
      const signed = await f.post(tlog.witnessRequest(1, [], issued));
      assert.equal(signed.status, 200);
      const rotated = await publishedNote(f);
      assertMergedCheckpoint(rotated, issued, f.signer, f.log);
      tlog.verifyNote(rotated, oldSigner);
      await f.reopen();
      assert.equal(await publishedNote(f), rotated);
    },
  );

  test(
    algorithm.keyType + ' witness client merges a successful cosigned checkpoint retry',
    async (t) => {
      const f = await fixture(t, 'witness', algorithm);
      const original = additionalSignatures(f, f.checkpoint([Buffer.from('client replay')]));
      const submit = (note, old) =>
        tlog.submitWitness(f.base, tlog.witnessRequest(old, [], note), {
          signer: f.signer,
          checkpoint: note,
          allowLoopback: true,
        });
      const first = await submit(original, 0);
      assert.equal(first.status, 'SIGNED');
      const next = await submit(first.checkpoint, 1);
      assert.equal(next.status, 'SIGNED');
      assertMergedCheckpoint(next.checkpoint, first.checkpoint, f.signer, f.log);
      assert.equal(await publishedNote(f), next.checkpoint);
    },
  );

  test(
    algorithm.keyType + ' mirror publication merges an already cosigned initial checkpoint',
    async (t) => {
      const f = await fixture(t, 'mirror', algorithm);
      const entries = [Buffer.from('mirrored cosigned checkpoint')];
      const original = additionalSignatures(f, f.checkpoint(entries));
      const donorJournal = new Journal();
      let donorNote;
      try {
        const donor = new tlog.TlogMirror({
          journal: donorJournal,
          signer: f.signer,
          logs: new Map([[f.log.name, f.log]]),
        });
        assert.equal(donor.addCheckpoint(tlog.witnessRequest(0, [], original)).status, 200);
        assert.equal(donor.addEntries(tlog.mirrorUpload(f.log.name, entries)).status, 200);
        donorNote = donor.checkpoint(f.log.name);
      } finally {
        donorJournal.close();
      }
      assertMergedCheckpoint(donorNote, original, f.signer, f.log);
      assert.equal((await f.post(tlog.witnessRequest(0, [], donorNote))).status, 200);
      for (let attempt = 0; attempt < 2; attempt++) {
        const uploaded = await f.post(tlog.mirrorUpload(f.log.name, entries), '/add-entries');
        assert.equal(uploaded.status, 200);
        assert.equal(tlog.verifyNote(original + uploaded.body, f.signer).size, 1n);
        const published = await publishedNote(f);
        assertMergedCheckpoint(published, donorNote, f.signer, f.log);
        await f.reopen();
        assert.equal(await publishedNote(f), published);
      }
    },
  );
}

for (const responseCase of [
  { name: 'empty response with retained trusted signature', body: () => '', accepted: true },
  {
    name: 'unknown response with retained trusted signature',
    body: (f) => f.unknown,
    accepted: true,
  },
  {
    name: 'invalid selected replacement',
    body: (f) => forgedSignature(f.selected),
    code: 'NOTE_UNTRUSTED_SIGNATURE',
  },
  {
    name: 'duplicate selected response',
    body: (f) => f.selected + f.selected,
    code: 'CHECKPOINT_DUPLICATE_SIGNATURE',
  },
  {
    name: 'attempted log signature replacement',
    body: (f) => forgedSignature(f.logLine) + f.selected,
    code: 'CHECKPOINT_DUPLICATE_SIGNATURE',
  },
  { name: 'malformed response signature', body: () => 'malformed\n', code: 'CHECKPOINT_SIGNATURE' },
  {
    name: 'duplicate original signature',
    body: (f) => f.selected,
    duplicateOriginal: true,
    code: 'CHECKPOINT_DUPLICATE_SIGNATURE',
  },
]) {
  test('witness client signature merge handles ' + responseCase.name, async (t) => {
    const log = { ...generate('ed25519'), name: 'log.example/merge', scheme: 'ed25519-log' };
    const signer = { ...generate('ed25519'), name: log.name, scheme: 'ed25519-cosign' };
    const unknown = { ...generate('ed25519'), name: signer.name, scheme: signer.scheme };
    const body = tlog.checkpointBody(log.name, 0, treeHash([]));
    const f = {
      logLine: tlog.noteSignature(body, log),
      selected: tlog.noteSignature(body, signer),
      unknown: tlog.noteSignature(body, unknown),
    };
    const checkpoint =
      body + '\n' + f.logLine + f.selected + (responseCase.duplicateOriginal ? f.selected : '');
    const server = createServer((req, res) => {
      req.resume();
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(responseCase.body(f));
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise((resolve) => server.close(resolve)));
    const result = tlog.submitWitness(
      'http://127.0.0.1:' + server.address().port,
      tlog.witnessRequest(0, [], checkpoint),
      { signer, checkpoint, allowLoopback: true },
    );
    if (!responseCase.accepted) await assert.rejects(result, { code: responseCase.code });
    else {
      const signed = await result;
      assert.equal(signed.status, 'SIGNED');
      assert.equal(tlog.verifyNote(signed.checkpoint, signer).size, 0n);
      tlog.verifyPublishedCheckpoint(signed.checkpoint, log);
      assert(signed.checkpoint.startsWith(checkpoint));
    }
  });
}

for (const storedCase of [
  { name: 'log signature identity', code: 'WITNESS_STORED_SIGNATURE', lines: (logLine) => logLine },
  {
    name: 'multiple issued identities',
    code: 'WITNESS_STORED_SIGNATURE',
    lines: (logLine, selected, other) => selected + other,
  },
  {
    name: 'duplicate issued identity',
    code: 'CHECKPOINT_DUPLICATE_SIGNATURE',
    lines: (logLine, selected) => selected + selected,
  },
]) {
  test('witness publication rejects retained ' + storedCase.name + ' across reopen', async (t) => {
    const f = await fixture(t, 'witness');
    const note = f.checkpoint([]);
    const body = tlog.parseCheckpoint(note).body;
    const selected = tlog.noteSignature(body, f.signer);
    const other = tlog.noteSignature(body, {
      ...generate('ed25519'),
      name: 'other.example/stored',
      scheme: 'ed25519-cosign',
    });
    f.journal.put('witness', f.log.name, {
      size: 0n,
      root: treeHash([]),
      note,
      cosignature: storedCase.lines(tlog.noteSignature(body, f.log), selected, other),
    });
    const before = f.snapshot();
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = await fetch(
        f.base + '/' + sha256(Buffer.from(f.log.name)).toString('hex') + '/checkpoint',
      );
      assert.equal(result.status, 400);
      assert.equal(await result.text(), storedCase.code);
      assert.deepEqual(f.snapshot(), before);
      await f.reopen();
    }
  });
}

test('witness publication retains an empty issued response across reopen', async (t) => {
  const f = await fixture(t, 'witness');
  const note = f.checkpoint([]);
  const service = new tlog.TlogWitness({
    journal: f.journal,
    signer: f.signer,
    logs: new Map([[f.log.name, f.log]]),
  });
  assert.equal(service.addCheckpoint(tlog.witnessRequest(0, [], note), { sign: false }).body, '');
  const before = f.snapshot();
  assert.equal(await publishedNote(f), note);
  await f.reopen({ signer: { ...generateKeyPairSync('ml-dsa-87') } });
  assert.equal(await publishedNote(f), note);
  assert.deepEqual(f.snapshot(), before);
});
