import test from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import * as c from './core.mjs';
import { issueCertificate, name, OID } from './pki.mjs';
import { Journal } from './state.mjs';
import { createERS, renewERS, verifyERS } from './archive.mjs';
import { ArchivePublicationStore } from './retained-authorities.mjs';
import { TimestampAuthority, timestampRequest, tokenFromResponse } from './timestamp.mjs';
import { readBody } from './transport.mjs';

function waitFor(worker, event) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timer);
      worker.events.off(event, received);
      worker.child.off('error', failed);
      worker.child.off('exit', exited);
    };
    const received = (value) => {
      cleanup();
      resolve(value);
    };
    const failed = (error) => {
      cleanup();
      reject(error);
    };
    const exited = () => failed(new Error('Child exited before ' + event + ': ' + worker.stderr));
    const timer = setTimeout(
      () => failed(new Error('Child did not reach ' + event + ': ' + worker.stderr)),
      15000,
    );
    worker.events.once(event, received);
    worker.child.once('error', failed);
    worker.child.once('exit', exited);
  });
}

async function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'certconcord renewal process '));
  const workers = [],
    requests = [],
    errors = [];
  const tsaJournal = new Journal();
  const journalPath = join(directory, 'renewal.sqlite');
  let server;
  t.after(async () => {
    for (const worker of workers) {
      if (worker.child.exitCode === null && worker.child.signalCode === null)
        worker.child.kill('SIGKILL');
      await worker.closed;
    }
    if (server) {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
    tsaJournal.close();
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    assert(basename(directory).startsWith('certconcord renewal process '));
    rmSync(directory, { recursive: true, force: true });
    assert.deepEqual(errors, []);
  });
  const start = 1800000000,
    root = c.generate(),
    tsaKey = c.generate(),
    custodian = c.generate();
  const trustDomainID = c.random(),
    data = Buffer.from('A document retained across archive coordinator process death');
  const certificate = issueCertificate(
    {
      publicKey: tsaKey.publicKey,
      issuer: name('Synthetic Archive Root'),
      subject: name('Synthetic Archive TSA'),
      serial: 1,
      profileID: 'CERTCONCORD-TSA-v1',
      notBefore: start - 100,
      notAfter: start + 1000,
    },
    root.privateKey,
  );
  let tsaTime = start;
  const timestampTrust = { certificate, policy: '1.3.6.1.4.1.32473.99.21' };
  const tsa = new TimestampAuthority({
    ...timestampTrust,
    privateKey: tsaKey.privateKey,
    journal: tsaJournal,
    accuracySeconds: 0,
    clock: () => tsaTime,
  });
  const initialToken = tokenFromResponse(
    tsa.issue(timestampRequest(c.sha512(data), { policy: tsa.policy }).der),
  );
  const initialRecord = await createERS(data, { tsa: async () => initialToken });
  const initialHistory = [{ serial: 0, custodianKeyID: c.keyID(custodian.publicKey) }];
  const seed = new Journal(journalPath);
  let initial;
  try {
    const store = new ArchivePublicationStore(seed, {
      validatePublication: (publication) => ({
        overall: verifyERS(publication.evidenceRecord, data, {
          ...timestampTrust,
          issuerKey: root.publicKey,
          at: start,
        }).integrity,
      }),
    });
    initial = store.publish({
      archiveID: 'document',
      previousHash: null,
      dataHash: c.sha512(data),
      evidenceRecord: initialRecord,
      history: initialHistory,
    });
  } finally {
    seed.close();
  }
  const request = {
    operationID: c.random(),
    archiveID: 'document',
    previousHash: initial.digest,
    timestampRequest: timestampRequest(c.sha512(initialToken), { policy: tsa.policy }).der,
    protectionDeadline: start + 100,
  };
  let retainedToken;
  tsaTime = start + 10;
  server = createServer(async (incoming, response) => {
    try {
      const body = await readBody(incoming, { maxBytes: 4096 });
      assert.equal(incoming.headers['content-type'], 'application/timestamp-query');
      requests.push({ method: incoming.method, url: incoming.url, body });
      assert.deepEqual(requests, [{ method: 'POST', url: '/', body: request.timestampRequest }]);
      const issued = tsa.issue(body);
      retainedToken = tokenFromResponse(issued);
      response.writeHead(200, { 'content-type': 'application/timestamp-reply' });
      response.end(issued);
    } catch (error) {
      errors.push(error.message);
      response.writeHead(500);
      response.end();
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const authority = (key, role) => ({
    mode: 'RAW_KEY',
    publicKeyDER: c.spki(key.publicKey),
    knownAt: start - 10,
    validFrom: start - 10,
    validUntil: start + 1000,
    roles: [role],
    scopes: [{ trustDomainID }],
    status: {
      scope: 'AUTHORITY',
      authorityID: c.keyID(key.publicKey),
      trustDomainID,
      status: 'GOOD',
      publishedAt: start - 10,
      nextUpdate: start + 1000,
    },
  });
  const history = [...initialHistory, { serial: 1, custodianKeyID: c.keyID(custodian.publicKey) }];
  const configuration = {
    journalPath,
    request,
    initial,
    data,
    history,
    timestampTrust,
    trustDomainID,
    issuerKeyDER: c.spki(root.publicKey),
    custodianKeyDER: c.spki(custodian.publicKey),
    authorities: [
      authority(tsaKey, 'TIMESTAMP_AUTHORITY'),
      authority(custodian, 'ARCHIVE_CUSTODIAN'),
    ],
    url: 'http://127.0.0.1:' + server.address().port + '/',
  };
  async function startWorker(mode, at) {
    const child = fork(new URL('./archive-renewal-process-child.mjs', import.meta.url), [], {
      cwd: directory,
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      serialization: 'advanced',
      execArgv: [],
      windowsHide: true,
    });
    const worker = { child, events: new EventEmitter(), stderr: '' };
    worker.closed = new Promise((resolve) =>
      child.once('close', (code, signal) => resolve({ code, signal })),
    );
    workers.push(worker);
    let output = '';
    child.stdout.on('data', (chunk) => {
      output += chunk;
      if (output.length > 1024 * 1024) {
        worker.stderr += 'Child output exceeded bound';
        child.kill('SIGKILL');
        return;
      }
      while (output.includes('\n')) {
        const end = output.indexOf('\n'),
          line = output.slice(0, end);
        output = output.slice(end + 1);
        try {
          const message = JSON.parse(line);
          worker.events.emit(message.event, c.decodeCBOR(c.unb64u(message.value)));
        } catch (error) {
          worker.stderr += error.message;
          child.kill('SIGKILL');
        }
      }
    });
    child.stderr.on('data', (chunk) => {
      worker.stderr += chunk;
      if (worker.stderr.length > 65536) child.kill('SIGKILL');
    });
    const ready = waitFor(worker, 'ready');
    child.send({ ...configuration, mode, at });
    assert.equal((await ready).pid, child.pid);
    assert.notEqual(child.pid, process.pid);
    worker.call = async (action, token) => {
      const answer = waitFor(worker, 'result');
      child.send({ action, token });
      return answer;
    };
    return worker;
  }
  const disk = () => {
    const journal = new Journal(journalPath);
    try {
      return {
        operation: journal.result('archive-renewal:' + c.b64u(request.operationID)),
        publication: journal.get('archive-publication', request.archiveID),
      };
    } finally {
      journal.close();
    }
  };
  return {
    start,
    request,
    initial,
    initialToken,
    history,
    data,
    requests,
    startWorker,
    disk,
    replaceRequest: (value) => {
      const journal = new Journal(journalPath), id = 'archive-renewal:' + c.b64u(request.operationID);
      try {
        const saved = journal.get('archive-renewal-request', id);
        assert(saved);
        journal.put('archive-renewal-request', id, value, saved.revision);
        return journal.get('archive-renewal-request', id);
      } finally { journal.close(); }
    },
    token: () => retainedToken,
    expected: async () => ({
      publication: {
        archiveID: request.archiveID,
        previousHash: initial.digest,
        dataHash: c.sha512(data),
        history,
        evidenceRecord: await renewERS(initialRecord, data, {
          tsa: async (imprint, hashOID) => {
            assert.deepEqual(imprint, c.sha512(initialToken));
            assert.equal(hashOID, OID.sha512);
            return retainedToken;
          },
        }),
      },
    }),
  };
}

async function killAt(t, mode, recoveryMode = 'normal') {
  const f = await fixture(t),
    worker = await f.startWorker(mode, f.start + 10);
  const paused = waitFor(worker, 'paused');
  worker.child.send({ action: 'renew' });
  const checkpoint = await paused;
  assert.equal(checkpoint.stage, mode);
  assert.equal(checkpoint.pid, worker.child.pid);
  assert.equal(f.requests.length, 1);
  const beforeKill = f.disk();
  assert.equal(worker.child.kill('SIGKILL'), true);
  const exit = await worker.closed;
  if (process.platform === 'win32' && exit.signal === null)
    assert(Number.isInteger(exit.code) && exit.code !== 0);
  else assert.equal(exit.signal, 'SIGKILL', worker.stderr);
  const restarted = await f.startWorker(recoveryMode, f.start + 200);
  assert.notEqual(restarted.child.pid, worker.child.pid);
  t.diagnostic(
    JSON.stringify({
      stage: mode,
      terminatedPID: worker.child.pid,
      restartedPID: restarted.child.pid,
      exit,
      transactionDepth: checkpoint.depth,
      checkpointRevision: checkpoint.revision,
      visibleRevision: beforeKill.publication.revision,
      recoveredStatus: f.disk().operation.status,
      timestampRequests: f.requests.length,
    }),
  );
  return { ...f, checkpoint, beforeKill, restarted };
}

for (const [mode, description] of [
  ['after-token', 'after the TSA response'],
  ['before-commit', 'inside the publication transaction'],
]) {
  test(
    'archive renewal process death ' +
      description +
      ' preserves uncertainty until exact-token reconciliation',
    async (t) => {
      const f = await killAt(t, mode);
      assert.equal(f.checkpoint.depth, mode === 'before-commit' ? 2 : 0);
      assert.equal(f.checkpoint.revision, mode === 'before-commit' ? 1 : 0);
      assert.equal(f.checkpoint.operation.status, 'UNKNOWN_EXECUTION');
      assert.equal(f.beforeKill.operation.status, 'UNKNOWN_EXECUTION');
      assert.deepEqual(f.beforeKill.publication, {
        revision: 0,
        value: c.decodeCBOR(c.dcbor(f.initial)),
      });
      assert.deepEqual(f.disk(), f.beforeKill);
      assert.equal((await f.restarted.call('renew')).error.code, 'ARCHIVE_RENEWAL_UNKNOWN');
      assert.equal(f.requests.length, 1);
      assert.equal(
        (await f.restarted.call('reconcile', f.initialToken)).error.code,
        'TSA_REQUEST_BINDING',
      );
      assert.deepEqual(f.disk(), f.beforeKill);
      const expected = (await f.expected()).publication;
      const expectedValue = c.decodeCBOR(
        c.dcbor({ digest: c.sha512(c.dcbor(expected)), publication: expected }),
      );
      assert.deepEqual(
        f.checkpoint.publication,
        mode === 'before-commit' ? expectedValue : c.decodeCBOR(c.dcbor(f.initial)),
      );
      const completed = (await f.restarted.call('reconcile', f.token())).result;
      assert.deepEqual(completed, expectedValue);
      const recovered = await f.startWorker('normal', f.start + 200);
      assert.notEqual(recovered.child.pid, f.restarted.child.pid);
      assert.deepEqual((await recovered.call('renew')).result, completed);
      const final = (await recovered.call('inspect')).result;
      assert.equal(final.operation.status, 'COMPLETED');
      assert.deepEqual(c.decodeCBOR(final.operation.result), completed);
      assert.deepEqual(final.publication, completed);
      assert.equal(final.revision, 1);
      assert.equal(f.requests.length, 1);
    },
  );
}

test('archive renewal process recovery binds restored requests to one publication snapshot', async (t) => {
  const f = await killAt(t, 'after-token', 'changing-publication');
  assert.equal(f.beforeKill.operation.status, 'UNKNOWN_EXECUTION');
  assert.equal(f.beforeKill.publication.revision, 0);
  f.replaceRequest({ ...f.request, protectionDeadline: f.start + 300 });
  assert.equal((await f.restarted.call('reconcile', f.token())).error?.code, 'IDEMPOTENCY_CONFLICT');
  assert.deepEqual(f.disk(), f.beforeKill);
  assert.equal((await f.restarted.call('inspect')).result.publicationReads, 0);
  assert.equal(f.requests.length, 1);
  assert.deepEqual(c.dcbor(f.replaceRequest(f.request).value), c.dcbor(f.request));
  const expected = (await f.expected()).publication;
  const expectedValue = c.decodeCBOR(c.dcbor({ digest: c.sha512(c.dcbor(expected)), publication: expected }));
  const completed = (await f.restarted.call('reconcile', f.token())).result;
  assert.deepEqual(completed, expectedValue);
  const state = (await f.restarted.call('inspect')).result;
  assert.equal(state.publicationReads, 1);
  assert.equal(state.operation.status, 'COMPLETED');
  assert.deepEqual(c.decodeCBOR(state.operation.result), expectedValue);
  assert.deepEqual(state.publication, expectedValue);
  assert.equal(state.revision, 1);
  const reopened = await f.startWorker('normal', f.start + 200);
  assert.notEqual(reopened.child.pid, f.restarted.child.pid);
  assert.deepEqual((await reopened.call('renew')).result, expectedValue);
  const final = (await reopened.call('inspect')).result;
  assert.equal(final.operation.status, 'COMPLETED');
  assert.deepEqual(c.decodeCBOR(final.operation.result), expectedValue);
  assert.deepEqual(final.publication, expectedValue);
  assert.equal(final.revision, 1);
  assert.equal(final.publicationReads, 0);
  assert.equal(f.requests.length, 1);
});

test('archive renewal process death after commit recovers the original publication and result without another TSA request', async (t) => {
  const f = await killAt(t, 'after-commit');
  assert.equal(f.checkpoint.depth, 0);
  assert.equal(f.checkpoint.revision, 1);
  assert.equal(f.checkpoint.operation.status, 'COMPLETED');
  const expected = (await f.expected()).publication;
  const completed = c.decodeCBOR(
    c.dcbor({ digest: c.sha512(c.dcbor(expected)), publication: expected }),
  );
  assert.deepEqual(f.beforeKill.publication, { revision: 1, value: completed });
  assert.deepEqual(c.decodeCBOR(f.beforeKill.operation.result), completed);
  assert.deepEqual(f.disk(), f.beforeKill);
  assert.deepEqual((await f.restarted.call('renew')).result, completed);
  const recovered = (await f.restarted.call('inspect')).result;
  assert.deepEqual(recovered.publication, completed);
  assert.deepEqual(c.decodeCBOR(recovered.operation.result), completed);
  assert.equal(f.requests.length, 1);
});
