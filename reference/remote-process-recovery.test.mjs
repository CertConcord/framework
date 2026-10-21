import test from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import * as c from './core.mjs';
import { issueCertificate, name } from './pki.mjs';
import { activationContext, issuePermit, readControl } from './state.mjs';
import { RemoteCryptoKey } from './providers.mjs';
import { requestBytes } from './transport.mjs';

function waitForMessage(worker, event) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
        clearTimeout(timer);
        worker.child.off('message', message);
        worker.child.off('error', failed);
        worker.child.off('exit', exited);
      },
      failed = (error) => {
        cleanup();
        reject(error);
      },
      exited = () => failed(new Error('Child exited before ' + event + ': ' + worker.stderr)),
      message = (value) => {
        if (value.event === event) {
          cleanup();
          resolve(value);
        }
      },
      timer = setTimeout(
        () => failed(new Error('Child did not reach ' + event + ': ' + worker.stderr)),
        15000,
      );
    worker.child.on('message', message);
    worker.child.once('error', failed);
    worker.child.once('exit', exited);
  });
}

async function crashAndRestart(t, mode) {
  const directory = mkdtempSync(join(tmpdir(), 'certconcord-remote-process-')),
    workers = [];
  t.after(async () => {
    for (const worker of workers) {
      if (worker.child.exitCode === null && worker.child.signalCode === null)
        worker.child.kill('SIGKILL');
      await worker.closed;
    }
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    assert(basename(directory).startsWith('certconcord-remote-process-'));
    rmSync(directory, { recursive: true, force: true });
  });
  const holder = c.generate(),
    authority = c.generate(),
    issuer = name('Synthetic Authority'),
    certificate = issueCertificate(
      {
        publicKey: authority.publicKey,
        issuer,
        subject: issuer,
        serial: 1,
        profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
      },
      authority.privateKey,
    ),
    trustDomainID = c.random(),
    tbs = Buffer.from('Exact synthetic signing input across service process death'),
    activation = activationContext({
      trustDomainID,
      tbs,
      publicKey: holder.publicKey,
      simHash: c.random(64),
      certificateID: c.random(64),
      certificateRepresentationHash: c.random(64),
      transactionID: c.random(),
      policyHash: c.random(64),
      origin: 'https://example.org',
      rpID: 'example.org',
      audience: 'test-gateway',
    }),
    permit = issuePermit(activation, {
      certificate,
      privateKey: authority.privateKey,
      activationEvidenceHash: c.random(64),
      proofMode: 'HUMAN_WEBAUTHN',
    }),
    input = { keyRef: 'document-key', tbs, permit, operationID: c.b64u(activation.operationID) },
    configuration = {
      journalPath: join(directory, 'operations.sqlite'),
      effectsPath: join(directory, 'signing-calls.txt'),
      privateKey: holder.privateKey.export({ type: 'pkcs8', format: 'der' }),
      certificate,
      trustDomainID,
      token: c.b64u(c.random()),
      at: readControl(permit, 'OperationPermit', certificate).issuedAt,
    };
  async function start(mode) {
    const child = fork(new URL('./remote-process-recovery-child.mjs', import.meta.url), [], {
        stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
        serialization: 'advanced',
        execArgv: [],
        windowsHide: true,
      }),
      worker = { child, stderr: '' };
    worker.closed = new Promise((resolve) =>
      child.once('close', (code, signal) => resolve({ code, signal })),
    );
    child.stderr.on('data', (chunk) => {
      worker.stderr += chunk;
    });
    workers.push(worker);
    const ready = waitForMessage(worker, 'ready');
    child.send({ ...configuration, mode });
    const announcement = await ready;
    assert.equal(announcement.pid, child.pid);
    assert.notEqual(child.pid, process.pid);
    worker.remote = new RemoteCryptoKey({
      url: announcement.url,
      token: configuration.token,
      allowLoopback: true,
    });
    return worker;
  }
  const original = await start(mode),
    paused = waitForMessage(original, 'paused'),
    pending = original.remote.sign(input).then(
      (signature) => ({ signature }),
      (error) => ({ error }),
    ),
    checkpoint = await paused;
  assert.equal(checkpoint.stage, mode);
  assert.equal(original.child.kill('SIGKILL'), true);
  const exit = await original.closed;
  assert.equal(exit.signal, 'SIGKILL', original.stderr);
  assert.equal((await pending).error?.name, 'TypeError');
  const restarted = await start('normal');
  assert.notEqual(restarted.child.pid, original.child.pid);
  const assertOneSign = () =>
    assert.equal(readFileSync(configuration.effectsPath, 'utf8'), input.operationID + '\n');
  assertOneSign();
  return {
    remote: restarted.remote,
    input,
    publicKey: holder.publicKey,
    checkpoint,
    assertOneSign,
  };
}

test('Remote CryptoKey process death after completion recovers the original result without signing again', async (t) => {
  const { remote, input, publicKey, checkpoint, assertOneSign } = await crashAndRestart(
      t,
      'after-commit',
    ),
    context = { tbs: input.tbs, publicKey },
    recovered = await remote.getOperationResult(input.operationID, context),
    signature = c.unb64u(recovered.signature);
  assert.deepEqual({ ...recovered }, { status: 'COMPLETED', ...checkpoint.value });
  assert.equal(recovered.operationID, input.operationID);
  assert.equal(recovered.tbsHash, c.b64u(c.sha512(input.tbs)));
  assert(c.verify(input.tbs, signature, publicKey));
  assert.deepEqual(await remote.sign(input), signature);
  assert.deepEqual(await remote.getOperationResult(input.operationID, context), recovered);
  assertOneSign();
});

test('Remote CryptoKey process death before completion remains uncertain without redispatching signing', async (t) => {
  const { remote, input, publicKey, checkpoint, assertOneSign } = await crashAndRestart(
      t,
      'after-sign',
    ),
    context = { tbs: input.tbs, publicKey },
    unknown = { operationID: input.operationID, status: 'UNKNOWN_EXECUTION' };
  assert(c.verify(input.tbs, c.unb64u(checkpoint.value), publicKey));
  assert.deepEqual({ ...(await remote.getOperationResult(input.operationID, context)) }, unknown);
  const retry = await requestBytes(remote.url + '/rra/v1/sign', {
    method: 'POST',
    headers: { authorization: 'Bearer ' + remote.token, 'content-type': 'application/json' },
    body: JSON.stringify({
      version: 1,
      keyRef: input.keyRef,
      tbs: c.b64u(input.tbs),
      operationID: input.operationID,
      permit: c.b64u(input.permit),
    }),
    allowLoopback: true,
  });
  assert.equal(retry.status, 400);
  assert.deepEqual(JSON.parse(retry.body.toString('utf8')), { error: 'UNKNOWN_EXECUTION' });
  assert.deepEqual({ ...(await remote.getOperationResult(input.operationID, context)) }, unknown);
  assertOneSign();
});
