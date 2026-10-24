import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { serialize } from 'node:v8';
import { Worker } from 'node:worker_threads';
import { PostgresJournal } from './storage/postgres.mjs';

function publish(memory, value, ready = 1) {
  const bytes = serialize({ ok: true, value }), header = new Int32Array(memory, 0, 2);
  new Uint8Array(memory, 8, bytes.length).set(bytes);
  Atomics.store(header, 1, bytes.length);
  Atomics.store(header, 0, ready);
}
function transport(worker) {
  const memory = new SharedArrayBuffer(4096);
  // A completed BEGIN or SAVEPOINT leaves this response until the next RPC publishes.
  publish(memory, true);
  return Object.assign(Object.create(PostgresJournal.prototype), { memory, worker, timeoutMs: 100 });
}
async function nativeTransport(t, reply) {
  const worker = new Worker(`
    const { parentPort, workerData } = require('node:worker_threads');
    const { serialize } = require('node:v8');
    parentPort.on('message', ({ memory }) => {
      const header = new Int32Array(memory, 0, 2);
      if (workerData) {
        const bytes = serialize({ ok: true, value: { rows: [], changes: 1 } });
        new Uint8Array(memory, 8, bytes.length).set(bytes);
        Atomics.store(header, 1, bytes.length);
        Atomics.store(header, 0, 1);
        Atomics.notify(header, 0);
      } else {
        const deadline = performance.now() + 5000;
        // Release one notification only after a waiter exists, without publishing a response.
        while (Atomics.notify(header, 0) === 0 && performance.now() < deadline) {}
      }
    });
    parentPort.postMessage('ready');
  `, { eval: true, workerData: reply });
  t.after(() => worker.terminate());
  await once(worker, 'message');
  return transport(worker);
}

test('PostgreSQL RPC reads the current response after native publication', async (t) => {
  const journal = await nativeTransport(t, true);
  assert.deepEqual(journal.rpc('consumeNonce'), { rows: [], changes: 1 });
  assert.equal(journal.poisoned, undefined);
});

test('PostgreSQL RPC cannot accept a native notification without a current response', async (t) => {
  const journal = await nativeTransport(t, false);
  assert.throws(() => journal.rpc('consumeNonce'), { code: 'JOURNAL_OUTCOME_UNKNOWN' });
  assert.equal(journal.poisoned, true);
  assert.equal(Atomics.load(new Int32Array(journal.memory, 0, 2), 0), 0);
  assert.throws(() => journal.rpc('consumeNonce'), { code: 'JOURNAL_UNAVAILABLE' });
});

test('PostgreSQL RPC waits for publication after a stale wake without redispatch', (t) => {
  let dispatches = 0, waits = 0;
  const journal = transport({ postMessage() { dispatches++; } });
  t.mock.method(Atomics, 'wait', () => {
    if (++waits === 2) publish(journal.memory, { rows: [], changes: 1 });
    return 'ok';
  });
  assert.deepEqual(journal.rpc('consumeNonce'), { rows: [], changes: 1 });
  assert.equal(dispatches, 1);
  assert.equal(waits, 2);
  assert.equal(journal.poisoned, undefined);
});

test('PostgreSQL RPC stale wakes share one monotonic timeout budget', (t) => {
  let elapsed = 0, dispatches = 0, terminations = 0;
  const budgets = [];
  const journal = transport({
    postMessage() { dispatches++; },
    terminate() { terminations++; },
  });
  t.mock.method(performance, 'now', () => elapsed);
  t.mock.method(Atomics, 'wait', (_header, _index, _value, timeout) => {
    budgets.push(timeout);
    elapsed += 400;
    return 'ok';
  });
  assert.throws(() => journal.rpc('consumeNonce'), { code: 'JOURNAL_OUTCOME_UNKNOWN' });
  assert.deepEqual(budgets, [1100, 700, 300]);
  assert.equal(dispatches, 1);
  assert.equal(terminations, 1);
  assert.equal(journal.poisoned, true);
  assert.throws(() => journal.rpc('consumeNonce'), { code: 'JOURNAL_UNAVAILABLE' });
  assert.equal(dispatches, 1);
});
