import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { Journal } from './state.mjs';
import { TimestampClient } from './timestamp-service.mjs';
import { encodeTimestampResponse } from './timestamp-protocol.mjs';
import {
  epoch,
  applicationFixture,
  deferred,
  operation,
  assertVerdict,
} from './timestamp-application-fixtures.mjs';

let f;
before(() => {
  f = applicationFixture();
});
after(() => f?.close());
function harness(t, overrides = {}) {
  const journal = overrides.journal ?? new Journal();
  if (!overrides.journal) t.after(() => journal.close());
  const state = {
    sends: 0,
    contexts: 0,
    context: f.context({ knowledgeTime: epoch + 20 }),
    ...overrides.state,
  };
  const options = {
    journal,
    clientID: 'fixture-client',
    maxResponseDelaySeconds: 15,
    readContext: async () => {
      state.contexts++;
      return overrides.readContext ? overrides.readContext(state) : state.context;
    },
    send: async (requestDER, metadata) => {
      state.sends++;
      assert.equal(journal.depth ?? 0, 0, 'transport callback runs outside SQLite transaction');
      return overrides.send ? overrides.send(requestDER, metadata, state) : f.response(requestDER);
    },
  };
  return { client: new TimestampClient(options), state, journal, options };
}

test('client durably accepts a bound response and repeated lookup does not re-send or re-verify', async (t) => {
  const h = harness(t),
    op = operation(1),
    requestDER = f.request();
  const first = await h.client.request({ operationID: op, requestDER });
  assert.equal(first.state, 'COMPLETED');
  assertVerdict(first.verification, 'VALID');
  const expected = Buffer.from(first.responseDER),
    counts = [h.state.sends, h.state.contexts];
  first.responseDER.fill(0);
  first.verification.tokenDER.fill(0);
  first.operationID.fill(0);
  assert.deepEqual(h.client.result(op).responseDER, expected);
  assert.deepEqual((await h.client.request({ operationID: op, requestDER })).responseDER, expected);
  assert.deepEqual([h.state.sends, h.state.contexts], counts);
  await assert.rejects(
    h.client.request({ operationID: op, requestDER: f.request({ nonce: 99n }) }),
    { code: 'IDEMPOTENCY_CONFLICT' },
  );
});

test('client requires nonce even though standalone verification supports nonce-free proofs', async (t) => {
  const h = harness(t);
  await assert.rejects(
    h.client.request({ operationID: operation(2), requestDER: f.request({ nonce: null }) }),
    { code: 'TSP_NONCE_REQUIRED', overall: 'UNSUPPORTED' },
  );
  assert.equal(h.state.sends + h.state.contexts, 0);
});

test('client rejects caller-supplied current-time overrides', async (t) => {
  const h = harness(t);
  await assert.rejects(
    h.client.request({
      operationID: operation(3),
      requestDER: f.request(),
      knowledgeTime: epoch + 20,
    }),
    { code: 'TSP_UNKNOWN_OPTION', overall: 'INVALID' },
  );
  assert.equal(h.state.sends, 0);
});

test('parallel request retries perform one external dispatch', async (t) => {
  const entered = deferred(),
    release = deferred();
  const h = harness(t, {
    send: async (raw) => {
      entered.resolve();
      await release.promise;
      return f.response(raw);
    },
  });
  const op = operation(4),
    requestDER = f.request(),
    waiting = h.client.request({ operationID: op, requestDER });
  await entered.promise;
  assert.equal(
    (await h.client.request({ operationID: op, requestDER })).state,
    'UNKNOWN_EXECUTION',
  );
  assert.equal(h.state.sends, 1);
  release.resolve();
  assertVerdict((await waiting).verification, 'VALID');
});

test('lost transport result is not replayed and only an exact bound response reconciles', async (t) => {
  const h = harness(t, {
    send: async () => {
      throw Error('connection lost after remote acceptance');
    },
  });
  const op = operation(5),
    requestDER = f.request();
  assert.equal(
    (await h.client.request({ operationID: op, requestDER })).state,
    'UNKNOWN_EXECUTION',
  );
  assert.equal(
    (await h.client.request({ operationID: op, requestDER })).state,
    'UNKNOWN_EXECUTION',
  );
  assert.equal(h.state.sends, 1);
  const result = await h.client.reconcile({ operationID: op, responseDER: f.response(requestDER) });
  assert.equal(result.state, 'COMPLETED');
  assertVerdict(result.verification, 'VALID');
  assert.equal(h.state.sends, 1);
  await assert.rejects(
    h.client.reconcile({ operationID: op, responseDER: f.response(requestDER) }),
    { code: 'TSP_RESPONSE_CONFLICT' },
  );
});

test('a received wrong-nonce response is retained as INVALID without another dispatch', async (t) => {
  const h = harness(t, { send: async (raw) => f.response(raw, { nonce: 88n }) });
  const op = operation(6),
    requestDER = f.request(),
    result = await h.client.request({ operationID: op, requestDER });
  assert.equal(result.state, 'COMPLETED');
  assertVerdict(result.verification, 'INVALID');
  assert.deepEqual(
    (await h.client.request({ operationID: op, requestDER })).responseDER,
    result.responseDER,
  );
  assert.equal(h.state.sends, 1);
});

test('waiting is a retained interim observation and explicit reconciliation accepts a terminal token', async (t) => {
  const h = harness(t, { send: async () => encodeTimestampResponse({ status: 3 }) });
  const op = operation(7),
    requestDER = f.request();
  const pending = await h.client.request({ operationID: op, requestDER });
  assert.equal(pending.state, 'PENDING');
  assert.equal(pending.responseDER, undefined);
  assertVerdict(pending.verification, 'INDETERMINATE', 'TSP_WAITING');
  const terminal = await h.client.reconcile({
    operationID: op,
    responseDER: f.response(requestDER),
  });
  assertVerdict(terminal.verification, 'VALID');
  assert.equal(h.state.sends, 1);
});

test('completed transport rejection remains a no-proof result', async (t) => {
  const h = harness(t, {
    send: async () => encodeTimestampResponse({ status: 2, failureBits: [14] }),
  });
  const result = await h.client.request({ operationID: operation(8), requestDER: f.request() });
  assert.equal(result.state, 'COMPLETED');
  assertVerdict(result.verification, 'INDETERMINATE', 'TSP_REQUEST_REJECTED');
  assert.deepEqual(result.verification.protocol.failureBits, [14]);
});

test('a correctly bound response outside the actual response-delay budget is retained but not VALID', async (t) => {
  const h = harness(t, {
    send: async (raw, _metadata, state) => {
      const response = f.response(raw);
      state.context.knowledgeTime = epoch + 36;
      return response;
    },
  });
  const result = await h.client.request({ operationID: operation(9), requestDER: f.request() });
  assert.equal(result.state, 'COMPLETED');
  assertVerdict(result.verification, 'INDETERMINATE', 'TSP_RESPONSE_DELAY');
});

test('an old token predating the actual request observation is not accepted as a fresh response', async (t) => {
  const h = harness(t, { send: async (raw) => f.response(raw, { genTime: epoch + 19 }) });
  assertVerdict(
    (await h.client.request({ operationID: operation(10), requestDER: f.request() })).verification,
    'INVALID',
    'TSP_RESPONSE_TIME',
  );
});

test('request and callback metadata mutation cannot change the durable dispatch binding', async (t) => {
  const entered = deferred(),
    release = deferred();
  const h = harness(t, {
    readContext: async (state) => {
      if (state.contexts === 1) {
        entered.resolve();
        await release.promise;
      }
      return state.context;
    },
    send: async (raw, metadata) => {
      const response = f.response(raw);
      raw.fill(0);
      metadata.operationID.fill(0);
      return response;
    },
  });
  const requestDER = f.request(),
    expected = Buffer.from(requestDER),
    op = operation(11),
    originalID = Buffer.from(op);
  const waiting = h.client.request({ operationID: op, requestDER });
  await entered.promise;
  requestDER.fill(0);
  op.fill(0);
  release.resolve();
  const result = await waiting;
  assertVerdict(result.verification, 'VALID');
  assert.deepEqual(result.operationID, originalID);
  assert.deepEqual(result.verification.requestDER, expected);
});

test('received bytes are snapshotted before the post-receipt context await', async (t) => {
  const requestDER = f.request(),
    responseDER = f.response(requestDER),
    expected = Buffer.from(responseDER);
  const entered = deferred(),
    release = deferred();
  const h = harness(t, {
    send: async () => responseDER,
    readContext: async (state) => {
      if (state.contexts === 2) {
        entered.resolve();
        await release.promise;
      }
      return state.context;
    },
  });
  const waiting = h.client.request({ operationID: operation(12), requestDER });
  await entered.promise;
  responseDER.fill(0);
  release.resolve();
  const result = await waiting;
  assertVerdict(result.verification, 'VALID');
  assert.deepEqual(result.responseDER, expected);
});

test('unavailable post-receipt context retains the response for later reconciliation without dispatch', async (t) => {
  const requestDER = f.request(),
    responseDER = f.response(requestDER);
  const h = harness(t, {
    send: async () => responseDER,
    readContext: async (state) => {
      if (state.contexts === 2) throw Error('context temporarily unavailable');
      return state.context;
    },
  });
  const op = operation(13),
    first = await h.client.request({ operationID: op, requestDER });
  assert.equal(first.state, 'PENDING');
  assertVerdict(first.verification, 'INDETERMINATE', 'TSP_CONTEXT_UNAVAILABLE');
  assertVerdict((await h.client.reconcile({ operationID: op, responseDER })).verification, 'VALID');
  assert.equal(h.state.sends, 1);
});

test('a future accuracy upper bound reconciles the same received bytes after real time progression', async (t) => {
  const requestDER = f.request(),
    responseDER = f.response(requestDER, { accuracyMicros: 500000 });
  const h = harness(t, { send: async () => responseDER });
  const op = operation(14),
    first = await h.client.request({ operationID: op, requestDER });
  assert.equal(first.state, 'PENDING');
  assertVerdict(first.verification, 'INDETERMINATE', 'TSP_NOT_YET_OBSERVABLE');
  h.state.context.knowledgeTime++;
  const result = await h.client.reconcile({ operationID: op, responseDER });
  assertVerdict(result.verification, 'VALID');
  assert.deepEqual(result.responseDER, responseDER);
  assert.equal(h.state.sends, 1);
});

test('restart retains completed bytes and persistent knowledge rollback protection', async (t) => {
  const path = f.file('application-client.sqlite'),
    requestDER = f.request(),
    op = operation(15);
  let journal = new Journal(path),
    h = harness(t, { journal });
  const first = await h.client.request({ operationID: op, requestDER });
  journal.close();
  journal = new Journal(path);
  t.after(() => journal.close());
  h = harness(t, { journal });
  h.state.context.knowledgeTime--;
  assert.deepEqual(
    (await h.client.request({ operationID: op, requestDER })).responseDER,
    first.responseDER,
  );
  assert.equal(h.state.sends + h.state.contexts, 0);
  await assert.rejects(
    h.client.request({ operationID: operation(16), requestDER: f.request({ nonce: 43n }) }),
    { code: 'TSP_CLOCK_ROLLBACK', overall: 'INDETERMINATE' },
  );
  assert.equal(h.state.sends, 0);
});

test('completion write failure retains the response and never triggers a replacement request', async (t) => {
  const requestDER = f.request(),
    responseDER = f.response(requestDER),
    h = harness(t, { send: async () => responseDER });
  const original = h.journal.reconcile.bind(h.journal);
  let failOnce = true;
  h.journal.reconcile = (...args) => {
    if (failOnce) {
      failOnce = false;
      throw Error('simulated completion commit failure');
    }
    return original(...args);
  };
  const op = operation(17),
    first = await h.client.request({ operationID: op, requestDER });
  assert.equal(first.state, 'UNKNOWN_EXECUTION');
  assert.equal(first.responseDER, undefined);
  assert.equal(h.state.sends, 1);
  const final = await h.client.reconcile({ operationID: op, responseDER });
  assertVerdict(final.verification, 'VALID');
  assert.equal(h.state.sends, 1);
});

test('a timely received response keeps its first trusted receipt time across a failed completion and late reconciliation', async (t) => {
  const requestDER = f.request(),
    responseDER = f.response(requestDER);
  const h = harness(t, { send: async () => responseDER }),
    original = h.journal.reconcile.bind(h.journal);
  let failOnce = true;
  h.journal.reconcile = (...args) => {
    if (failOnce) {
      failOnce = false;
      throw Error('simulated completion commit failure');
    }
    return original(...args);
  };
  const op = operation(18);
  try {
    await h.client.request({ operationID: op, requestDER });
  } catch (error) {
    assert.equal(error.message, 'simulated completion commit failure');
  }
  assert.equal(h.state.sends, 1);
  h.state.context.knowledgeTime = epoch + 40;
  const result = await h.client.reconcile({ operationID: op, responseDER });
  assertVerdict(result.verification, 'VALID');
  assert.deepEqual(result.responseDER, responseDER);
  assert.equal(h.state.sends, 1);
});

test('a delayed waiting-response callback cannot overwrite the receipt time of a newer terminal candidate', async (t) => {
  const requestDER = f.request(),
    terminal = f.response(requestDER, { genTime: epoch + 30, accuracyMicros: 500000 });
  const entered = deferred(),
    oldWaiter = deferred();
  const h = harness(t, {
    send: async () => encodeTimestampResponse({ status: 3 }),
    readContext: async (state) => {
      if (state.contexts === 1) return f.context({ knowledgeTime: epoch + 20 });
      if (state.contexts === 2) {
        entered.resolve();
        return oldWaiter.promise;
      }
      if (state.contexts === 3) return f.context({ knowledgeTime: epoch + 30 });
      return f.context({ knowledgeTime: epoch + 41 });
    },
  });
  const op = operation(19),
    original = h.client.request({ operationID: op, requestDER });
  await entered.promise;
  const pending = await h.client.reconcile({ operationID: op, responseDER: terminal });
  assert.equal(pending.state, 'PENDING');
  assertVerdict(pending.verification, 'INDETERMINATE', 'TSP_NOT_YET_OBSERVABLE');
  oldWaiter.resolve(f.context({ knowledgeTime: epoch + 40 }));
  try {
    await original;
  } catch (error) {
    assert.equal(error.code, 'TSP_RESPONSE_CONFLICT');
  }
  const result = await h.client.reconcile({ operationID: op, responseDER: terminal });
  assertVerdict(result.verification, 'VALID');
  assert.deepEqual(result.responseDER, terminal);
  assert.equal(h.state.sends, 1);
});

test('a pre-dispatch persistence failure is typed unavailable with the original operation ID and no send', async (t) => {
  const h = harness(t),
    original = h.journal.put.bind(h.journal),
    op = operation(20);
  let failOnce = true;
  h.journal.put = (...args) => {
    if (failOnce) {
      failOnce = false;
      throw Error('database unavailable');
    }
    return original(...args);
  };
  await assert.rejects(h.client.request({ operationID: op, requestDER: f.request() }), (error) => {
    assert.equal(error.code, 'TSP_PERSISTENCE_UNAVAILABLE');
    assert.equal(error.overall, 'INDETERMINATE');
    assert.deepEqual(error.operationID, op);
    return true;
  });
  assert.equal(h.state.sends, 0);
  assertVerdict(
    (await h.client.request({ operationID: op, requestDER: f.request() })).verification,
    'VALID',
  );
  assert.equal(h.state.sends, 1);
});
