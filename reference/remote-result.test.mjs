import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import * as c from './core.mjs';
import { RemoteCryptoKey } from './providers.mjs';
import { readBody, sendJSON } from './transport.mjs';

// Synthetic RRA peer over real HTTP; no external provider interoperability claim.
async function fixture(t) {
  const key = c.generate('ec'),
    tbs = Buffer.from('Retained exact remote signing input'),
    operationID = c.b64u(c.random()),
    completed = {
      operationID,
      status: 'COMPLETED',
      tbsHash: c.b64u(c.sha512(tbs)),
      signature: c.b64u(c.sign(tbs, key.privateKey)),
    },
    f = {
      key,
      tbs,
      operationID,
      completed,
      response: completed,
      requests: [],
      beforeResponse: async () => {},
    },
    server = createServer(async (req, res) => {
      try {
        const request = JSON.parse((await readBody(req)).toString('utf8'));
        f.requests.push({ path: req.url, request });
        assert.equal(req.method, 'POST');
        assert.equal(req.headers.authorization, 'Bearer synthetic-result-query');
        assert.equal(req.url, '/rra/v1/result');
        assert.deepEqual(request, { operationID });
        await f.beforeResponse();
        sendJSON(res, 200, f.response);
      } catch {
        sendJSON(res, 400, { error: 'INVALID_REQUEST' });
      }
    });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  f.remote = new RemoteCryptoKey({
    url: 'http://127.0.0.1:' + server.address().port,
    token: 'synthetic-result-query',
    allowLoopback: true,
  });
  f.context = { tbs, publicKey: key.publicKey };
  f.query = () => f.remote.getOperationResult(operationID, f.context);
  f.assertQueries = (count) =>
    assert.deepEqual(
      f.requests,
      Array.from({ length: count }, () => ({ path: '/rra/v1/result', request: { operationID } })),
    );
  return f;
}

test('Remote CryptoKey result queries verify completed signatures against retained input and key', async (t) => {
  const f = await fixture(t),
    result = await f.query();
  assert.deepEqual({ ...result }, f.completed);
  assert(c.verify(f.tbs, c.unb64u(result.signature), f.key.publicKey));
  assert.deepEqual(await f.query(), result);
  f.assertQueries(2);
});

test('Remote CryptoKey result queries reject substituted operation, message and signing key', async (t) => {
  const f = await fixture(t),
    other = c.generate('ec'),
    changed = Buffer.from('Another remote signing input'),
    cases = [
      [{ operationID: c.b64u(c.random()) }, 'REMOTE_RESPONSE_BINDING'],
      [{ tbsHash: c.b64u(c.sha512(changed)) }, 'REMOTE_RESPONSE_BINDING'],
      [{ signature: c.b64u(c.sign(changed, f.key.privateKey)) }, 'REMOTE_RESULT_SIGNATURE'],
      [{ signature: c.b64u(c.sign(f.tbs, other.privateKey)) }, 'REMOTE_RESULT_SIGNATURE'],
      [{ signature: '' }, 'REMOTE_RESULT_SIGNATURE'],
      [{ signature: 'not+base64url' }, 'BAD_BASE64URL'],
    ];
  for (const [replacement, code] of cases) {
    f.response = { ...f.completed, ...replacement };
    await assert.rejects(f.query(), { code });
  }
  f.response = f.completed;
  await assert.rejects(
    f.remote.getOperationResult(f.operationID, { tbs: f.tbs, publicKey: other.publicKey }),
    { code: 'REMOTE_RESULT_SIGNATURE' },
  );
  f.assertQueries(cases.length + 1);
});

test('Remote CryptoKey result queries reject malformed completion and ambiguous states', async (t) => {
  const f = await fixture(t),
    state = { operationID: f.operationID, status: 'UNKNOWN_EXECUTION' },
    cases = [
      [null, 'EXPECTED_MAP'],
      [[], 'EXPECTED_MAP'],
      [{}, 'MISSING_FIELD'],
      [{ operationID: f.operationID }, 'MISSING_FIELD'],
      [{ status: 'COMPLETED' }, 'MISSING_FIELD'],
      [{ ...state, status: 'DISPATCHED' }, 'REMOTE_RESULT_STATUS'],
      [{ ...state, status: 'SUCCESS' }, 'REMOTE_RESULT_STATUS'],
      [{ ...state, status: null }, 'REMOTE_RESULT_STATUS'],
      [{ ...state, status: 'COMPLETED' }, 'MISSING_FIELD'],
      [{ ...state, status: 'COMPLETED', tbsHash: f.completed.tbsHash }, 'MISSING_FIELD'],
      [{ ...state, status: 'COMPLETED', signature: f.completed.signature }, 'MISSING_FIELD'],
      [{ ...f.completed, extra: true }, 'UNKNOWN_FIELD'],
      [{ ...state, signature: f.completed.signature }, 'UNKNOWN_FIELD'],
      [{ ...state, status: 'NOT_FOUND', tbsHash: f.completed.tbsHash }, 'UNKNOWN_FIELD'],
    ];
  for (const [response, code] of cases) {
    f.response = response;
    await assert.rejects(f.query(), { code });
  }
  f.assertQueries(cases.length);
});

test('Remote CryptoKey result queries preserve unresolved outcomes without signing', async (t) => {
  const f = await fixture(t);
  for (const status of ['UNKNOWN_EXECUTION', 'NOT_FOUND']) {
    f.response = { operationID: f.operationID, status };
    assert.deepEqual({ ...(await f.query()) }, f.response);
  }
  f.assertQueries(2);
});

test('Remote CryptoKey result queries require retained input and an expected public key before HTTP', async (t) => {
  const f = await fixture(t);
  for (const context of [
    undefined,
    {},
    { tbs: f.tbs },
    { publicKey: f.key.publicKey },
    { tbs: f.tbs.toString('utf8'), publicKey: f.key.publicKey },
    { tbs: f.tbs, publicKey: f.key.privateKey },
  ])
    await assert.rejects(f.remote.getOperationResult(f.operationID, context), {
      code: 'REMOTE_RESULT_CONTEXT',
    });
  f.assertQueries(0);
});

test('Remote CryptoKey result queries freeze retained input before waiting for HTTP', async (t) => {
  const f = await fixture(t),
    original = Buffer.from(f.tbs),
    changed = Buffer.alloc(f.tbs.length);
  for (const substitute of [false, true]) {
    let entered, release;
    const ready = new Promise((resolve) => {
        entered = resolve;
      }),
      gate = new Promise((resolve) => {
        release = resolve;
      });
    f.beforeResponse = async () => {
      entered();
      await gate;
    };
    f.tbs.set(original);
    f.response = substitute
      ? {
          ...f.completed,
          tbsHash: c.b64u(c.sha512(changed)),
          signature: c.b64u(c.sign(changed, f.key.privateKey)),
        }
      : f.completed;
    const pending = f.query();
    await ready;
    f.tbs.fill(0);
    release();
    if (substitute) await assert.rejects(pending, { code: 'REMOTE_RESPONSE_BINDING' });
    else assert.deepEqual({ ...(await pending) }, f.completed);
  }
  f.assertQueries(2);
});
