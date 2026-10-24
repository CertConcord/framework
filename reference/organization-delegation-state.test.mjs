import test from 'node:test';
import assert from 'node:assert/strict';
import { decision, record, snapshot } from './organization-delegation-state.mjs';

function guardedProxy(target, revoke = false) {
  let calls = 0;
  const traps = Object.fromEntries(
    ['getPrototypeOf', 'getOwnPropertyDescriptor', 'ownKeys', 'get'].map((name) => [
      name,
      () => {
        calls++;
        throw Object.assign(new Error(name), { overall: 'UNSUPPORTED', commitState: 'COMMITTED' });
      },
    ]),
  );
  const pair = Proxy.revocable(target, traps);
  if (revoke) pair.revoke();
  return { value: pair.proxy, calls: () => calls };
}

for (const [name, target, revoked] of [
  ['record', { value: 1 }, false],
  ['null-prototype record', Object.assign(Object.create(null), { value: 1 }), false],
  ['array', [1], false],
  ['bytes', Buffer.from([1]), false],
  ['revoked record', { value: 1 }, true],
]) {
  test(`organization snapshot rejects ${name} proxies without executing their traps`, () => {
    const proxy = guardedProxy(target, revoked);
    for (const value of [proxy.value, { retained: proxy.value }, [proxy.value]]) {
      assert.throws(() => snapshot(value), { code: 'ORG_OBJECT_SCHEMA', overall: 'INVALID' });
    }
    assert.equal(proxy.calls(), 0);
  });
}

for (const revoked of [false, true]) {
  test(`organization record rejects ${revoked ? 'revoked' : 'live'} proxies before reflection`, () => {
    const proxy = guardedProxy({ value: 1 }, revoked);
    assert.throws(() => record(proxy.value, ['value']), {
      code: 'ORG_OBJECT_SCHEMA',
      overall: 'INVALID',
    });
    assert.equal(proxy.calls(), 0);
  });
}

test('organization snapshots retain independent copies of ordinary public records and bytes', () => {
  const bytes = Buffer.from([1, 2, 3]);
  const original = Object.assign(Object.create(null), { bytes, members: [{ value: 7 }] });
  record(original, ['bytes', 'members']);
  const copied = snapshot(original);
  bytes[0] = 9;
  original.members[0].value = 8;
  assert.deepEqual(copied, { bytes: Buffer.from([1, 2, 3]), members: [{ value: 7 }] });
});

for (const hook of ['constructor', 'species']) {
  for (const thrown of [null, { overall: 'VALID' }, new Error('observation unavailable')]) {
    test(`organization Promise ${hook} exceptions cannot replace the asynchronous outcome: ${String(thrown)}`, () => {
      const value = Promise.resolve({ overall: 'VALID', reason: 'caller' });
      const get = () => {
        throw thrown;
      };
      if (hook === 'constructor') Object.defineProperty(value, 'constructor', { get });
      else
        Object.defineProperty(value, 'constructor', {
          value: {
            get [Symbol.species]() {
              return get();
            },
          },
        });
      assert.deepEqual(decision(value), {
        overall: 'INDETERMINATE',
        reason: 'ORG_ASYNC_DEPENDENCY',
      });
      assert.throws(() => snapshot(value), {
        code: 'ORG_ASYNC_DEPENDENCY',
        overall: 'INDETERMINATE',
      });
    });
  }
}

test('organization Promise rejection observation ignores an own then accessor', async () => {
  const value = Promise.reject(new Error('asynchronous dependency'));
  let calls = 0;
  Object.defineProperty(value, 'then', {
    get() {
      calls++;
      throw new Error('own then');
    },
  });
  assert.deepEqual(decision(value), { overall: 'INDETERMINATE', reason: 'ORG_ASYNC_DEPENDENCY' });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls, 0);
});
