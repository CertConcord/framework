import test from 'node:test';
import assert from 'node:assert/strict';
import { record, snapshot } from './organization-delegation-state.mjs';

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
