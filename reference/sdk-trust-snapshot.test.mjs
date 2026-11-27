import test from 'node:test';
import assert from 'node:assert/strict';
import { snapshotTrust } from './sdk/trust-snapshot.mjs';

test('closed trust copies nested bytes, collections and policy without replacing callbacks', () => {
  const callback = () => ({ overall: 'INDETERMINATE', reason: 'EXTERNAL_SOURCE' });
  const source = {
    expectedPolicy: { allowed: [Buffer.from([1, 2, 3])] },
    members: new Map([[Buffer.from([4]), { key: Buffer.from([5]) }]]),
    scopes: new Set([Buffer.from([6])]),
    callback,
  };
  const selected = snapshotTrust(source);
  assert.notStrictEqual(selected, source);
  assert.strictEqual(selected.callback, callback);
  source.expectedPolicy.allowed[0].fill(0);
  source.members.values().next().value.key.fill(0);
  source.scopes.values().next().value.fill(0);
  assert.deepEqual(selected.expectedPolicy.allowed[0], Buffer.from([1, 2, 3]));
  assert.deepEqual(selected.members.values().next().value.key, Buffer.from([5]));
  assert.deepEqual(selected.scopes.values().next().value, Buffer.from([6]));
});

test('closed trust rejects accessors and proxies before invoking them', () => {
  let observed = 0;
  const accessor = { get authorityResolver() { observed++; return () => true; } };
  assert.throws(() => snapshotTrust({ nested: accessor }), /SDK_TRUST_ACCESSOR/);
  const proxy = new Proxy({}, { get() { observed++; return null; } });
  assert.throws(() => snapshotTrust({ nested: proxy }), /SDK_TRUST_PROXY/);
  class HostileMap extends Map {
    [Symbol.iterator]() { observed++; return super[Symbol.iterator](); }
  }
  assert.throws(() => snapshotTrust({ nested: new HostileMap() }), /SDK_TRUST_OBJECT_TYPE/);
  assert.equal(observed, 0);
});

test('typed views copy their bytes without consulting an overridable constructor', () => {
  const bytes = new Uint8Array([7, 8]);
  const view = new DataView(new Uint8Array([9, 10]).buffer);
  const selected = snapshotTrust({ bytes, view });
  bytes[0] = 0;
  view.setUint8(0, 0);
  assert.deepEqual([...selected.bytes], [7, 8]);
  assert.equal(selected.view.getUint8(0), 9);

  const alias = new Uint8Array([1]);
  Object.defineProperty(alias, 'constructor', { value: function Alias() { return alias; } });
  assert.throws(() => snapshotTrust({ alias }), /SDK_TRUST_OBJECT_TYPE/);
  let observed = 0;
  const accessed = new Uint8Array([1, 2]);
  Object.defineProperty(accessed, 'length', { get() { observed++; return 3; } });
  assert.throws(() => snapshotTrust({ accessed }), /SDK_TRUST_OBJECT_TYPE/);
  assert.equal(observed, 0);
  class BufferSubclass extends ArrayBuffer {}
  assert.throws(() => snapshotTrust({ bytes: new BufferSubclass(2) }), /SDK_TRUST_OBJECT_TYPE/);
});
