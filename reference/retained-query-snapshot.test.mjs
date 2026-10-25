import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as c from './core.mjs';
import { createRetainedAuthorityResolver } from './retained-authorities.mjs';
import { verifyTimestampToken } from './timestamp.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors/retained-authority-key-incidents.json', import.meta.url)));
const decode = (row) => {
  const bytes = Buffer.from(row.cbor, 'base64');
  assert.equal(bytes.length, row.bytes);
  assert.equal(c.sha256(bytes).toString('hex'), row.sha256);
  return c.decodeCBOR(bytes);
};
const T = 1800000000;
const valid = { overall: 'VALID', reason: 'AUTHORITY_ADMITTED', role: 'STATUS_AUTHORITY',
  mode: 'RAW_KEY', coverageUntil: T + 500 };
const revoked = { overall: 'INVALID', reason: 'AUTHORITY_REVOKED' };
const shape = { overall: 'INVALID', reason: 'HISTORY_QUERY' };
const time = { overall: 'INVALID', reason: 'HISTORY_TIME' };
function fixture(caseName = 'withdrawn-encoding-before-compromise-remains-valid') {
  const row = vectors.cases.find((item) => item.name === caseName);
  const material = decode(vectors.materials.find((item) => item.id === row.material));
  const query = { ...decode(row.query), stateTime: T + 70, knowledgeTime: T + 80 };
  const history = material.histories[row.history], calls = [];
  return { material, query, history, calls, resolve(action = () => {}, overrides = {}) {
    return createRetainedAuthorityResolver({ ...material, history,
      verifyPublication: ({ proof, imprint, at }) => {
        const checked = verifyTimestampToken(proof, { certificate: material.tsaCertificate,
          issuerKey: c.publicFromDER(material.governance.roots[0].publicKeyDER),
          policy: material.tsaPolicy, imprint, at, maxFutureSkew: 0 });
        calls.push({ published: checked.poeUpperBound, at });
        action(calls.length);
        return { overall: 'VALID', ...checked };
      }, ...overrides });
  } };
}

test('retained query snapshots the same knowledge cutoff across publication callbacks', () => {
  const early = fixture(), late = fixture(), changing = fixture();
  late.query.knowledgeTime = changing.query.knowledgeTime = T + 110;
  const before = c.dcbor(changing.query);
  assert.deepEqual(early.resolve()(early.query), valid);
  assert.deepEqual(late.resolve()(late.query), revoked);
  assert.deepEqual(changing.resolve((call) => {
    changing.query.knowledgeTime = call === 1 ? T + 80 : T + 110;
  })(changing.query), revoked);
  assert.deepEqual(c.dcbor(changing.query), before);
  assert.deepEqual(changing.calls, late.calls);
  assert.deepEqual(changing.calls.map((call) => call.published), [T, T + 90, T + 95]);
  assert.deepEqual(early.calls.map((call) => call.published), [T, T + 90]);
});

for (const prototype of [Object.prototype, null]) {
  test('retained query accepts owned data with ' + (prototype ? 'ordinary' : 'null') + ' prototypes', () => {
    const f = fixture();
    f.query = Object.assign(Object.create(prototype), f.query);
    f.query.scope = Object.assign(Object.create(prototype), f.query.scope);
    const before = c.dcbor(f.query);
    Object.freeze(f.query.scope); Object.freeze(f.query);
    assert.deepEqual(f.resolve()(f.query), valid);
    assert.deepEqual(c.dcbor(f.query), before);
    assert.equal(f.calls.length, 2);
  });
}

for (const [knowledgeTime, expected, publications] of [
  [T + 80.25, valid, [T, T + 90]],
  [T + 89.75, valid, [T, T + 90]],
  [T + 90, revoked, [T, T + 90, T + 95]],
]) {
  test('retained query preserves fractional state and knowledge boundary ' + knowledgeTime, () => {
    const f = fixture();
    f.query.stateTime = T + 70.5; f.query.knowledgeTime = knowledgeTime;
    assert.deepEqual(f.resolve()(f.query), expected);
    assert.equal(f.query.stateTime, T + 70.5);
    assert.equal(f.query.knowledgeTime, knowledgeTime);
    assert.deepEqual(f.calls.map((call) => call.published), publications);
  });
}

const mutations = [
  ['purpose', (f) => { f.query.scope.purpose = 'not-selected'; },
    (f) => { f.query.scope.purpose = 'document-signature'; }, { overall: 'INVALID', reason: 'AUTHORITY_SCOPE' }],
  ['domain bytes', (f) => { f.query.scope.trustDomainID.fill(0); },
    (f) => { f.material.trustDomainID.copy(f.query.scope.trustDomainID); }, { overall: 'INVALID', reason: 'AUTHORITY_SCOPE' }],
  ['identity reference', (f) => {
    f.query.publicKeyDER = Buffer.from(f.history[0].manifest.authorities.find((record) =>
      record.publicKeyDER && !record.roles.includes('STATUS_AUTHORITY')).publicKeyDER);
  }, (f, initial) => { f.query.publicKeyDER = initial.publicKeyDER; }, { overall: 'INVALID', reason: 'AUTHORITY_ROLE' }],
  ['identity bytes', () => {}, (f) => { f.query.publicKeyDER.fill(0); }, valid],
  ['scope reference', () => {}, (f) => { f.query.scope = { trustDomainID: Buffer.alloc(32) }; }, valid],
  ['role and operation time', () => {}, (f) => { f.query.role = 'ISSUER'; f.query.stateTime = T - 1; }, valid],
];
for (const [name, prepare, mutate, expected] of mutations) {
  test('retained query detaches ' + name + ' before publication callbacks', () => {
    const f = fixture(), initial = c.decodeCBOR(c.dcbor(f.query));
    prepare(f);
    const stable = f.resolve()(f.query);
    f.calls.length = 0;
    assert.deepEqual(stable, expected);
    assert.deepEqual(f.resolve((call) => { if (call === 1) mutate(f, initial); })(f.query), expected);
    assert.equal(f.calls.length, 2);
  });
}

test('retained query detaches selected certificate bytes before publication callbacks', () => {
  const f = fixture('selected-certificate-positive');
  const expected = { ...valid, mode: 'CERTIFICATE' };
  assert.deepEqual(f.resolve()(f.query), expected);
  f.calls.length = 0;
  assert.deepEqual(f.resolve(() => { f.query.certificate.fill(0); })(f.query), expected);
  assert.equal(f.calls.length, 1);
});

test('retained query preserves optional identity nulls and certificate precedence', () => {
  const raw = fixture(); raw.query.certificate = null;
  assert.deepEqual(raw.resolve()(raw.query), valid);
  for (const publicKeyDER of [null, undefined, raw.query.publicKeyDER]) {
    const f = fixture('selected-certificate-positive'); f.query.publicKeyDER = publicKeyDER;
    assert.deepEqual(f.resolve()(f.query), { ...valid, mode: 'CERTIFICATE' });
    assert.equal(f.calls.length, 1);
  }
});

const badTimes = [
  ['negative state', { stateTime: -0.5 }],
  ['negative knowledge', { stateTime: -1, knowledgeTime: -0.5 }],
  ['NaN state', { stateTime: NaN }],
  ['infinite state', { stateTime: Infinity }],
  ['NaN knowledge', { knowledgeTime: NaN }],
  ['infinite knowledge', { knowledgeTime: Infinity }],
  ['missing state', { stateTime: undefined }],
  ['missing knowledge', { knowledgeTime: undefined }],
  ['null state', { stateTime: null }],
  ['string state', { stateTime: String(T + 70) }],
  ['string knowledge', { knowledgeTime: String(T + 80) }],
  ['boolean state', { stateTime: true }],
  ['state after knowledge', { stateTime: T + 81 }],
  ['knowledge after validation', { knowledgeTime: T + 301 }],
  ['unsafe state and knowledge', { stateTime: Number.MAX_SAFE_INTEGER + 1, knowledgeTime: Number.MAX_SAFE_INTEGER + 1 }],
];
for (const [name, values] of badTimes) {
  test('retained query rejects ' + name + ' before publication verification', () => {
    const f = fixture(); Object.assign(f.query, values);
    assert.deepEqual(f.resolve()(f.query), time);
    assert.deepEqual(f.calls, []);
  });
}

test('retained query validates numeric times without coercing objects', () => {
  const f = fixture(); let hooks = 0;
  f.query.stateTime = { [Symbol.toPrimitive]() { hooks++; return T + 70; } };
  assert.deepEqual(f.resolve()(f.query), time);
  assert.equal(hooks, 0); assert.deepEqual(f.calls, []);
});

test('retained query allows zero and exact maximum safe instants without inventing history', () => {
  for (const instant of [0, Number.MAX_SAFE_INTEGER]) {
    const f = fixture(); f.query.stateTime = f.query.knowledgeTime = instant;
    assert.deepEqual(f.resolve(() => {}, { history: [], validationTime: Number.MAX_SAFE_INTEGER })(f.query),
      { overall: 'INDETERMINATE', reason: 'HISTORY_MISSING' });
    assert.deepEqual(f.calls, []);
  }
});

for (const field of ['stateTime', 'knowledgeTime', 'role', 'scope', 'publicKeyDER', 'certificate']) {
  test('retained query rejects own ' + field + ' accessor without executing it', () => {
    const f = fixture(); let hooks = 0;
    Object.defineProperty(f.query, field, { get() { hooks++; throw Error('query accessor'); } });
    assert.deepEqual(f.resolve()(f.query), shape);
    assert.equal(hooks, 0); assert.deepEqual(f.calls, []);
  });
}

test('retained query rejects proxy and custom-prototype records without executing traps', () => {
  const f = fixture(); let hooks = 0;
  const handler = { get() { hooks++; throw Error('get'); }, ownKeys() { hooks++; throw Error('keys'); },
    getPrototypeOf() { hooks++; throw Error('prototype'); }, getOwnPropertyDescriptor() { hooks++; throw Error('descriptor'); } };
  const proxy = new Proxy({}, handler);
  const revokedProxy = Proxy.revocable({}, handler); revokedProxy.revoke();
  const resolve = f.resolve();
  for (const query of [null, undefined, [], () => {}, proxy, revokedProxy.proxy, Object.create(proxy), Object.create(f.query)])
    assert.deepEqual(resolve(query), shape);
  for (const scope of [null, undefined, [], proxy, revokedProxy.proxy, Object.create(proxy), Object.create(f.query.scope)])
    assert.deepEqual(resolve({ ...f.query, scope }), shape);
  assert.equal(hooks, 0); assert.deepEqual(f.calls, []);
});

test('retained query rejects executable and unsupported scope fields without hooks', () => {
  const f = fixture(); let hooks = 0;
  const scopes = [
    { ...f.query.scope, get purpose() { hooks++; return 'document-signature'; } },
    { ...f.query.scope, get trustDomainID() { hooks++; return f.material.trustDomainID; } },
    { ...f.query.scope, purpose: { [Symbol.toPrimitive]() { hooks++; return 'document-signature'; } } },
    { ...f.query.scope, purpose: () => 'document-signature' },
  ];
  for (const scope of scopes) assert.deepEqual(f.resolve()({ ...f.query, scope }), shape);
  assert.equal(hooks, 0); assert.deepEqual(f.calls, []);
});

test('retained query preserves ordinary scope errors and known revocation precedence', () => {
  for (const change of [
    (scope) => { scope.extra = 'not-a-scope-field'; },
    (scope) => { scope.purpose = ''; },
    (scope) => { scope.purpose = null; },
    (scope) => { scope.trustDomainID = 'not-bytes'; },
    (scope) => { delete scope.trustDomainID; },
  ]) {
    for (const knowledgeTime of [T + 80, T + 110]) {
      const f = fixture(); change(f.query.scope); f.query.knowledgeTime = knowledgeTime;
      assert.deepEqual(f.resolve()(f.query), knowledgeTime === T + 110 ? revoked :
        { overall: 'INVALID', reason: 'AUTHORITY_SCOPE' });
      assert.equal(f.calls.length, knowledgeTime === T + 110 ? 3 : 2);
    }
  }
});

test('retained query preserves consumed nonenumerable scope data and ignores unused fields', () => {
  const f = fixture(); let hooks = 0;
  for (const key of Object.keys(f.query.scope))
    Object.defineProperty(f.query.scope, key, { enumerable: false });
  Object.defineProperty(f.query.scope, 'unused', { get() { hooks++; throw Error('unused'); } });
  Object.defineProperty(f.query.scope, Symbol('unused'), { enumerable: true, get() { hooks++; throw Error('symbol'); } });
  assert.deepEqual(f.resolve()(f.query), valid);
  assert.equal(hooks, 0); assert.equal(f.calls.length, 2);
  assert.equal(Object.getOwnPropertyDescriptor(f.query.scope, 'purpose').enumerable, false);
});

test('retained query keeps nonenumerable scope semantics before missing identity decisions', () => {
  const f = fixture('unselected-raw-key-under-certificate-policy');
  Object.defineProperty(f.query.scope, 'profileID', { value: null, enumerable: false });
  assert.deepEqual(f.resolve()(f.query), { overall: 'INDETERMINATE', reason: 'AUTHORITY_MISSING' });
  assert.equal(f.calls.length, 1);
  assert.equal(Object.getOwnPropertyDescriptor(f.query.scope, 'profileID').enumerable, false);
});

test('retained query rejects nonprimitive roles before history and incident decisions', () => {
  for (const knowledgeTime of [T + 80, T + 110]) {
    const f = fixture(); let hooks = 0;
    f.query.knowledgeTime = knowledgeTime;
    f.query.role = { [Symbol.toPrimitive]() { hooks++; return 'STATUS_AUTHORITY'; } };
    assert.deepEqual(f.resolve()(f.query), shape);
    assert.equal(hooks, 0); assert.deepEqual(f.calls, []);
    f.query.role = 'UNSELECTED_ROLE';
    assert.deepEqual(f.resolve()(f.query), knowledgeTime === T + 110 ? revoked :
      { overall: 'UNSUPPORTED', reason: 'AUTHORITY_ROLE_UNSUPPORTED' });
    assert.equal(f.calls.length, knowledgeTime === T + 110 ? 3 : 2);
  }
});

test('retained query ignores unrelated top-level fields without reading them', () => {
  const f = fixture(); let hooks = 0;
  Object.defineProperty(f.query, 'extension', { get() { hooks++; throw Error('unused'); } });
  assert.deepEqual(f.resolve()(f.query), valid);
  assert.equal(hooks, 0); assert.equal(f.calls.length, 2);
});

test('retained query copies genuine Buffer view bytes without caller conversion hooks', () => {
  const f = fixture(); let hooks = 0;
  for (const [owner, key] of [[f.query, 'publicKeyDER'], [f.query.scope, 'trustDomainID']]) {
    const original = owner[key], backing = Buffer.alloc(original.length + 7);
    original.copy(backing, 3); owner[key] = backing.subarray(3, 3 + original.length);
    for (const property of ['valueOf', 'length', 'byteLength', 'byteOffset', 'buffer', 'constructor', Symbol.iterator, Symbol.toPrimitive])
      Object.defineProperty(owner[key], property, { get() { hooks++; throw Error('byte hook'); } });
  }
  assert.deepEqual(f.resolve()(f.query), valid);
  assert.equal(hooks, 0); assert.equal(f.calls.length, 2);
});

test('retained query rejects fake proxy custom and shared byte views before reading them', () => {
  const f = fixture(); let hooks = 0;
  const proxy = new Proxy(f.query.publicKeyDER, { get() { hooks++; throw Error('get'); },
    getPrototypeOf() { hooks++; throw Error('prototype'); } });
  const custom = Buffer.from(f.query.publicKeyDER);
  Object.setPrototypeOf(custom, new Proxy(Buffer.prototype, { getPrototypeOf() { hooks++; throw Error('chain'); } }));
  const unsupported = [proxy, Object.create(Buffer.prototype), custom, new Uint8Array(32),
    new Uint16Array(32), new DataView(new ArrayBuffer(32)), Buffer.from(new SharedArrayBuffer(32))];
  for (const bytes of unsupported) {
    assert.deepEqual(f.resolve()({ ...f.query, publicKeyDER: bytes }), shape);
    assert.deepEqual(f.resolve()({ ...f.query, scope: { ...f.query.scope, trustDomainID: bytes } }), shape);
  }
  assert.deepEqual(f.resolve()({ ...f.query, publicKeyDER: 'bytes' }), shape);
  assert.equal(hooks, 0); assert.deepEqual(f.calls, []);
});
