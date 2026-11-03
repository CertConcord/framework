import test from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { D, dcbor, decodeCBOR, wrapAES, unwrapAES, seal, open } from './core.mjs';
import { wrapperHeader, wrapRoot, unwrapRoot, EpochTransition } from './protection.mjs';
import { Journal } from './state.mjs';

const corpus = JSON.parse(
  readFileSync(new URL('./vectors/prf-kpp-root-admission.json', import.meta.url)),
);
const algorithms = ['AES-256-GCM', 'AES-256-KW', 'AES-256-KWP'];
const random = crypto.randomBytes;
const key = (prf, header, domain) =>
  Buffer.from(crypto.hkdfSync('sha256', prf, header.kdfSalt, D(domain, header), 32));
function nativeMAC(prf, header, ciphertext) {
  const k = key(prf, header, 'WrapperMACKey');
  try {
    return crypto.createHmac('sha256', k).update(D('WrapperMAC', { header, ciphertext })).digest();
  } finally {
    k.fill(0);
  }
}
function nativeOpen(prf, wrapper) {
  const h = wrapper.header,
    k = key(prf, h, 'WrapperKDF');
  try {
    if (h.aead === 'AES-256-GCM') {
      const d = crypto.createDecipheriv('aes-256-gcm', k, wrapper.nonce);
      d.setAAD(D('WrapperAAD', h));
      d.setAuthTag(wrapper.tag);
      return Buffer.concat([d.update(wrapper.ciphertext), d.final()]);
    }
    assert.deepEqual(wrapper.tag, nativeMAC(prf, h, wrapper.ciphertext));
    const padded = h.aead === 'AES-256-KWP';
    const d = crypto.createDecipheriv(
      padded ? 'id-aes256-wrap-pad' : 'id-aes256-wrap',
      k,
      padded ? Buffer.from('a65959a6', 'hex') : Buffer.alloc(8, 0xa6),
    );
    return Buffer.concat([d.update(wrapper.ciphertext), d.final()]);
  } finally {
    k.fill(0);
  }
}
function nativeSeal(prf, root, h) {
  const k = key(prf, h, 'WrapperKDF');
  try {
    if (h.aead === 'AES-256-GCM') {
      const nonce = random(12),
        c = crypto.createCipheriv('aes-256-gcm', k, nonce);
      c.setAAD(D('WrapperAAD', h));
      return {
        schemaVersion: 1,
        header: h,
        nonce,
        ciphertext: Buffer.concat([c.update(root), c.final()]),
        tag: c.getAuthTag(),
      };
    }
    const padded = h.aead === 'AES-256-KWP';
    const c = crypto.createCipheriv(
      padded ? 'id-aes256-wrap-pad' : 'id-aes256-wrap',
      k,
      padded ? Buffer.from('a65959a6', 'hex') : Buffer.alloc(8, 0xa6),
    );
    const ciphertext = Buffer.concat([c.update(root), c.final()]);
    return { schemaVersion: 1, header: h, ciphertext, tag: nativeMAC(prf, h, ciphertext) };
  } finally {
    k.fill(0);
  }
}
const shortLength = (a) => (a === 'AES-256-GCM' ? 31 : a === 'AES-256-KW' ? 16 : 1);
function fixtureHeader(aead) {
  return wrapperHeader({
    aead,
    trustDomainID: random(32),
    subjectID: random(32),
    credentialIDHash: random(32),
    contextID: random(32),
    rpID: 'prf-root-admission.example',
    purpose: 'ACCOUNT_WRAP',
  });
}
function observeOverwrite(root, action) {
  const original = Buffer.prototype.fill,
    seen = [];
  Buffer.prototype.fill = function (...args) {
    if (this.length === root.length && this.equals(root)) seen.push(this);
    return Reflect.apply(original, this, args);
  };
  try {
    action();
  } finally {
    Buffer.prototype.fill = original;
  }
  assert(seen.length > 0, 'The exact rejected/retired plaintext buffer was observed');
  for (const buffer of seen) assert.deepEqual(buffer, Buffer.alloc(root.length));
}
test('PRF-KPP root admission: raw envelope inventory covers all authenticated root boundaries', () => {
  assert.equal(corpus.schema, 'certconcord-prf-kpp-root-admission-v1');
  assert.equal(new Set(corpus.cases.map((r) => r.id)).size, corpus.cases.length);
  for (const [a, lengths] of [
    ['AES-256-GCM', [0, 1, 31, 32, 33]],
    ['AES-256-KW', [16, 24, 32, 40]],
    ['AES-256-KWP', [1, 31, 32, 33]],
  ]) {
    assert.deepEqual(
      corpus.cases
        .filter((r) => r.algorithm === a && r.kind === 'authenticated')
        .map((r) => Buffer.from(r.syntheticRoot, 'hex').length),
      lengths,
    );
  }
});
for (const row of corpus.cases) {
  test('PRF-KPP root admission raw: ' + row.id, () => {
    const wire = Buffer.from(row.wire, 'base64'),
      prf = Buffer.from(row.syntheticPRF, 'hex');
    assert.equal(wire.length, row.bytes);
    assert.equal(crypto.createHash('sha256').update(wire).digest('hex'), row.sha256);
    const w = decodeCBOR(wire),
      before = dcbor(w),
      oldPRF = Buffer.from(prf);
    assert.equal(w.header.aead, row.algorithm);
    if (row.kind === 'authenticated') {
      const plaintext = nativeOpen(prf, w);
      assert.deepEqual(plaintext, Buffer.from(row.syntheticRoot, 'hex'));
      if (plaintext.length === 32) assert.deepEqual(unwrapRoot(prf, w), plaintext);
      else assert.throws(() => unwrapRoot(prf, w), { code: 'ROOT_LENGTH' });
    } else {
      assert.throws(() => nativeOpen(prf, w));
      const code = row.kind.includes('tag')
        ? row.algorithm === 'AES-256-GCM'
          ? 'AEAD_AUTHENTICATION'
          : 'WRAPPER_MAC'
        : 'KW_AUTHENTICATION';
      if (!row.kind.includes('tag'))
        assert.deepEqual(w.tag, nativeMAC(prf, w.header, w.ciphertext));
      assert.throws(() => unwrapRoot(prf, w), { code });
    }
    assert.deepEqual(dcbor(w), before);
    assert.deepEqual(prf, oldPRF);
  });
}
for (const algorithm of algorithms) {
  test(
    'PRF-KPP root admission: ' + algorithm + ' overwrites rejected plaintext before throwing',
    () => {
      const prf = random(32),
        root = random(shortLength(algorithm)),
        w = nativeSeal(prf, root, fixtureHeader(algorithm));
      assert.deepEqual(nativeOpen(prf, w), root);
      const before = dcbor(w),
        oldPRF = Buffer.from(prf);
      observeOverwrite(root, () =>
        assert.throws(() => unwrapRoot(prf, w), { code: 'ROOT_LENGTH' }),
      );
      assert.deepEqual(dcbor(w), before);
      assert.deepEqual(prf, oldPRF);
    },
  );
  test('PRF-KPP root admission: ' + algorithm + ' retains outbound root validation', () => {
    const prf = random(32),
      h = fixtureHeader(algorithm),
      oldPRF = Buffer.from(prf);
    for (const n of [0, 31, 32, 33]) {
      const root = random(n),
        original = Buffer.from(root);
      if (n === 32) assert.deepEqual(unwrapRoot(prf, wrapRoot(prf, root, h)), original);
      else assert.throws(() => wrapRoot(prf, root, h), { code: 'ROOT_LENGTH' });
      assert.deepEqual(root, original);
      assert.deepEqual(prf, oldPRF);
    }
  });
  for (const scenario of [
    'equal-short',
    'new-short',
    'old-short',
    'equal-valid',
    'different-valid',
  ]) {
    test('PRF-KPP root admission: ' + algorithm + ' epoch ' + scenario, (t) => {
      const dir = mkdtempSync(join(tmpdir(), 'certconcord-prf-root-')),
        path = join(dir, 'state.sqlite');
      let j = new Journal(path);
      t.after(() => {
        j.close();
        rmSync(dir, { recursive: true, force: true });
      });
      const oldPRF = random(32),
        newPRF = random(32),
        h = fixtureHeader(algorithm);
      const next = {
        ...h,
        epoch: 1,
        prfSalt: random(32),
        kdfSalt: random(32),
        wrapperID: random(32),
      };
      const oldRoot = random(
        ['equal-short', 'old-short'].includes(scenario) ? shortLength(algorithm) : 32,
      );
      const newRoot = scenario.startsWith('equal-')
        ? Buffer.from(oldRoot)
        : random(scenario === 'new-short' ? shortLength(algorithm) : 32);
      if (scenario === 'different-valid') assert.notDeepEqual(newRoot, oldRoot);
      const oldWrapper = nativeSeal(oldPRF, oldRoot, h),
        newWrapper = nativeSeal(newPRF, newRoot, next);
      assert.deepEqual(nativeOpen(oldPRF, oldWrapper), oldRoot);
      assert.deepEqual(nativeOpen(newPRF, newWrapper), newRoot);
      const transition = new EpochTransition(j),
        id = 'synthetic-root';
      transition.prepare(id, { oldWrapper, newWrapper });
      const before = j.get('epoch', id),
        put = j.put.bind(j);
      let writes = 0;
      j.put = (...args) => {
        writes++;
        return put(...args);
      };
      if (scenario === 'equal-valid') {
        const revision = transition.commit(id, newPRF, oldPRF),
          after = j.get('epoch', id);
        assert.equal(writes, 1);
        assert.equal(revision, before.revision + 1);
        const expectedValue = decodeCBOR(dcbor(before.value));
        expectedValue.state = 'COMMITTED';
        assert.deepEqual(after, { revision, value: expectedValue });
      } else {
        const code = scenario === 'different-valid' ? 'EPOCH_ROOT_CHANGED' : 'ROOT_LENGTH';
        const commit = () => assert.throws(() => transition.commit(id, newPRF, oldPRF), { code });
        if (scenario === 'new-short') observeOverwrite(oldRoot, commit);
        else commit();
        assert.equal(writes, 0);
        assert.deepEqual(j.get('epoch', id), before);
        assert.throws(() => transition.retire(id, before.revision), { code: 'EPOCH_STATE' });
        assert.equal(writes, 0);
        if (scenario === 'new-short') {
          assert.deepEqual(unwrapRoot(oldPRF, j.get('epoch', id).value.oldWrapper), oldRoot);
          j.close();
          j = new Journal(path);
          assert.deepEqual(j.get('epoch', id), before);
          assert.deepEqual(unwrapRoot(oldPRF, j.get('epoch', id).value.oldWrapper), oldRoot);
        }
      }
    });
  }
}
test('PRF-KPP root admission: generic primitives retain non-root lengths', () => {
  const k = random(32);
  for (const [padded, lengths] of [
    [false, [16, 40]],
    [true, [1, 33]],
  ])
    for (const n of lengths) {
      const p = random(n);
      assert.deepEqual(unwrapAES(k, wrapAES(k, p, padded), padded), p);
    }
  const p = random(31),
    aad = Buffer.from('synthetic-generic-gcm');
  assert.deepEqual(open(k, seal(k, p, aad), aad), p);
});
