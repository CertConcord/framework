import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { parseDER, oidText } from './core.mjs';
import { verifyCRL, verifyOCSP } from './revocation.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/crl-time-choice.json', import.meta.url), 'utf8'),
);
const bytes = (s) => Buffer.from(s, 'base64');
const key = (s) => createPublicKey({ key: bytes(s), format: 'der', type: 'spki' });

function signedParts(v) {
  const outer = parseDER(bytes(v.raw));
  const basic =
    v.protocol === 'CRL'
      ? outer
      : parseDER(outer.children[1].children[0].children[1].value);
  const tbs = basic.children[0],
    a = tbs.children;
  let nodes;
  if (v.protocol === 'CRL') {
    const entry = a[5].children[0].children;
    const extension = entry[2].children.find((e) => oidText(e.children[0]) === '2.5.29.24');
    nodes = {
      thisUpdate: a[3],
      nextUpdate: a[4],
      revokedAt: entry[1],
      invalidityDate: parseDER(extension.children.at(-1).value),
    };
  } else {
    const single = a[2].children[0].children;
    nodes = {
      producedAt: a[1],
      thisUpdate: single[2],
      nextUpdate: single[3].children[0],
    };
    if (single[1].tag === 0xa1) nodes.revokedAt = single[1].children[0];
  }
  return { basic, tbs, nodes };
}

test('CRL Time raw vectors authenticate exact signed bytes and time fields', () => {
  assert.equal(vectors.schemaVersion, 1);
  assert.equal(vectors.profile, 'crl-time-choice');
  assert.equal(vectors.cases.length, 35);
  assert.equal(new Set(vectors.cases.map((v) => v.id)).size, 35);
  assert.equal(vectors.cases.reduce((n, v) => n + v.checks.length, 0), 68);
  for (const v of vectors.cases) {
    assert.ok(['CRL', 'OCSP'].includes(v.protocol), v.id);
    const raw = bytes(v.raw),
      { basic, tbs, nodes } = signedParts(v);
    assert.equal(createHash('sha256').update(raw).digest('hex'), v.sha256, v.id);
    assert.deepEqual(tbs.raw, bytes(v.tbs), v.id);
    assert.equal(oidText(basic.children[1].children[0]), '1.2.840.10045.4.3.2', v.id);
    assert.equal(basic.children[2].value[0], 0, v.id);
    assert.deepEqual(basic.children[2].value.subarray(1), bytes(v.signature), v.id);
    assert.equal(verify('sha256', tbs.raw, key(v.signerPublicKeySPKI), bytes(v.signature)), true, v.id);
    assert.equal(
      verify('sha256', tbs.raw, key(v.publicKeySPKI), bytes(v.signature)),
      v.signatureValidForSelectedKey,
      v.id,
    );
    assert.deepEqual(Object.keys(nodes).sort(), Object.keys(v.timeNodes).sort(), v.id);
    for (const [field, n] of Object.entries(nodes)) {
      assert.equal(n.tag, v.timeNodes[field].tag, v.id + ':' + field);
      assert.deepEqual(n.value, Buffer.from(v.timeNodes[field].text, 'ascii'), v.id + ':' + field);
    }
  }
});

for (const v of vectors.cases)
  test('CRL Time raw replay ' + v.id, () => {
    for (const q of v.checks) {
      const raw = bytes(v.raw);
      const result =
        v.protocol === 'CRL'
          ? verifyCRL(raw, {
              issuer: bytes(v.issuer),
              publicKey: key(v.publicKeySPKI),
              serial: BigInt(q.serial),
              at: q.at,
              knowledgeTime: q.knowledgeTime,
            })
          : verifyOCSP(raw, {
              request: bytes(v.request),
              issuerPublicKey: key(v.publicKeySPKI),
              at: q.at,
              knowledgeTime: q.knowledgeTime,
            });
      assert.equal(Object.isFrozen(result), true);
      const expected = { ...q.expected };
      if (Object.hasOwn(expected, 'number')) {
        assert.equal(typeof result.number, 'bigint');
        expected.number = BigInt(expected.number);
      }
      assert.deepEqual(result, expected, q.id ?? v.id);
    }
  });
