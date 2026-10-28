import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { parseDER } from './core.mjs';
import { verifyCRL } from './revocation.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors/crl-reason-codes.json', import.meta.url), 'utf8'));
const publicKey = createPublicKey({
  key: Buffer.from(vectors.publicKeySPKI, 'base64'), type: 'spki', format: 'der',
});
const issuer = Buffer.from(vectors.issuerDER, 'base64');
const options = {
  issuer, publicKey, at: vectors.at, knowledgeTime: vectors.knowledgeTime,
  minNumber: BigInt(vectors.minNumber),
};
const normalize = value => JSON.parse(JSON.stringify(value,
  (key, item) => typeof item === 'bigint' ? item.toString() : item));

for (const row of vectors.cases) for (const query of row.queries)
  test('CRL reason admission: ' + row.id + ' / serial ' + query.serial, () => {
    const raw = Buffer.from(row.raw, 'base64');
    assert.equal(createHash('sha256').update(raw).digest('hex'), row.sha256);
    const [tbs, , signature] = parseDER(raw).children;
    assert.deepEqual(tbs.raw, Buffer.from(row.tbs, 'base64'));
    assert.equal(signature.tag, 3);
    assert.equal(signature.value[0], 0);
    assert.deepEqual(signature.value.subarray(1), Buffer.from(row.signature, 'base64'));
    assert.equal(verify(null, tbs.raw, publicKey, signature.value.subarray(1)), true);
    const result = verifyCRL(raw, { ...options, serial: BigInt(query.serial) });
    assert.deepEqual(normalize(result), query.expected);
    assert.equal(Object.isFrozen(result), true);
  });

test('CRL reason vectors do not admit a changed signature', () => {
  const raw = Buffer.from(vectors.cases[0].raw, 'base64');
  raw[raw.length - 1] ^= 1;
  const [tbs, , signature] = parseDER(raw).children;
  assert.equal(verify(null, tbs.raw, publicKey, signature.value.subarray(1)), false);
  assert.deepEqual(verifyCRL(raw, { ...options, serial: 43n }), {
    status: 'INVALID', overall: 'INVALID', reason: 'CRL_SIGNATURE',
  });
});
