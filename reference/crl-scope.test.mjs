import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { parseDER } from './core.mjs';
import { verifyCRL } from './revocation.mjs';
import { evaluateStatusEvidence } from './status-result.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors/crl-scope.json', import.meta.url), 'utf8'));
const key = createPublicKey({ key: Buffer.from(vectors.publicKeySPKI, 'base64'), type: 'spki', format: 'der' });
for (const row of vectors.cases) test('CRL scope admission: ' + row.id, () => {
  const raw = Buffer.from(row.raw, 'base64');
  assert.equal(createHash('sha256').update(raw).digest('hex'), row.sha256);
  const [tbs, , signature] = parseDER(raw).children;
  assert.deepEqual(tbs.raw, Buffer.from(row.tbs, 'base64'));
  assert.equal(signature.value[0], 0);
  assert.deepEqual(signature.value.subarray(1), Buffer.from(row.signature, 'base64'));
  assert.equal(verify('sha256', tbs.raw, key, signature.value.subarray(1)), row.signatureValid);
  const result = verifyCRL(raw, {
    issuer: Buffer.from(row.issuerHex, 'hex'), publicKey: key, serial: BigInt(row.serial),
    at: row.at, knowledgeTime: row.knowledgeTime,
  });
  const actual = { ...result };
  if (typeof actual.number === 'bigint') actual.number = actual.number.toString();
  assert.deepEqual(actual, row.expected);
  assert.equal(Object.isFrozen(result), true);
});

test('status evaluator keeps scoped CRLs unsupported and malformed evidence invalid', () => {
  for (const [code, overall] of [
    ['SCOPED_CRL_UNSUPPORTED', 'UNSUPPORTED'],
    ['DELTA_CRL_UNSUPPORTED', 'UNSUPPORTED'],
    ['STATUS_CRITICAL_EXTENSION', 'UNSUPPORTED'],
    ['CRL_SCOPE', 'INVALID'],
    [undefined, 'INVALID'],
  ]) {
    const result = evaluateStatusEvidence(() => { throw Object.assign(new Error('Synthetic evidence'), { code }); }, 'CRL');
    assert.deepEqual(result, { status: overall, overall, reason: code ?? 'CRL_MALFORMED' });
    assert.equal(Object.isFrozen(result), true);
  }
});
