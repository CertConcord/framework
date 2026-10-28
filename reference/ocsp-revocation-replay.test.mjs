import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { parseDER } from './core.mjs';
import { verifyOCSP } from './revocation.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors/ocsp-revocation-contract.json', import.meta.url), 'utf8'));
test('OCSP revoked-info corpus retains every selected signed case', () => {
  assert.equal(vectors.schemaVersion, 1);
  assert.equal(vectors.profile, 'ocsp-revocation-contract');
  assert.equal(vectors.cases.length, 43);
  assert.equal(new Set(vectors.cases.map(row => row.id)).size, 43);
});
for (const row of vectors.cases) test('OCSP revoked-info raw vector: ' + row.id, () => {
  const raw = Buffer.from(row.raw, 'base64'),
    publicKey = createPublicKey({ key: Buffer.from(row.publicKeySPKI, 'base64'), type: 'spki', format: 'der' }),
    [tbs, , signature] = parseDER(parseDER(raw).children[1].children[0].children[1].value).children,
    certStatus = tbs.children[2].children[0].children[1];
  assert.equal(createHash('sha256').update(raw).digest('hex'), row.sha256);
  assert.deepEqual(tbs.raw, Buffer.from(row.tbs, 'base64'));
  assert.equal(signature.value[0], 0);
  assert.deepEqual(signature.value.subarray(1), Buffer.from(row.signature, 'base64'));
  assert.equal(verify('sha256', tbs.raw, publicKey, signature.value.subarray(1)), row.signatureValid);
  assert.equal(certStatus.tag, row.certStatus.tag);
  assert.equal(certStatus.value.toString('hex'), row.certStatus.contentHex);
  const result = verifyOCSP(raw, { request: Buffer.from(row.request, 'base64'), issuerPublicKey: publicKey, ...row.query });
  assert.deepEqual(result, row.expected);
  assert(Object.isFrozen(result));
});
