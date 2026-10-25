import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { parseDER } from './core.mjs';
import { verifyOCSP } from './revocation.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors/ocsp-null-status.json', import.meta.url), 'utf8'));
for (const row of vectors.cases) test('OCSP NULL status encoding: ' + row.id, () => {
  const raw = Buffer.from(row.raw, 'base64');
  const key = createPublicKey({ key: Buffer.from(row.publicKeySPKI, 'base64'), type: 'spki', format: 'der' });
  assert.equal(createHash('sha256').update(raw).digest('hex'), row.sha256);
  const [tbs, , signature] = parseDER(parseDER(raw).children[1].children[0].children[1].value).children;
  assert.deepEqual(tbs.raw, Buffer.from(row.tbs, 'base64'));
  assert.equal(signature.value[0], 0);
  assert.deepEqual(signature.value.subarray(1), Buffer.from(row.signature, 'base64'));
  assert.equal(verify('sha256', tbs.raw, key, signature.value.subarray(1)), row.signatureValid);
  const certStatus = tbs.children[2].children[0].children[1];
  assert.equal(certStatus.tag, row.certStatus.tag);
  assert.equal(certStatus.value.toString('hex'), row.certStatus.contentHex);
  const result = verifyOCSP(raw, { request: Buffer.from(row.request, 'base64'), issuerPublicKey: key, at: row.at, knowledgeTime: row.knowledgeTime });
  assert.deepEqual(result, row.expected);
  assert.equal(Object.isFrozen(result), true);
});
