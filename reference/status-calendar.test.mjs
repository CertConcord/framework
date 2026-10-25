import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { parseDER, oidText } from './core.mjs';
import { verifyCRL, verifyOCSP } from './revocation.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors/status-calendar.json', import.meta.url), 'utf8'));
function timeNode(tbs, protocol, field) {
  const a = tbs.children;
  if (protocol === 'CRL') {
    if (field === 'thisUpdate') return a[3];
    if (field === 'nextUpdate') return a[4];
    const entry = a[5].children[0].children;
    if (field === 'revokedAt') return entry[1];
    assert.equal(field, 'invalidityDate');
    const extension = entry[2].children.find(e => oidText(e.children[0]) === '2.5.29.24');
    return parseDER(extension.children.at(-1).value);
  }
  if (field === 'producedAt') return a[1];
  const single = a[2].children[0].children;
  if (field === 'thisUpdate') return single[2];
  if (field === 'nextUpdate') return single[3].children[0];
  assert.equal(field, 'revokedAt');
  return single[1].children[0];
}
for (const row of vectors.cases) test('signed status calendar: ' + row.id, () => {
  const raw = Buffer.from(row.raw, 'base64');
  const key = createPublicKey({ key: Buffer.from(row.publicKeySPKI, 'base64'), type: 'spki', format: 'der' });
  assert.equal(createHash('sha256').update(raw).digest('hex'), row.sha256);
  const root = parseDER(raw);
  const [tbs, , signature] = row.protocol === 'CRL' ? root.children : parseDER(root.children[1].children[0].children[1].value).children;
  assert.deepEqual(tbs.raw, Buffer.from(row.tbs, 'base64'));
  assert.equal(signature.value[0], 0);
  assert.deepEqual(signature.value.subarray(1), Buffer.from(row.signature, 'base64'));
  assert.equal(verify('sha256', tbs.raw, key, signature.value.subarray(1)), true);
  const time = timeNode(tbs, row.protocol, row.field);
  assert.equal(time.tag, 24);
  assert.deepEqual(time.value, Buffer.from(row.wireText, 'ascii'));
  for (const query of row.checks) {
    const result = row.protocol === 'CRL'
      ? verifyCRL(raw, { issuer: Buffer.from(row.issuer, 'base64'), publicKey: key, serial: BigInt(row.serial), at: query.at, knowledgeTime: query.knowledgeTime })
      : verifyOCSP(raw, { request: Buffer.from(row.request, 'base64'), issuerPublicKey: key, at: query.at, knowledgeTime: query.knowledgeTime });
    const actual = { ...result };
    if (typeof actual.number === 'bigint') actual.number = actual.number.toString();
    assert.deepEqual(actual, query.expected, 'at=' + query.at + ', knowledgeTime=' + query.knowledgeTime);
    assert.equal(Object.isFrozen(result), true);
  }
});
