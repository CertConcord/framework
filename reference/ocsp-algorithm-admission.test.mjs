import test from 'node:test';
import assert from 'node:assert/strict';
import { constants, createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseDER } from './core.mjs';
import { verifyOCSP } from './revocation.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors/ocsp-algorithm-admission.json', import.meta.url)));
const sha256 = data => createHash('sha256').update(data).digest('hex');
function signatureParts(raw) {
  const response = parseDER(raw);
  const basic = parseDER(response.children[1].children[0].children[1].value);
  return { tbs: basic.children[0].raw, signature: basic.children[2].value.subarray(1) };
}

test('OCSP algorithm vectors retain the frozen signed originals', () => {
  assert.equal(vectors.schemaVersion, 1);
  assert.equal(vectors.profile, 'ocsp-algorithm-admission');
  assert.deepEqual(vectors.groups.map(g => g.id), ['rsa-response-signature', 'sha256-certid']);
  const [rsa, cert] = vectors.groups;
  assert.equal(sha256(Buffer.from(rsa.request, 'base64')), '07885296295c2208956f2054cb95d479283de6b6e28c426ca8a67308df9893f0');
  assert.equal(sha256(Buffer.from(rsa.issuerPublicKeySPKI, 'base64')), '9dfa107acce62f4f2ff8ee224310bbc4e7668d18d9affac5793ca58f43f20ef9');
  assert.equal(rsa.cases[0].sha256, 'bede41006af1e9761e32bacd42291dd5cd8c3420f49030717a481c6372c52827');
  assert.equal(rsa.cases[4].sha256, 'a7ef4dad7f1810aad3f231763a1892930507ec9149385a398717e8bea972da63');
  assert.equal(sha256(Buffer.from(cert.request, 'base64')), 'e499dc155de22e19a6f38c2a2e28d68857f6b1ff8952c075f2847b0760d6df91');
  assert.equal(cert.cases[0].sha256, 'ab61af042bba4172113cb840a2a42420e3b2d3ddb14626d5bd6e4b63bfb3b3d7');
  assert.equal(cert.cases[1].sha256, 'f246808b8cdf6b49fde669e798e074a8b30cea066ea617873624bf0a95656017');
  const rsaKey = createPublicKey({key: Buffer.from(rsa.issuerPublicKeySPKI, 'base64'), format: 'der', type: 'spki'});
  const positive = signatureParts(Buffer.from(rsa.cases[0].raw, 'base64'));
  const bitFlip = signatureParts(Buffer.from(rsa.cases[4].raw, 'base64'));
  assert.deepEqual(positive.tbs, bitFlip.tbs);
  assert.equal(verify('sha256', positive.tbs, {key: rsaKey, padding: constants.RSA_PKCS1_PADDING}, positive.signature), true);
  assert.equal(verify('sha256', bitFlip.tbs, {key: rsaKey, padding: constants.RSA_PKCS1_PADDING}, bitFlip.signature), false);
  const certKey = createPublicKey({key: Buffer.from(cert.issuerPublicKeySPKI, 'base64'), format: 'der', type: 'spki'});
  for (const row of cert.cases) {
    const { tbs, signature } = signatureParts(Buffer.from(row.raw, 'base64'));
    assert.equal(verify(null, tbs, certKey, signature), true, row.id);
  }
});

for (const group of vectors.groups) {
  const request = Buffer.from(group.request, 'base64');
  const issuerPublicKey = createPublicKey({key: Buffer.from(group.issuerPublicKeySPKI, 'base64'), format: 'der', type: 'spki'});
  for (const row of group.cases) test('OCSP algorithm admission: ' + row.id, () => {
    const raw = Buffer.from(row.raw, 'base64');
    assert.equal(sha256(raw), row.sha256);
    const result = verifyOCSP(raw, {request, issuerPublicKey, at: vectors.at, knowledgeTime: vectors.at});
    for (const [field, value] of Object.entries(row.expected)) assert.equal(result[field], value, field);
  });
}
