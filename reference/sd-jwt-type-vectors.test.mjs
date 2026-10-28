import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { verifySDJWT } from './jose.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/sd-jwt-type-claims.json', import.meta.url), 'utf8'),
);
const issuerKey = createPublicKey({ key: vectors.issuerPublicJWK, format: 'jwk' });
const holderKey = createPublicKey({ key: vectors.holderPublicJWK, format: 'jwk' });
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('base64url');

// Verify the original compact bytes before invoking the reference implementation.
function signedClaims(compact, key, typ) {
  const parts = compact.split('.');
  assert.equal(parts.length, 3);
  const [header, payload, signature] = parts;
  assert.deepEqual(JSON.parse(Buffer.from(header, 'base64url')), { alg: 'ES256', typ });
  const bytes = Buffer.from(header + '.' + payload);
  const sig = Buffer.from(signature, 'base64url');
  const options = { key, dsaEncoding: 'ieee-p1363' };
  assert.equal(sig.length, 64);
  assert.equal(verify('sha256', bytes, options, sig), true);
  const changedSignature = Buffer.from(sig);
  changedSignature[0] ^= 1;
  assert.equal(verify('sha256', bytes, options, changedSignature), false);
  assert.equal(verify('sha256', bytes.subarray(0, -1), options, sig), false);
  return JSON.parse(Buffer.from(payload, 'base64url'));
}

test('SD-JWT type corpus retains all positive and negative cases', () => {
  assert.equal(vectors.cases.length, 25);
  assert.equal(new Set(vectors.cases.map((v) => v.id)).size, 25);
  assert.equal(vectors.cases.filter((v) => v.expectedAcceptance).length, 7);
});

for (const vector of vectors.cases) {
  test('SD-JWT signed type vector: ' + vector.id, () => {
    const parts = vector.credential.split('~');
    const issuerJWT = parts.shift();
    const bindingJWT = parts.pop();
    const claims = signedClaims(issuerJWT, issuerKey, 'dc+sd-jwt');
    const binding = signedClaims(bindingJWT, holderKey, 'kb+jwt');
    assert.deepEqual(claims.cnf.jwk, vectors.holderPublicJWK);
    assert.equal(binding.sd_hash, sha256([issuerJWT, ...parts, ''].join('~')));
    assert.equal(vector.policy.requireKeyBinding, true);
    const check = () => verifySDJWT(vector.credential, issuerKey, vector.policy);
    if (vector.expectedAcceptance) {
      assert.deepEqual(JSON.parse(JSON.stringify(check().claims)), vector.expectedClaims);
    } else {
      assert.throws(check, { code: vector.expectedError });
    }
  });
}
