import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { decodeJWS, issueSDJWT, verifySDJWT } from './jose.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/sd-jwt-hash-claims.json', import.meta.url), 'utf8'),
);
const issuerKey = createPublicKey({ key: vectors.issuerPublicJWK, format: 'jwk' });
const holderKey = createPublicKey({ key: vectors.holderPublicJWK, format: 'jwk' });
const hash = (bytes) => createHash('sha256').update(bytes).digest('base64url');
function signedClaims(compact, key, typ) {
  const parts = compact.split('.');
  assert.equal(parts.length, 3);
  const [header, payload, signature] = parts;
  assert.deepEqual(JSON.parse(Buffer.from(header, 'base64url')), { alg: 'ES256', typ });
  const input = Buffer.from(header + '.' + payload, 'ascii');
  const bytes = Buffer.from(signature, 'base64url');
  assert.equal(bytes.length, 64);
  const options = { key, dsaEncoding: 'ieee-p1363' };
  assert.equal(verify('sha256', input, options, bytes), true);
  const altered = Buffer.from(bytes);
  altered[0] ^= 1;
  assert.equal(verify('sha256', input, options, altered), false);
  assert.equal(verify('sha256', input.subarray(0, -1), options, bytes), false);
  return JSON.parse(Buffer.from(payload, 'base64url'));
}

test('SD-JWT hash corpus pins default, explicit, nested and key-binding boundaries', () => {
  assert.equal(vectors.cases.length, 39);
  assert.equal(new Set(vectors.cases.map((c) => c.id)).size, 39);
  assert.equal(vectors.cases.filter((c) => c.expectedAcceptance).length, 10);
  for (const jwk of [vectors.issuerPublicJWK, vectors.holderPublicJWK])
    assert.equal(
      ['d', 'p', 'q', 'k', 'priv'].some((name) => Object.hasOwn(jwk, name)),
      false,
    );
});

for (const vector of vectors.cases) {
  test('SD-JWT signed hash vector: ' + vector.id, () => {
    assert.equal(
      createHash('sha256').update(vector.credential, 'ascii').digest('hex'),
      vector.sha256,
    );
    const parts = vector.credential.split('~');
    const issuerJWT = parts.shift(),
      bindingJWT = parts.pop();
    const claims = signedClaims(issuerJWT, issuerKey, 'dc+sd-jwt');
    const binding = signedClaims(bindingJWT, holderKey, 'kb+jwt');
    assert.deepEqual(claims, vector.issuerPayload);
    assert.deepEqual(claims.cnf.jwk, vectors.holderPublicJWK);
    assert.deepEqual(binding, vector.keyBindingClaims);
    assert.equal(vector.policy.requireKeyBinding, true);
    if (vector.id !== 'default-hash-still-binds-hash')
      assert.equal(
        binding.sd_hash,
        hash(Buffer.from([issuerJWT, ...parts, ''].join('~'), 'ascii')),
      );
    assert.deepEqual(
      parts,
      vector.disclosures.map((d) => d.raw),
    );
    for (const d of vector.disclosures) {
      assert.equal(d.digest, hash(Buffer.from(d.raw, 'ascii')));
      assert.deepEqual(JSON.parse(Buffer.from(d.raw, 'base64url')), d.decoded);
    }
    const check = () => verifySDJWT(vector.credential, issuerKey, vector.policy);
    if (vector.expectedAcceptance)
      assert.deepEqual(JSON.parse(JSON.stringify(check().claims)), vector.expectedClaims);
    else assert.throws(check, { code: vector.expectedError });
  });
}

const freshIssuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const freshHolder = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const holderJWK = freshHolder.publicKey.export({ format: 'jwk' });
const at = Math.floor(Date.now() / 1000);
const issuerID = 'https://issuer.example.invalid';
const type = 'urn:example:sd-jwt-hash-issuer';
function issue(overrides = {}) {
  return issueSDJWT(
    {
      claims: { qualification: 'synthetic' },
      disclose: [],
      issuer: issuerID,
      holderJWK,
      vct: type,
      expiresAt: at + 3600,
      ...overrides,
    },
    freshIssuer.privateKey,
  );
}
function readIssued(issued) {
  return verifySDJWT(issued.credential, freshIssuer.publicKey, { issuer: issuerID, vct: type, at })
    .claims;
}

test('SD-JWT issuer retains an explicit SHA-256 hash claim', () => {
  const issued = issue();
  assert.equal(JSON.parse(decodeJWS(issued.credential.split('~')[0]).payload)._sd_alg, 'sha-256');
  assert.equal(readIssued(issued).qualification, 'synthetic');
});

for (const [label, options] of [
  ['visible object', { claims: { profile: { _sd_alg: 'sha-256' } } }],
  ['visible array object', { claims: { profiles: [{ _sd_alg: null }] } }],
  ['disclosed object', { claims: { profile: { _sd_alg: 'sha-256' } }, disclose: ['profile'] }],
  [
    'disclosed array object',
    { claims: { profiles: [{ _sd_alg: 'sha-512' }] }, disclose: ['profiles'] },
  ],
  ['status object', { status: { token_status_list: { _sd_alg: 'sha-256' } } }],
  ['holder JWK extension', { holderJWK: { ...holderJWK, extension: { _sd_alg: 'sha-256' } } }],
]) {
  test('SD-JWT issuer rejects nested hash metadata in ' + label, () => {
    assert.throws(() => issue(options), { code: 'SD_FORMAT' });
  });
}

for (const disclosed of [false, true]) {
  const label = disclosed ? 'disclosed' : 'visible';
  test('SD-JWT issuer checks the serialized ' + label + ' claim value', () => {
    let calls = 0;
    const profile = {
      toJSON() {
        calls++;
        return { _sd_alg: 'sha-256' };
      },
    };
    assert.throws(() => issue({ claims: { profile }, disclose: disclosed ? ['profile'] : [] }), {
      code: 'SD_FORMAT',
    });
    assert.equal(calls, 1);
  });
  test('SD-JWT issuer signs the same serialized ' + label + ' claim value it checked', () => {
    let calls = 0;
    const profile = {
      toJSON() {
        calls++;
        return calls === 1 ? { qualification: 'synthetic' } : { _sd_alg: 'sha-256' };
      },
    };
    const issued = issue({ claims: { profile }, disclose: disclosed ? ['profile'] : [] });
    assert.equal(calls, 1);
    assert.equal(readIssued(issued).profile.qualification, 'synthetic');
  });
}

test('SD-JWT issuer preserves omitted and overwritten caller hash metadata', () => {
  for (const disclosed of [false, true]) {
    const issued = issue({
      claims: {
        profile: { _sd_alg: undefined, qualification: 'synthetic' },
        _sd_alg: { unused: { _sd_alg: null } },
        _sd: [{ _sd_alg: null }],
        cnf: { _sd_alg: null },
      },
      disclose: disclosed ? ['profile'] : [],
    });
    const claims = readIssued(issued);
    assert.equal(claims.profile.qualification, 'synthetic');
    assert.equal(Object.hasOwn(claims.profile, '_sd_alg'), false);
    assert.deepEqual(JSON.parse(JSON.stringify(claims.cnf.jwk)), holderJWK);
  }
});

test('SD-JWT issuer preserves the existing depth boundary for unprovided digests', () => {
  let detail = { _sd: [hash(Buffer.from('unprovided synthetic disclosure'))] };
  let expected = {};
  for (let i = 0; i < 29; i++) {
    detail = { child: detail };
    expected = { child: expected };
  }
  const issued = issue({ claims: { detail } });
  assert.deepEqual(JSON.parse(JSON.stringify(readIssued(issued).detail)), expected);
});

for (const [label, value] of [
  ['null', null],
  ['unsupported', 'sha-384'],
]) {
  test('SD-JWT issuer rejects a serialized top-level ' + label + ' hash claim', () => {
    const claims = {
      qualification: 'synthetic',
      toJSON() {
        return { ...this, _sd_alg: value };
      },
    };
    assert.throws(() => issue({ claims }), { code: 'SD_FORMAT' });
  });
}

test('SD-JWT issuer permits the default hash in the actual serialized payload', () => {
  let calls = 0;
  const claims = {
    qualification: 'synthetic',
    toJSON() {
      calls++;
      const value = { ...this };
      delete value._sd_alg;
      return value;
    },
  };
  const issued = issue({ claims });
  assert.equal(calls, 1);
  assert.equal(
    Object.hasOwn(JSON.parse(decodeJWS(issued.credential.split('~')[0]).payload), '_sd_alg'),
    false,
  );
  assert.equal(readIssued(issued).qualification, 'synthetic');
});

test('SD-JWT default hash does not weaken required key binding or signatures', () => {
  const vector = vectors.cases.find((c) => c.id === 'default-sha256-object-disclosure');
  const parts = vector.credential.split('~');
  assert.throws(() => verifySDJWT(parts.slice(0, -1).join('~') + '~', issuerKey, vector.policy), {
    code: 'KEY_BINDING_REQUIRED',
  });
  for (const index of [0, parts.length - 1]) {
    const changed = [...parts],
      token = changed[index].split('.');
    const signature = Buffer.from(token[2], 'base64url');
    signature[0] ^= 1;
    token[2] = signature.toString('base64url');
    changed[index] = token.join('.');
    assert.throws(() => verifySDJWT(changed.join('~'), issuerKey, vector.policy), {
      code: 'JWS_SIGNATURE',
    });
  }
});
