import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateSync } from 'node:zlib';
import { b64u, generate, now } from './core.mjs';
import { signJWS, verifyJWT } from './jose.mjs';
import { verifyStatusList } from './openid.mjs';

function fixture() {
  const key = generate('ec'),
    at = now(),
    uri = 'https://synthetic.example/status/1',
    options = { publicKey: key.publicKey, uri, index: 0, at },
    claims = {
      iss: uri,
      sub: uri,
      iat: at,
      exp: at + 300,
      status_list: { bits: 1, lst: b64u(deflateSync(Buffer.alloc(1024))) },
    },
    token = (changes = {}, signer = key.privateKey) =>
      signJWS({ ...claims, ...changes }, signer, { typ: 'statuslist+jwt' });
  return { key, options, claims, token };
}

test('Status List distinguishes authenticated status, missing evidence and stale evidence', () => {
  const { options, claims, token } = fixture();
  assert.deepEqual(verifyStatusList(token(), options), { status: 'GOOD', overall: 'VALID' });
  assert.deepEqual(verifyStatusList(token(), { ...options, at: claims.exp }), {
    status: 'STALE',
    overall: 'INDETERMINATE',
    reason: 'STATUS_LIST_STALE',
  });
  assert.deepEqual(verifyStatusList(undefined, options), {
    status: 'UNKNOWN',
    overall: 'INDETERMINATE',
    reason: 'STATUS_LIST_MISSING',
  });
  assert.deepEqual(verifyStatusList(token(), { ...options, at: claims.iat - 1 }), {
    status: 'UNKNOWN',
    overall: 'INDETERMINATE',
    reason: 'STATUS_LIST_NOT_YET_KNOWN',
  });
  assert.deepEqual(verifyStatusList(token({ nbf: claims.iat + 1 }), options), {
    status: 'UNKNOWN',
    overall: 'INDETERMINATE',
    reason: 'STATUS_LIST_NOT_YET_KNOWN',
  });
  assert.ok(Object.isFrozen(verifyStatusList(token(), options)));
});

test('Status List preserves an established revocation even after the evidence refresh boundary', () => {
  const { options, claims, token } = fixture(),
    bytes = Buffer.alloc(1024);
  bytes[0] = 1;
  const revoked = token({ status_list: { bits: 1, lst: b64u(deflateSync(bytes)) } });
  for (const at of [claims.iat, claims.exp])
    assert.deepEqual(verifyStatusList(revoked, { ...options, at }), {
      status: 'REVOKED',
      overall: 'INVALID',
      reason: 'STATUS_LIST_REVOKED',
    });
});

test('Staleness cannot hide invalid signatures, bindings, encodings or status indices', () => {
  const { options, claims, token } = fixture(),
    stale = { ...options, at: claims.exp + 1 };
  assert.throws(
    () => verifyStatusList(token({}, generate('ec').privateKey), stale),
    /JWS_SIGNATURE/,
  );
  for (const changes of [
    { sub: 'https://other.example/status/1' },
    { iat: '0' },
    { exp: '1' },
    { exp: claims.iat },
    { exp: claims.iat + 301 },
    { nbf: '0' },
    { status_list: { ...claims.status_list, bits: 2 } },
  ])
    assert.throws(() => verifyStatusList(token(changes), stale), /STATUS_LIST_CONTEXT/);
  assert.throws(() => verifyStatusList(token(), { ...stale, index: 8192 }), /STATUS_INDEX/);
  assert.throws(
    () => verifyStatusList(token({ status_list: { bits: 1, lst: '?' } }), stale),
    /BAD_BASE64URL/,
  );
});

test('Expired authorization JWTs retain JWT_EXPIRED semantics', () => {
  const { key, options } = fixture(),
    authorization = signJWS(
      { iat: options.at - 60, exp: options.at, aud: 'synthetic' },
      key.privateKey,
    );
  assert.throws(
    () => verifyJWT(authorization, key.publicKey, { audience: 'synthetic', at: options.at }),
    { code: 'JWT_EXPIRED' },
  );
});
