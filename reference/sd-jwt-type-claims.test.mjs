import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { issueSDJWT, verifySDJWT, signJWS, decodeJWS } from './jose.mjs';

const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const holder = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const holderJWK = holder.publicKey.export({ format: 'jwk' });
const type = 'urn:example:qualification';
const alias = 'urn:example:additional-qualification';
const issuerID = 'https://issuer.example';
const at = Math.floor(Date.now() / 1000);
const digest = (value) => createHash('sha256').update(value).digest('base64url');
const disclosure = (name, value) =>
  Buffer.from(JSON.stringify(['synthetic-disclosure-salt', name, value])).toString('base64url');

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
    issuer.privateKey,
  );
}
function raw(changes = {}, disclosures = []) {
  const token = signJWS(
    {
      iss: issuerID,
      iat: at,
      exp: at + 3600,
      vct: type,
      cnf: { jwk: holderJWK },
      _sd_alg: 'sha-256',
      ...changes,
    },
    issuer.privateKey,
    { typ: 'dc+sd-jwt' },
  );
  return [token, ...disclosures, ''].join('~');
}
function verify(credential, policy = {}) {
  return verifySDJWT(credential, issuer.publicKey, { issuer: issuerID, at, ...policy });
}

test('SD-JWT VC without disclosures omits _sd and has one terminal separator', () => {
  const issued = issue();
  assert.equal(issued.disclosures.length, 0);
  assert.equal(issued.credential.split('~').length, 2);
  const signedClaims = JSON.parse(decodeJWS(issued.credential.split('~')[0]).payload);
  assert.equal(Object.hasOwn(signedClaims, '_sd'), false);
  assert.equal(verify(issued.credential, { vct: type }).claims.qualification, 'synthetic');
});

for (const [label, value] of [
  ['missing', undefined],
  ['empty', ''],
  ['null', null],
  ['number', 1],
  ['object', { id: type }],
]) {
  test(`SD-JWT VC rejects ${label} primary type even without an expected-type policy`, () => {
    assert.throws(() => issue({ vct: value }), { code: 'SD_FORMAT' });
    assert.throws(() => verify(raw({ vct: value })), { code: 'SD_FORMAT' });
  });
}

for (const [label, value] of [
  ['null', null],
  ['empty array', []],
  ['string', alias],
  ['nonstring member', [1]],
  ['empty member', ['']],
  ['nested member', [[alias]]],
  ['primary type member', [type]],
]) {
  test(`SD-JWT VC rejects additional types containing ${label}`, () => {
    assert.throws(
      () =>
        issue({
          claims: { qualification: 'synthetic', aka_vcts: value },
          disclose: ['qualification'],
        }),
      { code: 'SD_FORMAT' },
    );
    assert.throws(() => verify(raw({ aka_vcts: value })), { code: 'SD_FORMAT' });
  });
}

test('SD-JWT VC retains exact additional types, duplicates and case-distinct identifiers', () => {
  const aliases = [alias, alias, type.toUpperCase()];
  const issued = issue({
    claims: { aka_vcts: aliases, qualification: 'synthetic' },
    disclose: ['qualification'],
  });
  const result = verify(issued.credential, { vct: type });
  assert.deepEqual(result.claims.aka_vcts, aliases);
  assert.equal(result.claims.qualification, 'synthetic');
});

test('SD-JWT VC aliases do not replace an expected primary type', () => {
  assert.throws(() => verify(raw({ vct: 'urn:example:other', aka_vcts: [type] }), { vct: type }), {
    code: 'SD_FORMAT',
  });
});

test('SD-JWT VC issuer refuses to selectively disclose additional types', () => {
  assert.throws(() => issue({ claims: { aka_vcts: [alias] }, disclose: ['aka_vcts'] }), {
    code: 'SD_DISCLOSURE_NAMES',
  });
});

test('SD-JWT VC reader rejects a supplied additional-type disclosure', () => {
  const d = disclosure('aka_vcts', [alias]);
  assert.throws(() => verify(raw({ _sd: [digest(d)] }, [d])), { code: 'SD_FORMAT' });
});

test('SD-JWT VC reader cannot reconstruct its required primary type from a disclosure', () => {
  const d = disclosure('vct', type);
  assert.throws(() => verify(raw({ vct: undefined, _sd: [digest(d)] }, [d])), {
    code: 'SD_FORMAT',
  });
});

test('SD-JWT VC reader rejects visible selective-disclosure placeholders in additional types', () => {
  const d = Buffer.from(JSON.stringify(['synthetic-array-salt', alias])).toString('base64url');
  const changes = { aka_vcts: [{ '...': digest(d) }] };
  assert.throws(() => verify(raw(changes, [d])), { code: 'SD_FORMAT' });
  assert.throws(() => verify(raw(changes)), { code: 'SD_FORMAT' });
});

test('SD-JWT VC preserves private nested names and ordinary selective disclosure', () => {
  const value = { vct: 'private application data', aka_vcts: null };
  const d = disclosure('private_extension', value);
  const result = verify(raw({ _sd: [digest(d)] }, [d]));
  assert.equal(result.claims.private_extension.vct, value.vct);
  assert.equal(result.claims.private_extension.aka_vcts, null);
});

test('SD-JWT VC does not infer a hidden claim name from an unprovided digest', () => {
  const d = disclosure('private_extension', 'synthetic');
  const result = verify(raw({ _sd: [digest(d)] }));
  assert.equal(Object.hasOwn(result.claims, 'private_extension'), false);
  assert.equal(Object.hasOwn(result.claims, 'aka_vcts'), false);
});
