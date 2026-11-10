import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';

// Regeneration creates fresh synthetic keys in memory and saves public bytes only.
const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const holder = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const issuerPublicJWK = issuer.publicKey.export({ format: 'jwk' });
const holderPublicJWK = holder.publicKey.export({ format: 'jwk' });
const at = 1793620000;
const policy = {
  issuer: 'https://issuer.example.invalid',
  vct: 'urn:example:sd-jwt-hash-contract',
  at,
  requireKeyBinding: true,
  audience: 'https://verifier.example.invalid',
  nonce: 'synthetic-sd-jwt-hash-contract',
};
const encode = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');
const digest = (s) => createHash('sha256').update(s, 'ascii').digest('base64url');
const disclosure = (...items) => encode([randomBytes(16).toString('base64url'), ...items]);
const jwt = (claims, key, typ) => {
  const input = encode({ alg: 'ES256', typ }) + '.' + encode(claims);
  return input + '.' + sign('sha256', Buffer.from(input, 'ascii'), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
};
const cases = [];
function add(id, input = {}) {
  const payload = { iss: policy.issuer, iat: at, exp: at + 3600, vct: policy.vct, cnf: { jwk: holderPublicJWK }, ...input.payload };
  if (Object.hasOwn(input, 'algorithm')) payload._sd_alg = input.algorithm;
  const issuerJWT = jwt(payload, issuer.privateKey, 'dc+sd-jwt');
  const disclosures = input.disclosures ?? [];
  const base = [issuerJWT, ...disclosures, ''].join('~');
  const binding = { iat: at, aud: policy.audience, nonce: policy.nonce, sd_hash: digest(base), ...input.binding };
  const credential = base + jwt(binding, holder.privateKey, 'kb+jwt');
  const expectedAcceptance = !input.error;
  cases.push({ id, category: input.category ?? 'hash-claim-contract', credential, sha256: createHash('sha256').update(credential, 'ascii').digest('hex'), policy: { ...policy, ...input.policy }, expectedAcceptance, ...(input.error ? { expectedError: input.error } : { expectedClaims: { ...payload, ...input.claims } }), issuerPayload: payload, disclosures: disclosures.map((raw) => ({ raw, digest: digest(raw), decoded: JSON.parse(Buffer.from(raw, 'base64url')) })), keyBindingClaims: binding });
  if (expectedAcceptance) { delete cases.at(-1).expectedClaims._sd_alg; delete cases.at(-1).expectedClaims._sd; }
}

for (const explicit of [false, true]) {
  const algorithm = explicit ? { algorithm: 'sha-256' } : {};
  const prefix = explicit ? 'explicit-sha256' : 'default-sha256';
  add(prefix + '-clear', { ...algorithm, payload: { qualification: 'synthetic' } });
  const object = disclosure('qualification', 'synthetic');
  add(prefix + '-object-disclosure', { ...algorithm, payload: { _sd: [digest(object)] }, disclosures: [object], claims: { qualification: 'synthetic' } });
  const item = disclosure({ country: 'synthetic' });
  add(prefix + '-array-disclosure', { ...algorithm, payload: { items: [{ '...': digest(item) }] }, disclosures: [item], claims: { items: [{ country: 'synthetic' }] } });
}
for (const [id, algorithm] of [
  ['null', null], ['false', false], ['integer', 256], ['array', ['sha-256']],
  ['object', { name: 'sha-256' }], ['empty', ''], ['uppercase', 'SHA-256'],
  ['alias', 'sha256'], ['sha512', 'sha-512'],
]) add('top-level-' + id, { algorithm, error: 'SD_FORMAT', category: 'present-invalid-or-unsupported-hash' });

add('nested-ordinary-names-retained', { payload: { profile: { sd_alg: 'application data', _sd_alg_extra: null, child: [1, true, null] } } });
add('ordinary-root-and-nested-claim-values', { algorithm: 'sha-256', payload: { profile: [{ label: '_sd_alg', value: 'sha-512' }] } });
for (const [id, payload, extra] of [
  ['object', { profile: { _sd_alg: 'sha-256', qualification: 'synthetic' } }, { algorithm: 'sha-256' }],
  ['object-with-default', { profile: { _sd_alg: 'sha-256' } }, {}],
  ['object-null', { profile: { _sd_alg: null } }, {}],
  ['object-empty', { profile: { _sd_alg: '' } }, { algorithm: 'sha-256' }],
  ['object-integer', { profile: { _sd_alg: 1 } }, {}],
  ['object-false', { profile: { _sd_alg: false } }, {}],
  ['array-object', { profiles: [{ _sd_alg: 'sha-512' }] }, { algorithm: 'sha-256' }],
  ['deep-object', { profile: { deeper: [{ _sd_alg: ['sha-256'] }] } }, {}],
]) add('original-nested-' + id, { ...extra, payload, error: 'SD_FORMAT', category: 'issuer-signed-nested-hash' });

for (const [id, value, inArray] of [
  ['object', { _sd_alg: 'sha-256', qualification: 'synthetic' }, false],
  ['null', { _sd_alg: null }, false],
  ['array-object', { _sd_alg: 'sha-512' }, true],
  ['deeper-object', { child: { _sd_alg: 'sha-256' } }, false],
  ['array-value', [{ _sd_alg: 'sha-256' }], false],
]) {
  const d = inArray ? disclosure(value) : disclosure('profile', value);
  const payload = inArray ? { profiles: [{ '...': digest(d) }] } : { _sd: [digest(d)] };
  add('disclosed-nested-' + id, { algorithm: 'sha-256', payload, disclosures: [d], error: 'SD_FORMAT', category: 'selected-disclosure-placement-policy' });
}
{
  const inner = disclosure('child', { _sd_alg: 'sha-256' });
  const outer = disclosure('profile', { _sd: [digest(inner)] });
  add('recursive-disclosed-nested-object', { payload: { _sd: [digest(outer)] }, disclosures: [outer, inner], error: 'SD_FORMAT', category: 'selected-disclosure-placement-policy' });
}
for (const array of [false, true]) {
  const hidden = array ? disclosure({ _sd_alg: 'sha-256' }) : disclosure('profile', { _sd_alg: 'sha-256' });
  add('unprovided-disclosure-does-not-reveal-' + (array ? 'array-value' : 'object-value'), { payload: array ? { profiles: [{ '...': digest(hidden) }] } : { _sd: [digest(hidden)] }, claims: array ? { profiles: [] } : {}, category: 'opaque-unprovided-digest' });
}
for (const explicit of [false, true]) {
  const d = disclosure('_sd_alg', 'sha-256');
  add('disclosed-root-hash-' + (explicit ? 'explicit' : 'default'), { ...(explicit ? { algorithm: 'sha-256' } : {}), payload: { _sd: [digest(d)] }, disclosures: [d], error: 'SD_OVERWRITE', category: 'reserved-disclosure-name' });
}
for (const [id, binding, error] of [
  ['nonce', { nonce: 'different-synthetic-nonce' }, 'SD_KEY_BINDING'],
  ['audience', { aud: 'https://different.example.invalid' }, 'JWT_AUDIENCE'],
  ['hash', { sd_hash: digest('different-presentation') }, 'SD_KEY_BINDING'],
]) add('default-hash-still-binds-' + id, { payload: { qualification: 'synthetic' }, binding, error, category: 'key-binding-retained' });
{
  const intended = disclosure('qualification', 'synthetic');
  const different = disclosure('qualification', 'different');
  add('default-hash-rejects-substituted-disclosure', { payload: { _sd: [digest(intended)] }, disclosures: [different], error: 'SD_UNREFERENCED_DISCLOSURE', category: 'disclosure-digest-retained' });
}
assert.equal(cases.length, 39);
assert.equal(new Set(cases.map((c) => c.id)).size, cases.length);
const result = { schema: 'sd-jwt-hash-contract-v1', source: 'Fresh synthetic P-256 signatures; private keys exist in generator memory only.', algorithm: 'ES256', disclosureHashProfile: 'SHA-256; RFC 9901 default applies only when the top-level claim is absent.', placement: 'The verifier rejects visible nested _sd_alg, including values reconstructed from supplied disclosures. Undisclosed digests do not reveal hidden member names.', capturedAt: at, issuerPublicJWK, holderPublicJWK, cases };
writeFileSync(new URL('../reference/vectors/sd-jwt-hash-claims.json', import.meta.url), JSON.stringify(result, null, 2) + '\n');
