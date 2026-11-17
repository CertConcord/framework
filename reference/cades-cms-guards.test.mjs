import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { parseDER } from './core.mjs';
import { inspectAdESSignature } from './ades-cms.mjs';

const vectorBytes = readFileSync(new URL('./vectors/cades-cms-guards.json', import.meta.url));
assert.equal(createHash('sha256').update(vectorBytes).digest('hex'),
  '4eed46cb62dd88021706909c56f9300057b8dfd3aadd6506313a7d7064cbe5b7');
const frozen = JSON.parse(vectorBytes);
assert.equal(frozen.schema, 'certconcord.cms-guards.v1');
const load = (name) => {
  const entry = frozen.vectors[name];
  const raw = Buffer.from(entry.derBase64, 'base64');
  assert.equal(raw.length, entry.bytes);
  assert.equal(createHash('sha256').update(raw).digest('hex'), entry.sha256);
  return raw;
};
const [positive, negative] = ['digestExtraSha512', 'digestMalformedUnused'].map(load);
const signedData = (cms) => parseDER(cms).children[1].children[0].children;

test('frozen CMS pair changes only unsigned digestAlgorithms while retaining the signer', () => {
  const a = signedData(positive), b = signedData(negative);
  assert.equal(a.length, b.length);
  for (let i = 0; i < a.length; i++) {
    if (i !== 1) assert.deepEqual(a[i].raw, b[i].raw);
  }
  assert.equal(a[1].children.length, 2);
  assert.equal(b[1].children.length, 2);
  assert.equal(a[1].children[1].children[0].tag, 0x06);
  assert.equal(b[1].children[1].children[0].tag, 0x0c);
});

test('an additional valid unused SHA-512 DigestAlgorithmIdentifier remains valid', () => {
  const verdict = inspectAdESSignature(positive, { profile: 'CADES' });
  assert.equal(verdict.overall, 'VALID');
  assert.equal(verdict.reason, 'CADES_VALID');
});

test('a malformed unused DigestAlgorithmIdentifier is rejected', () => {
  const verdict = inspectAdESSignature(negative, { profile: 'CADES' });
  assert.equal(verdict.overall, 'INVALID');
  assert.equal(verdict.reason, 'EXPECTED_OID');
});

const issuerVectors = ['essOnlyIssuer', 'essExtraDns'].map(load);

test('signed ESS IssuerSerial with only the certificate issuer directoryName is valid', () => {
  const verdict = inspectAdESSignature(issuerVectors[0], { profile: 'CADES' });
  assert.equal(verdict.overall, 'VALID');
  assert.equal(verdict.reason, 'CADES_VALID');
});

test('signed ESS IssuerSerial with an extra dNSName is rejected', () => {
  const verdict = inspectAdESSignature(issuerVectors[1], { profile: 'CADES' });
  assert.equal(verdict.overall, 'INVALID');
  assert.equal(verdict.reason, 'CADES_ESS_ISSUER_SERIAL');
});

const nameVectors = ['issuerEquivalent', 'issuerDifferent'].map(load);

test('semantically equal issuer name in CMS SignerInfo identifies the signing certificate', () => {
  const verdict = inspectAdESSignature(nameVectors[0], { profile: 'CADES' });
  assert.equal(verdict.overall, 'VALID');
  assert.equal(verdict.reason, 'CADES_VALID');
});

test('genuinely unequal issuer name in CMS SignerInfo cannot identify the certificate', () => {
  const verdict = inspectAdESSignature(nameVectors[1], { profile: 'CADES' });
  assert.equal(verdict.overall, 'INVALID');
  assert.equal(verdict.reason, 'CADES_SIGNING_CERTIFICATE_BINDING');
});
