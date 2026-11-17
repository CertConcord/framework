import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, verify, X509Certificate } from 'node:crypto';
import { parseDER } from './core.mjs';
import { parseCertificate } from './pki.mjs';
import { verifyCRL } from './revocation.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/crl-der-structure.json', import.meta.url), 'utf8'),
);
const bytes = (item) => Buffer.from(item.raw, 'base64');
const digest = (raw) => createHash('sha256').update(raw).digest('hex');
const issuerCertificate = bytes(vectors.issuerCertificate);
const issuer = parseCertificate(issuerCertificate).subject;
const publicKey = new X509Certificate(issuerCertificate).publicKey;
const crls = new Map(vectors.crls.map((row) => [row.id, row]));
const malformedTagPaths = new Map([
  ['crl-extensions-wrapper-extra-null', [0x30, 0x05]],
  ['crl-extensions-collection-context-a1', [0xa1]],
  ['revoked-certificates-set-tag', [0x31]],
  ['entry-extensions-container-context-tag', [0xa0]],
  ['entry-extension-item-context-tag', [0xa0]],
  ['entry-extension-critical-null', [0x06, 0x05, 0x04]],
  ['tbscertlist-root-context-tag', [0xa0]],
]);
const expectedQueries = new Map([
  ['canonical-good', ['GOOD', 'VALID', null]],
  ['canonical-revoked', ['REVOKED', 'INVALID', 'CRL_REVOKED']],
  ['crl-extensions-wrapper-extra-null', ['INVALID', 'INVALID', 'CRL_STRUCTURE']],
  ['crl-extensions-collection-context-a1', ['INVALID', 'INVALID', 'STATUS_EXTENSION']],
  ['revoked-certificates-set-tag', ['INVALID', 'INVALID', 'CRL_STRUCTURE']],
  ['entry-extensions-container-context-tag', ['INVALID', 'INVALID', 'CRL_STRUCTURE']],
  ['entry-extension-item-context-tag', ['INVALID', 'INVALID', 'STATUS_EXTENSION']],
  ['entry-extension-critical-null', ['INVALID', 'INVALID', 'STATUS_EXTENSION']],
  ['tbscertlist-root-context-tag', ['INVALID', 'INVALID', 'CRL_STRUCTURE']],
  ['interstitial-null-skips-revoked', ['INVALID', 'INVALID', 'CRL_STRUCTURE']],
]);
function tagPath(id, tbs) {
  if (id === 'tbscertlist-root-context-tag') return [tbs.tag];
  const revoked = tbs.children[5];
  if (id === 'revoked-certificates-set-tag') return [revoked.tag];
  const entryExtensions = revoked.children[0].children[2];
  if (id === 'entry-extensions-container-context-tag') return [entryExtensions.tag];
  if (id === 'entry-extension-item-context-tag') return [entryExtensions.children[0].tag];
  if (id === 'entry-extension-critical-null')
    return entryExtensions.children[0].children.map((child) => child.tag);
  const wrapper = tbs.children.at(-1);
  if (id === 'crl-extensions-wrapper-extra-null')
    return wrapper.children.map((child) => child.tag);
  return [wrapper.children[0].tag];
}

test('direct CRL DER structure vectors are frozen issuer-signed originals', () => {
  assert.equal(vectors.schemaVersion, 1);
  assert.equal(vectors.profile, 'rfc5280-direct-crl-der-structure');
  assert.equal(vectors.at, 1800000040);
  assert.equal(vectors.crls.length, 9);
  assert.equal(vectors.queries.length, 10);
  assert.equal(crls.size, 9);
  assert.equal(expectedQueries.size, 10);
  assert.equal(bytes(vectors.issuerCertificate).length, vectors.issuerCertificate.bytes);
  assert.equal(digest(issuerCertificate), vectors.issuerCertificate.sha256);
  for (const row of vectors.crls) {
    const raw = bytes(row);
    assert.equal(raw.length, row.bytes, row.id);
    assert.equal(digest(raw), row.sha256, row.id);
    const outer = parseDER(raw);
    assert.equal(outer.tag, 0x30, row.id);
    assert.equal(outer.children.length, 3, row.id);
    assert.equal(outer.children[1].tag, 0x30, row.id);
    assert.equal(outer.children[2].tag, 0x03, row.id);
    assert.equal(outer.children[2].value[0], 0, row.id);
    assert.equal(
      verify('sha256', outer.children[0].raw, publicKey, outer.children[2].value.subarray(1)),
      true,
      row.id,
    );
    if (malformedTagPaths.has(row.id))
      assert.deepEqual(tagPath(row.id, outer.children[0]), malformedTagPaths.get(row.id), row.id);
  }
});

test('interstitial NULL is the only added TBSCertList member', () => {
  const canonical = parseDER(bytes(crls.get('canonical'))).children[0].children;
  const malformed = parseDER(bytes(crls.get('interstitial-null-skips-revoked'))).children[0].children;
  assert.equal(canonical.length, 7);
  assert.equal(malformed.length, 8);
  assert.deepEqual(malformed[6].raw, Buffer.from('0500', 'hex'));
  for (let i = 0; i < canonical.length; i++)
    assert.deepEqual(canonical[i].raw, malformed[i < 6 ? i : i + 1].raw);
});

for (const row of vectors.queries)
  test(`direct CRL DER structure: ${row.id}`, () => {
    assert.ok(crls.has(row.crl));
    assert.deepEqual(
      [row.expected.status, row.expected.overall, row.expected.reason],
      expectedQueries.get(row.id),
    );
    const result = verifyCRL(bytes(crls.get(row.crl)), {
      issuer,
      publicKey,
      serial: BigInt(row.serial),
      at: vectors.at,
      knowledgeTime: vectors.at,
    });
    assert.equal(result.status, row.expected.status);
    assert.equal(result.overall, row.expected.overall);
    assert.equal(result.reason ?? null, row.expected.reason);
    assert(Object.isFrozen(result));
  });
