import assert from 'node:assert/strict';
import { createHash, verify as verifySignature, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { keyID, parseDER, intValue } from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { verifyCAdES } from './cades.mjs';

const rawVectors = readFileSync(new URL('./vectors/cades-crl-admission.json', import.meta.url));
assert.equal(createHash('sha256').update(rawVectors).digest('hex'),
  '0a32ea0816bdcba427e8e4b48b9267fd6771b0b24029c1dd463423f048ead83b');
const vectors = JSON.parse(rawVectors);
assert.equal(vectors.schema, 'certconcord.cades-crl-admission.v1');
const decode = (entry) => {
  const bytes = Buffer.from(entry.derBase64, 'base64');
  assert.equal(bytes.length, entry.bytes);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256);
  return bytes;
};
const fixture = Object.fromEntries(Object.entries(vectors.fixture).map(([name, value]) => [name, decode(value)]));
const crls = Object.fromEntries(Object.entries(vectors.crls).map(([name, value]) => [name, decode(value)]));
const tbs = (name) => parseDER(crls[name]).children[0];
const rootPublicKey = new X509Certificate(fixture.root).publicKey;

test('all five frozen CRLs have valid issuer signatures over their exact TBS bytes', () => {
  for (const [name, raw] of Object.entries(crls)) {
    const parsed = parseDER(raw);
    assert.equal(verifySignature('sha256', parsed.children[0].raw, rootPublicKey,
      parsed.children[2].value.subarray(1)), true, name);
  }
});

test('empty revokedCertificates changes only the optional list within TBS', () => {
  const absent = tbs('absentList').children, empty = tbs('emptyList').children;
  assert.equal(absent.length, 6);
  assert.equal(empty.length, 7);
  for (let i = 0; i < 5; i++) assert.deepEqual(absent[i].raw, empty[i].raw);
  assert.equal(empty[5].raw.toString('hex'), '3000');
  assert.deepEqual(absent[5].raw, empty[6].raw);
});

test('empty CRL entry Extensions changes only the unrelated revoked record', () => {
  const absent = tbs('absentEntryExtensions').children;
  const empty = tbs('emptyEntryExtensions').children;
  assert.equal(absent.length, 7);
  assert.equal(empty.length, 7);
  for (let i = 0; i < 7; i++) if (i !== 5) assert.deepEqual(absent[i].raw, empty[i].raw);
  const a = absent[5].children[0].children, b = empty[5].children[0].children;
  assert.equal(a.length, 2);
  assert.equal(b.length, 3);
  assert.equal(intValue(a[0]), 777n);
  for (let i = 0; i < 2; i++) assert.deepEqual(a[i].raw, b[i].raw);
  assert.equal(b[2].raw.toString('hex'), '3000');
  const nonempty = tbs('nonemptyEntryExtensions').children[5].children[0].children;
  assert.equal(nonempty.length, 3);
  assert.equal(nonempty[2].children.length, 1);
});

const domain = Buffer.alloc(32, 0x91);
const scope = { trustDomainID: domain, issuerID: 'cades-fixture', representation: 'X509' };
const deadline = vectors.epoch + 100000;
const authorityResolver = createAuthorityResolver({ trustDomainID: domain,
  authorities: [{ mode: 'CERTIFICATE', certificate: fixture.root,
    knownAt: vectors.epoch - 100, validFrom: vectors.epoch - 100, validUntil: deadline,
    roles: ['ISSUER', 'STATUS_AUTHORITY'], scopes: [scope],
    status: { authorityID: keyID(rootPublicKey), trustDomainID: domain,
      scope: 'AUTHORITY', status: 'GOOD', publishedAt: vectors.epoch - 100,
      nextUpdate: deadline } }] });
const policy = (crl) => ({ trustedRoots: [fixture.root], authorityResolver, scope,
  algorithmDeadlines: { '1.2.840.10045.4.3.2': deadline },
  hashDeadlines: { '2.16.840.1.101.3.4.2.1': deadline,
    '2.16.840.1.101.3.4.2.3': deadline },
  keyDeadlines: Object.fromEntries([fixture.root, fixture.signer].map((cert) => [
    keyID(new X509Certificate(cert).publicKey).toString('hex'), deadline])),
  timestampPolicies: ['1.3.6.1.4.1.55555.91.1'],
  currentMaterial: { certificates: [fixture.signer, fixture.root], crls: [crl] } });

for (const [name, overall, reason] of [
  ['absentList', 'VALID', 'CADES_VALID'],
  ['emptyList', 'INVALID', 'CADES_CRL_REVOKED_LIST_EMPTY'],
  ['absentEntryExtensions', 'VALID', 'CADES_VALID'],
  ['emptyEntryExtensions', 'INVALID', 'CADES_EXTENSION_STRUCTURE'],
  ['nonemptyEntryExtensions', 'VALID', 'CADES_VALID'],
]) test(`full CAdES rejects only malformed CRL admission: ${name}`, () => {
  const result = verifyCAdES(fixture.cms, { content: fixture.content,
    minimumLevel: 'B', validationTime: vectors.epoch + 40,
    knowledgeTime: vectors.epoch + 40, policy: policy(crls[name]) });
  assert.equal(result.overall, overall, JSON.stringify(result.checks));
  assert.equal(result.reason, reason, JSON.stringify(result.checks));
  if (overall === 'VALID') assert.equal(result.verifiedLevel, 'B');
});
