import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { createAuthorityResolver } from './authority-history.mjs';
import { keyID, parseDER } from './core.mjs';
import { cmsView } from './cades-fixtures.mjs';
import { verifyCAdES } from './cades.mjs';
import { validateCAdESMaterial } from './cades-validation.mjs';
import { sameDistinguishedName } from './x509-name.mjs';

const raw = readFileSync(new URL('./vectors/cades-printablestring-byte-admission.json', import.meta.url));
const vectors = JSON.parse(raw);
assert.equal(vectors.schema, 'certconcord.cades-printablestring-byte-admission.v1');
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const decode = (entry) => {
  const bytes = Buffer.from(entry.base64, 'base64');
  assert.equal(bytes.length, entry.bytes);
  assert.equal(sha(bytes), entry.sha256);
  return bytes;
};
const root = decode(vectors.root);
const crl = decode(vectors.crl);
const content = decode(vectors.content);
const cmsValid = decode(vectors.cms.validPrintable);
const cmsMalformed = decode(vectors.cms.malformedPrintable);
const leafValid = decode(vectors.leaves.validPrintableIssuer);
const leafMalformed = decode(vectors.leaves.malformedPrintableIssuer);
const rootKey = new X509Certificate(root).publicKey;
const domain = Buffer.from(vectors.domainHex, 'hex');
const scope = { ...vectors.scope, trustDomainID: domain };
const epoch = vectors.epoch;
const cmsCertificates = cmsView(cmsValid).certificates.map((node) => node.raw);
assert(cmsCertificates.some((cert) => cert.equals(root)));
const authorityResolver = createAuthorityResolver({
  trustDomainID: domain,
  authorities: [{
    mode: 'CERTIFICATE', certificate: root,
    knownAt: epoch - 100, validFrom: epoch - 100, validUntil: epoch + 100000,
    roles: ['ISSUER', 'STATUS_AUTHORITY'], scopes: [scope],
    status: { authorityID: keyID(rootKey), trustDomainID: domain, scope: 'AUTHORITY',
      status: 'GOOD', publishedAt: epoch - 100, nextUpdate: epoch + 100000 },
  }],
});
const policy = {
  trustedRoots: [root], authorityResolver, scope,
  algorithmDeadlines: { '1.2.840.10045.4.3.2': epoch + 100000 },
  hashDeadlines: { '2.16.840.1.101.3.4.2.1': epoch + 100000,
    '2.16.840.1.101.3.4.2.3': epoch + 100000 },
  keyDeadlines: Object.fromEntries(cmsCertificates.map((cert) =>
    [keyID(new X509Certificate(cert).publicKey).toString('hex'), epoch + 100000])),
  timestampPolicies: ['1.3.6.1.4.1.55555.91.1'],
  currentMaterial: { certificates: cmsCertificates, crls: [crl] },
};
const verdict = (result) => ({ overall: result.overall, reason: result.reason });
const issuerName = (certificate) => {
  const tbs = parseDER(certificate).children[0].children;
  return tbs[tbs[0].tag === 0xa0 ? 3 : 2].raw;
};
const subjectName = (certificate) => {
  const tbs = parseDER(certificate).children[0].children;
  return tbs[tbs[0].tag === 0xa0 ? 5 : 4].raw;
};
const highBitPair = (valid, malformed) => {
  assert.equal(valid.length, malformed.length);
  const changed = [...valid.keys()].filter((i) => valid[i] !== malformed[i]);
  assert.equal(changed.length, 1);
  assert.equal(valid[changed[0]], 0x43);
  assert.equal(malformed[changed[0]], 0xc3);
};

test('frozen signed CMS PrintableString identifier rejects original high-bit octet', () => {
  const validView = cmsView(cmsValid);
  const malformedView = cmsView(cmsMalformed);
  highBitPair(validView.fields[1].children[0].raw, malformedView.fields[1].children[0].raw);
  assert.deepEqual(validView.fields.slice(3, 6).map((node) => node.raw),
    malformedView.fields.slice(3, 6).map((node) => node.raw));
  const input = { content, minimumLevel: 'B', validationTime: epoch + 40,
    knowledgeTime: epoch + 40, policy };
  assert.deepEqual(verdict(verifyCAdES(cmsValid, input)), vectors.expected.cmsValid);
  assert.deepEqual(verdict(verifyCAdES(cmsMalformed, input)), vectors.expected.cmsMalformed);
});

test('frozen issuer-signed certificate cannot select root through malformed PrintableString', () => {
  highBitPair(issuerName(leafValid), issuerName(leafMalformed));
  for (const certificate of [leafValid, leafMalformed])
    assert.equal(new X509Certificate(certificate).verify(rootKey), true);
  assert.equal(sameDistinguishedName(issuerName(leafValid), subjectName(root)), true);
  assert.throws(() => sameDistinguishedName(issuerName(leafMalformed), issuerName(leafValid)),
    { code: 'CADES_ISSUER_NAME_ENCODING' });
  const input = { certificates: [root], crls: [crl], purpose: 'SIGNER',
    stateTime: epoch + 40, knowledgeTime: epoch + 40, policy };
  assert.deepEqual(verdict(validateCAdESMaterial({ ...input, certificate: leafValid })),
    vectors.expected.rootValid);
  assert.deepEqual(verdict(validateCAdESMaterial({ ...input, certificate: leafMalformed })),
    vectors.expected.rootMalformed);
});
