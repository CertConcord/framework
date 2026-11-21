import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { createAuthorityResolver } from './authority-history.mjs';
import { inspectAdESSignature } from './ades-cms.mjs';
import { keyID } from './core.mjs';
import { O, epoch } from './cades-fixtures.mjs';
import { loadPAdES, pdfSignatures } from './pades-fixtures.mjs';

const raw = readFileSync(new URL('./vectors/pades-signed-page-text-admission.json', import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(sha(raw), '63bc76b1567566c44fc5de085578fb803bb5b281f0abf19c837fc3f946893a61');
const vectors = JSON.parse(raw);
assert.equal(vectors.schema, 'certconcord.pades-signed-page-text-admission.v1');
const load = entry => {
  const bytes = Buffer.from(entry.base64, 'base64');
  assert.equal(bytes.length, entry.bytes);
  assert.equal(sha(bytes), entry.sha256);
  return bytes;
};
const rootDER = load(vectors.fixture.rootCertificate);
const signerDER = load(vectors.fixture.signerCertificate);
const crl = load(vectors.fixture.crl);
const root = new X509Certificate(rootDER);
const signer = new X509Certificate(signerDER);
const domain = Buffer.alloc(32, 0x91);
const scope = { trustDomainID: domain, issuerID: 'cades-fixture', representation: 'X509' };
const authorityResolver = createAuthorityResolver({
  trustDomainID: domain,
  authorities: [{
    mode: 'CERTIFICATE', certificate: rootDER,
    knownAt: epoch - 100, validFrom: epoch - 100, validUntil: epoch + 100000,
    roles: ['ISSUER', 'STATUS_AUTHORITY'], scopes: [scope],
    status: {
      authorityID: keyID(root.publicKey), trustDomainID: domain,
      scope: 'AUTHORITY', status: 'GOOD',
      publishedAt: epoch - 100, nextUpdate: epoch + 100000,
    },
  }],
});
const policy = {
  trustedRoots: [rootDER], authorityResolver, scope,
  algorithmDeadlines: { [O.es256]: epoch + 100000 },
  hashDeadlines: { [O.sha256]: epoch + 100000, [O.sha512]: epoch + 100000 },
  keyDeadlines: {
    [keyID(root.publicKey).toString('hex')]: epoch + 100000,
    [keyID(signer.publicKey).toString('hex')]: epoch + 100000,
  },
  timestampPolicies: [O.policy],
  currentMaterial: { certificates: [signerDER, rootDER], crls: [crl] },
};
const api = await loadPAdES();

test('frozen signed page text vector issuer signatures are valid', () => {
  assert(root.verify(root.publicKey));
  assert(signer.verify(root.publicKey));
});

for (const pair of vectors.signedPDF) {
  test(`frozen signed page text: ${pair.id}`, async () => {
    for (const label of ['positive', 'negative']) {
      const entry = pair[label];
      const pdf = load(entry.pdf);
      assert(pdf.includes(Buffer.from(entry.stream)), `${pair.id} ${label} content stream`);
      const signatures = pdfSignatures(pdf);
      assert.equal(signatures.length, 1);
      const [{ cms, byteRange }] = signatures;
      assert.deepEqual(byteRange, entry.byteRange);
      assert.equal(sha(cms), entry.cmsSha256);
      const [start, firstLength, secondStart, secondLength] = byteRange;
      const content = Buffer.concat([
        pdf.subarray(start, start + firstLength),
        pdf.subarray(secondStart, secondStart + secondLength),
      ]);
      assert.equal(sha(content), entry.signedContentSha256);
      assert.equal(inspectAdESSignature(cms, { content, profile: 'PADES' }).overall, 'VALID');
      const result = await api.verifyPAdES(pdf, {
        minimumLevel: 'B', validationTime: epoch + 40, knowledgeTime: epoch + 40, policy,
      });
      assert.deepEqual({ overall: result.overall, reason: result.reason,
        verifiedLevel: result.verifiedLevel ?? null }, entry.expected, `${pair.id} ${label}`);
    }
  });
}
