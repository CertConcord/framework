import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { inspectAdESSignature } from './ades-cms.mjs';
import { ALG, keyID } from './core.mjs';
import { OID } from './pki.mjs';
import { loadPAdES, pdfSignatures } from './pades-fixtures.mjs';

const raw = readFileSync(new URL('./vectors/pades-line-annotation-admission.json', import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(sha(raw), 'f89b784fd86236c7c903f416c9015456240eeb271eb9c2e446c1ea20c3de1f47');
const vectors = JSON.parse(raw);
assert.equal(vectors.schema, 'certconcord.pades-line-annotation-admission.v1');
assert.equal(vectors.baseMain, '891ff4ed5ad92df67b7403c161324963ea7244ac');
assert.equal(vectors.officialIso32000_1Sha256,
  '9de0ca9e8570d6209e8bd48a355be8eb6ec376acfc3fc3ae97cd8730351417ff');
const load = entry => {
  const bytes = Buffer.from(entry.base64, 'base64');
  assert.equal(bytes.length, entry.bytes);
  assert.equal(sha(bytes), entry.sha256);
  return bytes;
};
const rootDER = load(vectors.fixture.rootCertificate);
const signerDER = load(vectors.fixture.signerCertificate);
const crlDER = load(vectors.fixture.crl);
const root = new X509Certificate(rootDER), signer = new X509Certificate(signerDER);
const at = Date.parse('2026-11-17T12:00:00Z') / 1000;
const deadline = at + 86400 * 30;
const scope = { trustDomainID: Buffer.alloc(32, 0xa5), issuerID: 'labs-synthetic-external-ca', representation: 'X509' };
const policy = {
  trustedRoots: [rootDER], scope,
  authorityResolver: ({ certificate, role, scope: requested, stateTime, knowledgeTime }) =>
    Buffer.isBuffer(certificate) && certificate.equals(rootDER) &&
    ['ISSUER', 'STATUS_AUTHORITY'].includes(role) &&
    requested.issuerID === scope.issuerID &&
    Buffer.from(requested.trustDomainID).equals(scope.trustDomainID) &&
    stateTime <= knowledgeTime && knowledgeTime === at
      ? { overall: 'VALID', reason: 'SYNTHETIC_PINNED_AUTHORITY', validUntil: deadline }
      : { overall: 'INVALID', reason: 'SYNTHETIC_AUTHORITY_MISMATCH' },
  algorithmDeadlines: { [ALG.ec.oid]: deadline },
  hashDeadlines: { [OID.sha256]: deadline, [OID.sha512]: deadline },
  keyDeadlines: Object.fromEntries([root.publicKey, signer.publicKey]
    .map(key => [keyID(key).toString('hex'), deadline])),
  currentMaterial: { certificates: [rootDER, signerDER], crls: [crlDER] },
  timestampPolicies: [],
};
const api = await loadPAdES();

test('frozen Line vector issuer and signer signatures are valid', () => {
  assert(root.verify(root.publicKey));
  assert(signer.verify(root.publicKey));
});

for (const pair of vectors.signedPDF) {
  test(`signed Line annotation field admission: ${pair.id}`, async () => {
    assert.deepEqual(pair.positive.byteRange, pair.negative.byteRange);
    for (const label of ['positive', 'negative']) {
      const entry = pair[label];
      const pdf = load(entry.pdf);
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
        minimumLevel: 'B', validationTime: at, knowledgeTime: at, policy,
      });
      assert.deepEqual({ overall: result.overall, reason: result.reason,
        verifiedLevel: result.verifiedLevel ?? null }, entry.expected, `${pair.id} ${label}`);
    }
  });
}
