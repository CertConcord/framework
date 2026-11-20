import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { createAuthorityResolver } from './authority-history.mjs';
import { inspectAdESSignature } from './ades-cms.mjs';
import { keyID } from './core.mjs';
import { O, epoch } from './cades-fixtures.mjs';
import { loadPAdES, pdfSignatures } from './pades-fixtures.mjs';

const raw = readFileSync(new URL('./vectors/pades-signature-version-admission.json', import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(sha(raw), '6c1a20d7b4031805ac84b8ad01cc3d1692597e0636098e90241660286fa28502');
const vectors = JSON.parse(raw);
assert.equal(vectors.schema, 'certconcord.pades-signature-version-admission.v1');
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

test('frozen public signer and root retain independent issuer signatures', () => {
  assert(root.verify(root.publicKey));
  assert(signer.verify(root.publicKey));
});

for (const [name, entry] of Object.entries(vectors.signedPDF))
  test(`frozen signed signature-dictionary version: ${name}`, async () => {
    const pdf = load(entry);
    assert(pdf.includes(Buffer.from(` /V ${entry.versionToken} /ByteRange [`)));
    const signatures = pdfSignatures(pdf);
    assert.equal(signatures.length, 1);
    const [signature] = signatures;
    assert.equal(sha(signature.cms), entry.cmsSha256);
    const [start, firstLength, secondStart, secondLength] = signature.byteRange;
    const content = Buffer.concat([
      pdf.subarray(start, start + firstLength),
      pdf.subarray(secondStart, secondStart + secondLength),
    ]);
    assert.equal(sha(content), entry.signedContentSha256);
    assert.equal(inspectAdESSignature(signature.cms, { content, profile: 'PADES' }).overall, 'VALID');
    const result = await api.verifyPAdES(pdf, {
      minimumLevel: 'B', validationTime: epoch + 40, knowledgeTime: epoch + 40, policy,
    });
    assert.deepEqual({ overall: result.overall, reason: result.reason,
      verifiedLevel: result.verifiedLevel ?? null }, entry.expected);
  });
