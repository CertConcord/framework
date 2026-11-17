import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { keyID, oidText, parseDER } from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { verifyCAdES } from './cades.mjs';

const raw = readFileSync(new URL('./vectors/cades-ec-signer-key-usage.json', import.meta.url));
assert.equal(
  createHash('sha256').update(raw).digest('hex'),
  '303388f418797a3b5b68bd68657f0c138486c53a0e25390051d22ee89c7a8221',
);
const vectors = JSON.parse(raw);
assert.equal(vectors.schema, 'certconcord.cades-ec-signer-key-usage.v1');
const decode = (entry) => {
  const bytes = Buffer.from(entry.derBase64, 'base64');
  assert.equal(bytes.length, entry.bytes);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256);
  return bytes;
};
const fixture = Object.fromEntries(
  Object.entries(vectors.fixture).map(([name, entry]) => [name, decode(entry)]),
);
const domain = Buffer.alloc(32, 0x91);
const scope = { trustDomainID: domain, issuerID: 'cades-fixture', representation: 'X509' };
const deadline = vectors.epoch + 100000;
const authorityResolver = createAuthorityResolver({
  trustDomainID: domain,
  authorities: [
    {
      mode: 'CERTIFICATE',
      certificate: fixture.root,
      knownAt: vectors.epoch - 100,
      validFrom: vectors.epoch - 100,
      validUntil: deadline,
      roles: ['ISSUER', 'STATUS_AUTHORITY'],
      scopes: [scope],
      status: {
        authorityID: keyID(new X509Certificate(fixture.root).publicKey),
        trustDomainID: domain,
        scope: 'AUTHORITY',
        status: 'GOOD',
        publishedAt: vectors.epoch - 100,
        nextUpdate: deadline,
      },
    },
  ],
});
const policy = (certificate) => ({
  trustedRoots: [fixture.root],
  authorityResolver,
  scope,
  algorithmDeadlines: { '1.2.840.10045.4.3.2': deadline },
  hashDeadlines: { '2.16.840.1.101.3.4.2.1': deadline, '2.16.840.1.101.3.4.2.3': deadline },
  keyDeadlines: Object.fromEntries(
    [fixture.root, certificate].map((bytes) => [
      keyID(new X509Certificate(bytes).publicKey).toString('hex'),
      deadline,
    ]),
  ),
  timestampPolicies: ['1.3.6.1.4.1.55555.91.1'],
  currentMaterial: { certificates: [certificate, fixture.root], crls: [fixture.rootCRL] },
});
const accepted = new Set([
  'digitalSignature',
  'digitalSignatureContentCommitment',
  'digitalSignatureKeyAgreement',
  'digitalSignatureKeyAgreementEncipherOnly',
  'digitalSignatureKeyAgreementDecipherOnly',
]);
const expectedUsageDER = {
  digitalSignature: '03020780',
  digitalSignatureContentCommitment: '030206c0',
  digitalSignatureKeyAgreement: '03020388',
  digitalSignatureKeyAgreementEncipherOnly: '03020089',
  digitalSignatureKeyAgreementDecipherOnly: '0303078880',
  digitalSignatureEncipherOnlyNoAgreement: '03020081',
  digitalSignatureDecipherOnlyNoAgreement: '0303078080',
  digitalSignatureKeyEncipherment: '030205a0',
  digitalSignatureDataEncipherment: '03020490',
  digitalSignatureKeyAgreementBothDirections: '0303078980',
};
assert.deepEqual(Object.keys(vectors.variants).sort(), Object.keys(expectedUsageDER).sort());
for (const [name, variant] of Object.entries(vectors.variants))
  test(`CAdES EC signer keyUsage ${name}`, () => {
    const certificate = decode(variant.certificate);
    const keyUsage = parseDER(certificate)
      .children[0].children.at(-1)
      .children[0].children.find((extension) => oidText(extension.children[0]) === '2.5.29.15');
    assert.ok(keyUsage, `${name} keyUsage`);
    assert.equal(keyUsage.children.length, 3, `${name} critical keyUsage`);
    assert.equal(keyUsage.children[1].raw.toString('hex'), '0101ff', `${name} critical keyUsage`);
    assert.equal(
      keyUsage.children[2].value.toString('hex'),
      expectedUsageDER[name],
      `${name} signed keyUsage DER`,
    );
    assert.equal(variant.keyUsageDER, expectedUsageDER[name], `${name} vector keyUsage metadata`);
    const result = verifyCAdES(decode(variant.cms), {
      content: fixture.document,
      minimumLevel: 'B',
      validationTime: vectors.epoch + 40,
      knowledgeTime: vectors.epoch + 40,
      policy: policy(certificate),
    });
    assert.equal(
      result.overall,
      accepted.has(name) ? 'VALID' : 'INVALID',
      JSON.stringify(result.checks),
    );
    assert.equal(
      result.reason,
      accepted.has(name) ? 'CADES_VALID' : 'CADES_SIGNER_EC_KEY_USAGE',
      JSON.stringify(result.checks),
    );
    if (accepted.has(name)) assert.equal(result.verifiedLevel, 'B');
  });
