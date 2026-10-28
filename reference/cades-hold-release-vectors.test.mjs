import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { sha256, keyID } from './core.mjs';
import { parseCertificate } from './pki.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { verifyCAdES } from './cades.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/cades-hold-release.json', import.meta.url)),
);
function decode(value) {
  const raw = Buffer.from(value.base64, 'base64');
  assert.equal(raw.length, value.bytes);
  assert.equal(sha256(raw).toString('hex'), value.sha256);
  return raw;
}
const root = decode(vectors.root),
  signer = decode(vectors.signer),
  content = decode(vectors.content);
const domain = Buffer.alloc(32, 0x91),
  scope = { trustDomainID: domain, issuerID: 'cades-fixture', representation: 'X509' };
const deadline = vectors.epoch + 100000;
const policy = (crls) => ({
  trustedRoots: [root],
  scope,
  authorityResolver: createAuthorityResolver({
    trustDomainID: domain,
    authorities: [
      {
        mode: 'CERTIFICATE',
        certificate: root,
        knownAt: vectors.epoch - 100,
        validFrom: vectors.epoch - 100,
        validUntil: deadline,
        roles: ['ISSUER', 'STATUS_AUTHORITY'],
        scopes: [scope],
        status: {
          authorityID: keyID(parseCertificate(root).publicKey),
          trustDomainID: domain,
          scope: 'AUTHORITY',
          status: 'GOOD',
          publishedAt: vectors.epoch - 100,
          nextUpdate: deadline,
        },
      },
    ],
  }),
  algorithmDeadlines: { '1.2.840.10045.4.3.2': deadline },
  hashDeadlines: { '2.16.840.1.101.3.4.2.1': deadline },
  keyDeadlines: Object.fromEntries(
    [root, signer].map((cert) => [
      keyID(parseCertificate(cert).publicKey).toString('hex'),
      deadline,
    ]),
  ),
  timestampPolicies: ['1.3.6.1.4.1.55555.91.1'],
  currentMaterial: {
    certificates: [root, signer],
    crls: crls.map((id) => decode(vectors.crls[id])),
  },
});
for (const row of vectors.cases)
  test('complete CRL hold transition raw replay: ' + row.id, () => {
    const result = verifyCAdES(decode(row.cms), {
      content,
      minimumLevel: 'B',
      validationTime: row.validationTime,
      knowledgeTime: row.knowledgeTime,
      policy: policy(row.crls),
    });
    assert.equal(result.overall, row.expected.overall, JSON.stringify(result.checks));
    assert.equal(result.reason, row.expected.reason);
  });
test('raw CAdES transition cannot hide substituted content', () => {
  const row = vectors.cases.find((q) => q.id === 'hold-and-release');
  const result = verifyCAdES(decode(row.cms), {
    content: Buffer.from('substituted content'),
    minimumLevel: 'B',
    validationTime: row.validationTime,
    knowledgeTime: row.knowledgeTime,
    policy: policy(row.crls),
  });
  assert.equal(result.overall, 'INVALID');
});
