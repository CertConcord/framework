import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { keyID } from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { validateSmimeMaterial } from './cades-validation.mjs';
import { parseCertificate } from './pki.mjs';
import { sameDistinguishedName } from './x509-name.mjs';

const raw = readFileSync(
  new URL('./vectors/cades-root-issuer-dn-equivalence.json', import.meta.url),
);
const vectors = JSON.parse(raw);
assert.equal(vectors.schema, 'certconcord.direct-root-issuer-dn-equivalence.v1');
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const decode = (item) => {
  const bytes = Buffer.from(item.base64, 'base64');
  assert.equal(bytes.length, item.bytes);
  assert.equal(sha(bytes), item.sha256);
  return bytes;
};
const root = decode(vectors.certificates.root);
const alternateRoot = decode(vectors.certificates.alternateEquivalentRoot);
const crl = decode(vectors.crl);
const rootKey = new X509Certificate(root).publicKey;
const rootName = parseCertificate(root).subject;
const alternate = parseCertificate(alternateRoot);
assert.equal(sameDistinguishedName(rootName, alternate.subject), true);
assert.notDeepEqual(root, alternateRoot);
assert.notDeepEqual(
  rootKey.export({ type: 'spki', format: 'der' }),
  new X509Certificate(alternateRoot).publicKey.export({ type: 'spki', format: 'der' }),
);
assert.equal(
  new X509Certificate(alternateRoot).verify(new X509Certificate(alternateRoot).publicKey),
  true,
);
const leaves = Object.fromEntries(
  ['exactIssuerLeaf', 'caseEquivalentIssuerLeaf', 'differentIssuerLeaf'].map((name) => [
    name,
    decode(vectors.certificates[name]),
  ]),
);
for (const certificate of Object.values(leaves))
  assert.equal(new X509Certificate(certificate).verify(rootKey), true);
assert.notDeepEqual(
  parseCertificate(leaves.exactIssuerLeaf).issuer,
  parseCertificate(leaves.caseEquivalentIssuerLeaf).issuer,
);
assert.equal(
  sameDistinguishedName(rootName, parseCertificate(leaves.caseEquivalentIssuerLeaf).issuer),
  true,
);
assert.equal(
  sameDistinguishedName(rootName, parseCertificate(leaves.differentIssuerLeaf).issuer),
  false,
);

const domain = Buffer.from(vectors.domainHex, 'hex');
const scope = {
  ...vectors.policy.scope,
  trustDomainID: Buffer.from(vectors.policy.scope.trustDomainID, 'hex'),
};
const rootID = keyID(rootKey);
const authorityResolver = createAuthorityResolver({
  trustDomainID: domain,
  authorities: [
    {
      mode: 'CERTIFICATE',
      certificate: root,
      knownAt: vectors.epoch - 1000,
      validFrom: vectors.epoch - 1000,
      validUntil: vectors.epoch + 100000,
      roles: ['ISSUER', 'STATUS_AUTHORITY'],
      scopes: [scope, { ...scope, purpose: 'SMIME_RECIPIENT_ENCRYPTION' }],
      status: {
        authorityID: rootID,
        trustDomainID: domain,
        scope: 'AUTHORITY',
        status: 'GOOD',
        publishedAt: vectors.epoch - 1000,
        nextUpdate: vectors.epoch + 100000,
      },
    },
  ],
});
const policy = (trustedRoots) => ({
  trustedRoots,
  scope,
  authorityResolver,
  algorithmDeadlines: vectors.policy.algorithmDeadlines,
  hashDeadlines: vectors.policy.hashDeadlines,
  keyDeadlines: vectors.policy.keyDeadlines,
  currentMaterial: { certificates: [], crls: [] },
});
const cases = {
  exactIssuer: { certificate: leaves.exactIssuerLeaf, trustedRoots: [root] },
  caseEquivalentIssuer: { certificate: leaves.caseEquivalentIssuerLeaf, trustedRoots: [root] },
  differentIssuer: { certificate: leaves.differentIssuerLeaf, trustedRoots: [root] },
  ambiguousEquivalentAnchors: {
    certificate: leaves.exactIssuerLeaf,
    trustedRoots: [root, alternateRoot],
  },
  differentKeyEquivalentAnchor: {
    certificate: leaves.caseEquivalentIssuerLeaf,
    trustedRoots: [alternateRoot],
  },
};
for (const [name, item] of Object.entries(cases))
  test(`signed direct-root issuer DN: ${name}`, () => {
    const result = validateSmimeMaterial({
      certificate: item.certificate,
      certificates: [root],
      crls: [crl],
      knowledgeTime: vectors.at,
      purpose: 'SMIME_SIGNING',
      policy: policy(item.trustedRoots),
    });
    assert.deepEqual({ overall: result.overall, reason: result.reason }, vectors.expected[name]);
  });
