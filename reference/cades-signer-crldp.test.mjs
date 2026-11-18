import assert from 'node:assert/strict';
import { createHash, verify as verifySignature, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { keyID, oidText, parseDER } from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { verifyCAdES } from './cades.mjs';

const rawVectors = readFileSync(new URL('./vectors/cades-signer-crldp.json', import.meta.url));
assert.equal(createHash('sha256').update(rawVectors).digest('hex'),
  'edb1c006c19391929efee32fd4ab2982f2478d0f10c52e171a57972465e91179');
const vectors = JSON.parse(rawVectors);
assert.equal(vectors.schema, 'certconcord.cades-signer-crldp.v1');
const decode = entry => {
  const bytes = Buffer.from(entry.derBase64, 'base64');
  assert.equal(bytes.length, entry.bytes);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256);
  return bytes;
};
const root = decode(vectors.fixture.root);
const document = decode(vectors.fixture.document);
const rootKey = new X509Certificate(root).publicKey;
const rootID = keyID(rootKey).toString('hex');
const domain = Buffer.alloc(32, 0x91);
const scope = { trustDomainID: domain, issuerID: 'cades-fixture', representation: 'X509' };
const deadline = vectors.epoch + 100000;
const authorityResolver = createAuthorityResolver({ trustDomainID: domain,
  authorities: [{ mode: 'CERTIFICATE', certificate: root,
    knownAt: vectors.epoch - 100, validFrom: vectors.epoch - 100, validUntil: deadline,
    roles: ['ISSUER', 'STATUS_AUTHORITY'], scopes: [scope],
    status: { authorityID: Buffer.from(rootID, 'hex'), trustDomainID: domain,
      scope: 'AUTHORITY', status: 'GOOD', publishedAt: vectors.epoch - 100,
      nextUpdate: deadline } }] });
const policy = (certificate, crl) => ({ trustedRoots: [root], authorityResolver, scope,
  algorithmDeadlines: { '1.2.840.10045.4.3.2': deadline },
  hashDeadlines: { '2.16.840.1.101.3.4.2.1': deadline,
    '2.16.840.1.101.3.4.2.3': deadline },
  keyDeadlines: Object.fromEntries([root, certificate].map(raw => [
    keyID(new X509Certificate(raw).publicKey).toString('hex'), deadline])),
  timestampPolicies: ['1.3.6.1.4.1.55555.91.1'],
  currentMaterial: { certificates: [certificate, root], crls: [crl] } });

for (const [name, description] of [
  ['unknownMember', 'an unknown DistributionPoint member'],
  ['emptyURI', 'an empty fullName URI'],
  ['reasonFlagsUnused8', 'eight unused ReasonFlags bits'],
  ['directCrlIssuer', 'a direct-issuer cRLIssuer under the selected CA profile'],
]) test(`CAdES B rejects signer CRLDP with ${description} and preserves its signed control`, () => {
  const variant = vectors.variants[name];
  const crl = decode(variant.crl);
  for (const [kind, expectedOverall, expectedReason] of [
    ['positive', 'VALID', 'CADES_VALID'],
    ['negative', 'INVALID', 'CADES_CERTIFICATE_CRLDP'],
  ]) {
    const certificate = decode(variant[kind].certificate);
    const cms = decode(variant[kind].cms);
    const parsed = parseDER(certificate);
    assert.equal(verifySignature('sha256', parsed.children[0].raw, rootKey,
      parsed.children[2].value.subarray(1)), true, `${name}/${kind} issuer signature`);
    const extensions = parsed.children[0].children.at(-1).children[0].children;
    const crldp = extensions.find(x => oidText(x.children[0]) === '2.5.29.31');
    assert(crldp, `${name}/${kind} CRLDP`);
    assert.equal(crldp.children.length, 2, `${name}/${kind} noncritical CRLDP`);
    const result = verifyCAdES(cms, { content: document, minimumLevel: 'B',
      validationTime: vectors.epoch + 40, knowledgeTime: vectors.epoch + 40,
      policy: policy(certificate, crl) });
    assert.equal(result.overall, expectedOverall, `${name}/${kind}: ${JSON.stringify(result.checks)}`);
    assert.equal(result.reason, expectedReason, `${name}/${kind}: ${JSON.stringify(result.checks)}`);
    if (kind === 'positive') assert.equal(result.verifiedLevel, 'B');
  }
});

test('CAdES B preserves a signed nonempty relative CRL distribution point name', () => {
  const variant = vectors.validVariants.nonemptyRelativeName;
  const certificate = decode(variant.certificate);
  const cms = decode(variant.cms);
  const crl = decode(variant.crl);
  assert.equal(new X509Certificate(certificate).verify(rootKey), true);
  const extensions = parseDER(certificate).children[0].children.at(-1).children[0].children;
  const crldp = extensions.find(x => oidText(x.children[0]) === '2.5.29.31');
  assert(crldp);
  const relativeName = parseDER(crldp.children.at(-1).value).children[0].children[0].children[0];
  assert.equal(relativeName.tag, 0xa1);
  assert(relativeName.children.length > 0);
  const result = verifyCAdES(cms, { content: document, minimumLevel: 'B',
    validationTime: vectors.epoch + 40, knowledgeTime: vectors.epoch + 40,
    policy: policy(certificate, crl) });
  assert.equal(result.overall, 'VALID', JSON.stringify(result.checks));
  assert.equal(result.reason, 'CADES_VALID', JSON.stringify(result.checks));
  assert.equal(result.verifiedLevel, 'B');
});
