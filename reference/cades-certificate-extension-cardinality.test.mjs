import assert from 'node:assert/strict';
import { createHash, verify as verifySignature, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { der, keyID, oidText, parseDER } from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { verifyCAdES } from './cades.mjs';

const rawVectors = readFileSync(new URL('./vectors/cades-certificate-extension-cardinality.json', import.meta.url));
assert.equal(createHash('sha256').update(rawVectors).digest('hex'),
  'ab3c3669761e939a879876f00e3abb84b460a9fe92ac5205ae91689c5ae8ad6d');
const vectors = JSON.parse(rawVectors);
assert.equal(vectors.schema, 'certconcord.cades-certificate-extension-cardinality.v1');
const decode = (entry) => {
  const bytes = Buffer.from(entry.derBase64, 'base64');
  assert.equal(bytes.length, entry.bytes);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256);
  return bytes;
};
const fixture = Object.fromEntries(Object.entries(vectors.fixture).map(([name, value]) => [name, decode(value)]));
const variants = Object.fromEntries(Object.entries(vectors.variants).map(([name, value]) => [name,
  { certificate: decode(value.certificate), cms: decode(value.cms) }]));
const rootKey = new X509Certificate(fixture.root).publicKey;
const signerKey = new X509Certificate(variants.absent.certificate).publicKey;

const signedData = (raw) => parseDER(raw).children[1].children[0];
const signerInfo = (raw) => signedData(raw).children.at(-1).children[0].children;
const extensions = (raw) => parseDER(raw).children[0].children.at(-1).children[0].children;

test('all frozen signer certificates and matched CMS signatures verify independently', () => {
  const baseTBS = parseDER(variants.absent.certificate).children[0].children;
  const baseInfo = signerInfo(variants.absent.cms);
  for (const [name, { certificate, cms }] of Object.entries(variants)) {
    const parsed = parseDER(certificate);
    assert.equal(verifySignature('sha256', parsed.children[0].raw, rootKey,
      parsed.children[2].value.subarray(1)), true, `${name} issuer signature`);
    const fields = parsed.children[0].children;
    for (let i = 0; i < fields.length - 1; i++)
      assert.deepEqual(fields[i].raw, baseTBS[i].raw, `${name} TBS field ${i}`);
    assert.equal(extensions(certificate).length, extensions(variants.absent.certificate).length +
      (name === 'absent' ? 0 : 1));
    const sd = signedData(cms);
    assert.equal(sd.children.find((node) => node.tag === 0xa0).children.some((node) =>
      node.raw.equals(certificate)), true, `${name} embedded certificate`);
    const si = signerInfo(cms);
    for (let i = 0; i < si.length; i++) if (![3, 5].includes(i))
      assert.deepEqual(si[i].raw, baseInfo[i].raw, `${name} signer info ${i}`);
    assert.equal(verifySignature('sha256', der(0x31, si[3].value), signerKey,
      si[5].value), true, `${name} CMS signature`);
  }
});

test('frozen extension bytes distinguish absent, empty, and nonempty forms', () => {
  const cases = [
    ['crldpEmpty', '2.5.29.31', '3000'],
    ['crldpEmptyMember', '2.5.29.31', '30023000'],
    ['aiaEmpty', '1.3.6.1.5.5.7.1.1', '3000'],
    ['sanEmptyDNS', '2.5.29.17', '30028200'],
    ['sanEmptyDirectoryName', '2.5.29.17', '3004a4023000'],
    ['siaEmpty', '1.3.6.1.5.5.7.1.11', '3000'],
    ['ianEmpty', '2.5.29.18', '3000'],
  ];
  for (const [name, expectedOID, expectedHex] of cases) {
    const extension = extensions(variants[name].certificate).at(-1).children;
    assert.equal(oidText(extension[0]), expectedOID);
    assert.equal(extension.length, 2, `${name} noncritical`);
    assert.equal(extension[1].value.toString('hex'), expectedHex);
  }
  for (const name of ['crldpNonempty', 'aiaNonempty', 'sanNonemptyDNS',
    'sanNonemptyDirectoryName', 'siaNonempty', 'ianNonempty'])
    assert.ok(parseDER(extensions(variants[name].certificate).at(-1).children.at(-1).value)
      .children.length > 0, name);
  const directory = (name) => parseDER(extensions(variants[name].certificate)
    .at(-1).children.at(-1).value).children[0].children[0];
  assert.equal(directory('sanEmptyDirectoryName').children.length, 0);
  assert.ok(directory('sanNonemptyDirectoryName').children.length > 0);
});

const domain = Buffer.alloc(32, 0x91);
const scope = { trustDomainID: domain, issuerID: 'cades-fixture', representation: 'X509' };
const deadline = vectors.epoch + 100000;
const authorityResolver = createAuthorityResolver({ trustDomainID: domain,
  authorities: [{ mode: 'CERTIFICATE', certificate: fixture.root,
    knownAt: vectors.epoch - 100, validFrom: vectors.epoch - 100, validUntil: deadline,
    roles: ['ISSUER', 'STATUS_AUTHORITY'], scopes: [scope],
    status: { authorityID: keyID(rootKey), trustDomainID: domain,
      scope: 'AUTHORITY', status: 'GOOD', publishedAt: vectors.epoch - 100,
      nextUpdate: deadline } }] });
const policy = (cert) => ({ trustedRoots: [fixture.root], authorityResolver, scope,
  algorithmDeadlines: { '1.2.840.10045.4.3.2': deadline },
  hashDeadlines: { '2.16.840.1.101.3.4.2.1': deadline,
    '2.16.840.1.101.3.4.2.3': deadline },
  keyDeadlines: Object.fromEntries([fixture.root, cert].map((raw) => [
    keyID(new X509Certificate(raw).publicKey).toString('hex'), deadline])),
  timestampPolicies: ['1.3.6.1.4.1.55555.91.1'],
  currentMaterial: { certificates: [cert, fixture.root], crls: [fixture.rootCRL] } });

for (const [name, overall, reason] of [
  ['absent', 'VALID', 'CADES_VALID'],
  ['crldpEmpty', 'INVALID', 'CADES_CERTIFICATE_CRLDP'],
  ['crldpEmptyMember', 'INVALID', 'CADES_CERTIFICATE_CRLDP'],
  ['crldpNonempty', 'VALID', 'CADES_VALID'],
  ['aiaEmpty', 'INVALID', 'CADES_CERTIFICATE_AIA'],
  ['aiaNonempty', 'VALID', 'CADES_VALID'],
  ['sanEmptyDNS', 'INVALID', 'CADES_CERTIFICATE_SAN'],
  ['sanNonemptyDNS', 'VALID', 'CADES_VALID'],
  ['sanEmptyDirectoryName', 'INVALID', 'CADES_CERTIFICATE_SAN'],
  ['sanNonemptyDirectoryName', 'VALID', 'CADES_VALID'],
  ['siaEmpty', 'INVALID', 'CADES_CERTIFICATE_SIA'],
  ['siaNonempty', 'VALID', 'CADES_VALID'],
  ['ianEmpty', 'INVALID', 'CADES_CERTIFICATE_IAN'],
  ['ianNonempty', 'VALID', 'CADES_VALID'],
]) test(`full CAdES certificate extension admission: ${name}`, () => {
  const { certificate, cms } = variants[name];
  const result = verifyCAdES(cms, { content: fixture.document,
    minimumLevel: 'B', validationTime: vectors.epoch + 40,
    knowledgeTime: vectors.epoch + 40, policy: policy(certificate) });
  assert.equal(result.overall, overall, JSON.stringify(result.checks));
  assert.equal(result.reason, reason, JSON.stringify(result.checks));
  if (overall === 'VALID') assert.equal(result.verifiedLevel, 'B');
});
