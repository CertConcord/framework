import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { keyID, parseDER } from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { verifyCAdES } from './cades.mjs';
import { inspectAdESSignature } from './ades-cms.mjs';

const vectorBytes = readFileSync(new URL('./vectors/cades-cms-guards.json', import.meta.url));
assert.equal(createHash('sha256').update(vectorBytes).digest('hex'),
  'f0a535956ca30486747e09f0fb29673a8de066abad869e3fe691f2c18b4e327c');
const frozen = JSON.parse(vectorBytes);
assert.equal(frozen.schema, 'certconcord.cms-guards.v1');
const load = (name) => {
  const entry = frozen.vectors[name];
  const raw = Buffer.from(entry.derBase64, 'base64');
  assert.equal(raw.length, entry.bytes);
  assert.equal(createHash('sha256').update(raw).digest('hex'), entry.sha256);
  return raw;
};
const [positive, negative] = ['digestExtraSha512', 'digestMalformedUnused'].map(load);
const signedData = (cms) => parseDER(cms).children[1].children[0].children;

test('frozen CMS pair changes only unsigned digestAlgorithms while retaining the signer', () => {
  const a = signedData(positive), b = signedData(negative);
  assert.equal(a.length, b.length);
  for (let i = 0; i < a.length; i++) {
    if (i !== 1) assert.deepEqual(a[i].raw, b[i].raw);
  }
  assert.equal(a[1].children.length, 2);
  assert.equal(b[1].children.length, 2);
  assert.equal(a[1].children[1].children[0].tag, 0x06);
  assert.equal(b[1].children[1].children[0].tag, 0x0c);
});

test('an additional valid unused SHA-512 DigestAlgorithmIdentifier remains valid', () => {
  const verdict = inspectAdESSignature(positive, { profile: 'CADES' });
  assert.equal(verdict.overall, 'VALID');
  assert.equal(verdict.reason, 'CADES_VALID');
});

test('a malformed unused DigestAlgorithmIdentifier is rejected', () => {
  const verdict = inspectAdESSignature(negative, { profile: 'CADES' });
  assert.equal(verdict.overall, 'INVALID');
  assert.equal(verdict.reason, 'EXPECTED_OID');
});

const issuerVectors = ['essOnlyIssuer', 'essExtraDns'].map(load);

test('signed ESS IssuerSerial with only the certificate issuer directoryName is valid', () => {
  const verdict = inspectAdESSignature(issuerVectors[0], { profile: 'CADES' });
  assert.equal(verdict.overall, 'VALID');
  assert.equal(verdict.reason, 'CADES_VALID');
});

test('signed ESS IssuerSerial with an extra dNSName is rejected', () => {
  const verdict = inspectAdESSignature(issuerVectors[1], { profile: 'CADES' });
  assert.equal(verdict.overall, 'INVALID');
  assert.equal(verdict.reason, 'CADES_ESS_ISSUER_SERIAL');
});

const nameVectors = ['issuerEquivalent', 'issuerDifferent'].map(load);

test('semantically equal issuer name in CMS SignerInfo identifies the signing certificate', () => {
  const verdict = inspectAdESSignature(nameVectors[0], { profile: 'CADES' });
  assert.equal(verdict.overall, 'VALID');
  assert.equal(verdict.reason, 'CADES_VALID');
});

test('genuinely unequal issuer name in CMS SignerInfo cannot identify the certificate', () => {
  const verdict = inspectAdESSignature(nameVectors[1], { profile: 'CADES' });
  assert.equal(verdict.overall, 'INVALID');
  assert.equal(verdict.reason, 'CADES_SIGNING_CERTIFICATE_BINDING');
});

const fixture = (name) => {
  const entry = frozen.essDefaultFixture[name];
  const raw = Buffer.from(entry.derBase64, 'base64');
  assert.equal(raw.length, entry.bytes);
  assert.equal(createHash('sha256').update(raw).digest('hex'), entry.sha256);
  return raw;
};
const defaultCMS = ['essDefaultOmitted', 'essDefaultExplicitSha256', 'essNondefaultSha512'].map(load);

test('frozen ESS default pair changes only signed ESS attribute and signature', () => {
  const signed = (cms) => parseDER(cms).children[1].children[0];
  const a = signed(defaultCMS[0]), b = signed(defaultCMS[1]);
  assert.equal(a.children.length, b.children.length);
  for (let i = 0; i < a.children.length - 1; i++)
    assert.deepEqual(a.children[i].raw, b.children[i].raw);
  const signer = (sd) => sd.children.at(-1).children[0];
  const first = signer(a), second = signer(b);
  for (let i = 0; i < first.children.length; i++)
    if (i !== 3 && i !== 5) assert.deepEqual(first.children[i].raw, second.children[i].raw);
});

test('omitted SHA-256 default and explicit SHA-512 ESS hash remain valid', () => {
  for (const cms of [defaultCMS[0], defaultCMS[2]]) {
    const verdict = inspectAdESSignature(cms, { content: fixture('document'), profile: 'CADES' });
    assert.equal(verdict.overall, 'VALID');
    assert.equal(verdict.reason, 'CADES_VALID');
  }
});

test('explicit SHA-256 default in signed ESSCertIDv2 is rejected', () => {
  const verdict = inspectAdESSignature(defaultCMS[1], { content: fixture('document'), profile: 'CADES' });
  assert.equal(verdict.overall, 'INVALID');
  assert.equal(verdict.reason, 'CADES_SIGNING_CERTIFICATE_ENCODING');
});


test('public verifier enforces ESS default and unsigned-attribute cardinality', () => {
  const epoch = 1800000000;
  const O = { es256: '1.2.840.10045.4.3.2', sha256: '2.16.840.1.101.3.4.2.1',
    sha512: '2.16.840.1.101.3.4.2.3', policy: '1.3.6.1.4.1.55555.91.1' };
  const content = fixture('document');
  const certificate = fixture('signerCertificate');
  const root = fixture('rootCertificate');
  const crl = fixture('rootCRL');
  const signerX509 = new X509Certificate(certificate);
  const rootX509 = new X509Certificate(root);
  const domain = Buffer.alloc(32, 0x91);
  const scope = { trustDomainID: domain, issuerID: 'cades-fixture', representation: 'X509' };
  const status = { authorityID: keyID(rootX509.publicKey), trustDomainID: domain,
    scope: 'AUTHORITY', status: 'GOOD', publishedAt: epoch - 100,
    nextUpdate: epoch + 100000 };
  const authorityResolver = createAuthorityResolver({ trustDomainID: domain,
    authorities: [{ mode: 'CERTIFICATE', certificate: root, knownAt: epoch - 100,
      validFrom: epoch - 100, validUntil: epoch + 100000,
      roles: ['ISSUER', 'STATUS_AUTHORITY'], scopes: [scope], status }] });
  const signerID = keyID(signerX509.publicKey).toString('hex');
  const rootID = keyID(rootX509.publicKey).toString('hex');
  const policy = { trustedRoots: [root], authorityResolver, scope,
    algorithmDeadlines: { [O.es256]: epoch + 100000 },
    hashDeadlines: { [O.sha256]: epoch + 100000, [O.sha512]: epoch + 100000 },
    keyDeadlines: { [signerID]: epoch + 100000, [rootID]: epoch + 100000 },
    timestampPolicies: [O.policy],
    currentMaterial: { certificates: [certificate, root], crls: [crl] } };
  const expectations = [
    ['essDefaultOmitted', 'VALID', 'CADES_VALID'],
    ['essDefaultExplicitSha256', 'INVALID', 'CADES_SIGNING_CERTIFICATE_ENCODING'],
    ['essNondefaultSha512', 'VALID', 'CADES_VALID'],
    ['unsignedEmptyNegative', 'INVALID', 'CADES_ATTRIBUTES_ENCODING'],
    ['unsignedNonemptyPositive', 'VALID', 'CADES_VALID'],
  ];
  for (const [name, overall, reason] of expectations) {
    const result = verifyCAdES(load(name), { content, minimumLevel: 'B',
      validationTime: epoch + 40, knowledgeTime: epoch + 40, policy });
    assert.equal(result.overall, overall, name);
    assert.equal(result.reason, reason, name);
    if (overall === 'VALID') assert.equal(result.verifiedLevel, 'B');
  }
});


test('a malformed unused SHA-512 parameter is rejected without altering the signed fields', () => {
  const original = parseDER(load('digestExtraSha512')).children[1].children[0];
  const malformed = parseDER(load('digestInvalidSha512Params')).children[1].children[0];
  for (let i = 0; i < original.children.length; i++)
    if (i !== 1) assert.deepEqual(original.children[i].raw, malformed.children[i].raw);
  const verdict = inspectAdESSignature(load('digestInvalidSha512Params'), { profile: 'CADES' });
  assert.equal(verdict.overall, 'INVALID');
  assert.equal(verdict.reason, 'CADES_HASH_PARAMETERS');
});

test('an additional unused SHA-512 DigestAlgorithmIdentifier with NULL remains valid', () => {
  const verdict = inspectAdESSignature(load('digestSha512NullParams'), { profile: 'CADES' });
  assert.equal(verdict.overall, 'VALID');
  assert.equal(verdict.reason, 'CADES_VALID');
});


test('present empty unsignedAttrs is rejected, while absent and nonempty remain valid', () => {
  const positive = load('essDefaultOmitted');
  const negative = load('unsignedEmptyNegative');
  const nonempty = load('unsignedNonemptyPositive');
  const signer = (cms) => parseDER(cms).children[1].children[0].children.at(-1).children[0];
  const a = signer(positive), b = signer(negative), c = signer(nonempty);
  assert.equal(a.children.length, 6);
  assert.equal(b.children.length, 7);
  assert.equal(c.children.length, 7);
  for (let i = 0; i < 6; i++) {
    assert.deepEqual(a.children[i].raw, b.children[i].raw);
    assert.deepEqual(a.children[i].raw, c.children[i].raw);
  }
  assert.equal(b.children[6].raw.toString('hex'), 'a100');
  for (const [cms, overall, reason] of [
    [negative, 'INVALID', 'CADES_ATTRIBUTES_ENCODING'],
    [nonempty, 'VALID', 'CADES_VALID'],
  ]) {
    const result = inspectAdESSignature(cms, { content: fixture('document'), profile: 'CADES' });
    assert.equal(result.overall, overall);
    assert.equal(result.reason, reason);
  }
});
