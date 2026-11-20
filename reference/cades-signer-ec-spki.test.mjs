import assert from 'node:assert/strict';
import { createHash, verify, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { keyID, oidText, parseDER, set } from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { verifyCAdES } from './cades.mjs';
import { validateCertificate } from './pki.mjs';

const vectorRaw = readFileSync(new URL('./vectors/cades-signer-ec-spki.json', import.meta.url));
assert.equal(
  createHash('sha256').update(vectorRaw).digest('hex'),
  '390502f1fa424d33b3e10955bddc4d98c48d8a057a34712a3bad9e1ce2ae5798',
);
const vectors = JSON.parse(vectorRaw);
assert.equal(vectors.schema, 'certconcord.cades-signer-ec-spki.v1');
const sha = (raw) => createHash('sha256').update(raw).digest('hex');
const decode = (entry) => {
  const raw = Buffer.from(entry.derBase64, 'base64');
  assert.equal(raw.toString('base64'), entry.derBase64);
  assert.equal(raw.length, entry.bytes);
  assert.equal(sha(raw), entry.sha256);
  return raw;
};
const fixture = Object.fromEntries(
  Object.entries(vectors.fixture).map(([id, value]) => [id, decode(value)]),
);
const root = new X509Certificate(fixture.root);
const at = vectors.epoch + 40;
const deadline = at + 100000;
const domain = Buffer.alloc(32, 0xa9);
const scope = { trustDomainID: domain, issuerID: 'cades-spki-fixture', representation: 'X509' };
const rootID = keyID(root.publicKey);
const authorityResolver = createAuthorityResolver({
  trustDomainID: domain,
  authorities: [
    {
      mode: 'CERTIFICATE',
      certificate: fixture.root,
      knownAt: at - 3600,
      validFrom: at - 3600,
      validUntil: deadline,
      roles: ['ISSUER', 'STATUS_AUTHORITY'],
      scopes: [scope],
      status: {
        authorityID: rootID,
        trustDomainID: domain,
        scope: 'AUTHORITY',
        status: 'GOOD',
        publishedAt: at - 3600,
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
  hashDeadlines: {
    '2.16.840.1.101.3.4.2.1': deadline,
    '2.16.840.1.101.3.4.2.3': deadline,
  },
  keyDeadlines: {
    [rootID.toString('hex')]: deadline,
    [keyID(new X509Certificate(certificate).publicKey).toString('hex')]: deadline,
  },
  timestampPolicies: [],
  currentMaterial: { certificates: [certificate, fixture.root], crls: [fixture.rootCRL] },
});
const signedSPKI = (certificate) => {
  const spki = parseDER(certificate).children[0].children[6];
  const [algorithm, key] = spki.children;
  assert.equal(oidText(algorithm.children[0]), '1.2.840.10045.2.1');
  return { algorithm, key, raw: spki.raw };
};
const signedCMSMath = (cms, certificate) => {
  const signedData = parseDER(cms).children[1].children[0];
  const signer = signedData.children.at(-1).children[0];
  const attributes = signer.children[3].children.map((node) => node.raw);
  return verify(
    'sha256',
    set(...attributes),
    new X509Certificate(certificate).publicKey,
    signer.children[5].value,
  );
};

test('frozen signed EC SPKI corpus isolates parameters, point form and unused-bit count', () => {
  assert.equal(root.verify(root.publicKey), true);
  assert.equal(vectors.epoch, 1800000000);
  assert.deepEqual(
    Object.keys(vectors.cases).sort(),
    ['namedCurveUncompressed', 'nonzeroUnusedBits', 'specifiedCurve', 'hybridPoint'].sort(),
  );
  const signed = Object.fromEntries(
    Object.entries(vectors.cases).map(([id, entry]) => {
      const certificate = decode(entry.certificate),
        cms = decode(entry.cms);
      assert.equal(new X509Certificate(certificate).verify(root.publicKey), true, id);
      assert.equal(signedCMSMath(cms, certificate), true, id);
      return [id, signedSPKI(certificate)];
    }),
  );
  const good = signed.namedCurveUncompressed;
  assert.equal(good.algorithm.children[1].tag, 6);
  assert.equal(good.key.value[0], 0);
  assert.equal(good.key.value[1], 4);
  assert.equal(signed.nonzeroUnusedBits.key.value[0], 1);
  assert.deepEqual(signed.nonzeroUnusedBits.key.value.subarray(1), good.key.value.subarray(1));
  assert.equal(signed.hybridPoint.key.value[0], 0);
  assert.equal(signed.hybridPoint.key.value[1], 6);
  assert.deepEqual(signed.hybridPoint.key.value.subarray(2), good.key.value.subarray(2));
  assert.equal(signed.specifiedCurve.algorithm.children[1].tag, 0x30);
  assert.deepEqual(signed.specifiedCurve.key.value, good.key.value);
});

for (const [id, entry] of Object.entries(vectors.cases))
  test(`CAdES signer signed EC SPKI ${id}`, () => {
    const certificate = decode(entry.certificate);
    if (entry.expected === 'VALID')
      assert.doesNotThrow(() =>
        validateCertificate(certificate, root.publicKey, { at, allowCA: false }),
      );
    else
      assert.throws(
        () => validateCertificate(certificate, root.publicKey, { at, allowCA: false }),
        (error) => error.code === 'CERTIFICATE_SPKI',
      );
    const result = verifyCAdES(decode(entry.cms), {
      content: fixture.document,
      minimumLevel: 'B',
      validationTime: at,
      knowledgeTime: at,
      policy: policy(certificate),
    });
    assert.equal(result.overall, entry.expected, JSON.stringify(result.checks));
    assert.equal(
      result.reason,
      entry.expected === 'VALID' ? 'CADES_VALID' : 'CERTIFICATE_SPKI',
      JSON.stringify(result.checks),
    );
    if (entry.expected === 'VALID') assert.equal(result.verifiedLevel, 'B');
  });

test('signed compressed ECPoint remains admissible; other parity and bad signature do not', () => {
  const group = vectors.compressedFixture;
  const rootCertificate = decode(group.root);
  const rootKey = new X509Certificate(rootCertificate).publicKey;
  const crl = decode(group.crl),
    document = decode(group.document);
  const compressedCertificate = decode(group.compressed.certificate);
  const otherParityCertificate = decode(group.otherParity.certificate);
  const compressed = signedSPKI(compressedCertificate).key.value;
  const otherParity = signedSPKI(otherParityCertificate).key.value;
  assert.equal(compressed[0], 0);
  assert([2, 3].includes(compressed[1]));
  assert.equal(otherParity[0], 0);
  assert.equal(otherParity[1], compressed[1] ^ 1);
  assert.deepEqual(otherParity.subarray(2), compressed.subarray(2));
  for (const certificate of [compressedCertificate, otherParityCertificate]) {
    assert.equal(new X509Certificate(certificate).verify(rootKey), true);
    assert.doesNotThrow(() =>
      validateCertificate(certificate, rootKey, { at: group.at, allowCA: false }),
    );
  }
  assert.equal(signedCMSMath(decode(group.compressed.cms), compressedCertificate), true);
  assert.equal(signedCMSMath(decode(group.otherParity.cms), compressedCertificate), true);
  assert.equal(signedCMSMath(decode(group.otherParity.cms), otherParityCertificate), false);
  assert.equal(signedCMSMath(decode(group.badSignature.cms), compressedCertificate), false);
  const trustDomainID = Buffer.alloc(32, 0xb7);
  const selectedScope = {
    trustDomainID,
    issuerID: 'cades-compressed-spki',
    representation: 'X509',
  };
  const rootKeyID = keyID(rootKey);
  const selectedDeadline = group.at + 100000;
  const resolver = createAuthorityResolver({
    trustDomainID,
    authorities: [
      {
        mode: 'CERTIFICATE',
        certificate: rootCertificate,
        knownAt: group.at - 100,
        validFrom: group.at - 100,
        validUntil: selectedDeadline,
        roles: ['ISSUER', 'STATUS_AUTHORITY'],
        scopes: [selectedScope],
        status: {
          authorityID: rootKeyID,
          trustDomainID,
          scope: 'AUTHORITY',
          status: 'GOOD',
          publishedAt: group.at - 100,
          nextUpdate: selectedDeadline,
        },
      },
    ],
  });
  const selectedPolicy = (certificate) => ({
    trustedRoots: [rootCertificate],
    authorityResolver: resolver,
    scope: selectedScope,
    algorithmDeadlines: { '1.2.840.10045.4.3.2': selectedDeadline },
    hashDeadlines: {
      '2.16.840.1.101.3.4.2.1': selectedDeadline,
      '2.16.840.1.101.3.4.2.3': selectedDeadline,
    },
    keyDeadlines: {
      [rootKeyID.toString('hex')]: selectedDeadline,
      [keyID(new X509Certificate(certificate).publicKey).toString('hex')]: selectedDeadline,
    },
    timestampPolicies: [],
    currentMaterial: { certificates: [certificate, rootCertificate], crls: [crl] },
  });
  for (const [id, entry] of Object.entries({
    compressed: group.compressed,
    otherParity: group.otherParity,
    badSignature: group.badSignature,
  })) {
    const certificate = decode(entry.certificate);
    const result = verifyCAdES(decode(entry.cms), {
      content: document,
      minimumLevel: 'B',
      validationTime: group.at,
      knowledgeTime: group.at,
      policy: selectedPolicy(certificate),
    });
    assert.equal(result.overall, entry.expected, `${id}: ${JSON.stringify(result.checks)}`);
    assert.equal(
      result.reason,
      entry.expected === 'VALID' ? 'CADES_VALID' : 'CADES_SIGNATURE_INVALID',
      id,
    );
    if (entry.expected === 'VALID') assert.equal(result.verifiedLevel, 'B');
  }
});
