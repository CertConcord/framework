import assert from 'node:assert/strict';
import { createHash, verify as verifySignature, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { der, keyID, oidText, parseDER } from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { verifyCAdES } from './cades.mjs';

const rawVectors = readFileSync(
  new URL('./vectors/cades-certificate-policies.json', import.meta.url),
);
assert.equal(
  createHash('sha256').update(rawVectors).digest('hex'),
  '9fa80100b89e5c11a6cd8aff7ef3e7812f961f0b1ebbdb6c746658b5c0b0f2d6',
);
const vectors = JSON.parse(rawVectors);
assert.equal(vectors.schema, 'certconcord.cades-certificate-policies.v1');
const decode = (entry) => {
  const bytes = Buffer.from(entry.derBase64, 'base64');
  assert.equal(bytes.length, entry.bytes);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256);
  return bytes;
};
const fixture = Object.fromEntries(
  Object.entries(vectors.fixture).map(([name, value]) => [name, decode(value)]),
);
const variants = Object.fromEntries(
  Object.entries(vectors.variants).map(([name, value]) => [
    name,
    { certificate: decode(value.certificate), cms: decode(value.cms) },
  ]),
);
const rootKey = new X509Certificate(fixture.root).publicKey;
const signerKey = new X509Certificate(variants.absent.certificate).publicKey;
const signedData = (raw) => parseDER(raw).children[1].children[0];
const signerInfo = (raw) => signedData(raw).children.at(-1).children[0].children;
const extensions = (raw) => parseDER(raw).children[0].children.at(-1).children[0].children;
const policies = (name) =>
  parseDER(extensions(variants[name].certificate).at(-1).children[1].value);

test('all frozen policy certificates and matched CMS signatures verify independently', () => {
  const baseTBS = parseDER(variants.absent.certificate).children[0].children;
  const baseInfo = signerInfo(variants.absent.cms);
  for (const [name, { certificate, cms }] of Object.entries(variants)) {
    const parsed = parseDER(certificate);
    assert.equal(
      verifySignature(
        'sha256',
        parsed.children[0].raw,
        rootKey,
        parsed.children[2].value.subarray(1),
      ),
      true,
      `${name} issuer signature`,
    );
    const fields = parsed.children[0].children;
    for (let i = 0; i < fields.length - 1; i++)
      assert.deepEqual(fields[i].raw, baseTBS[i].raw, `${name} TBS field ${i}`);
    const entries = extensions(certificate);
    assert.equal(
      entries.length,
      extensions(variants.absent.certificate).length + (name === 'absent' ? 0 : 1),
    );
    if (name !== 'absent') {
      for (let i = 0; i < entries.length - 1; i++)
        assert.deepEqual(
          entries[i].raw,
          extensions(variants.absent.certificate)[i].raw,
          `${name} original extension ${i}`,
        );
      assert.equal(oidText(entries.at(-1).children[0]), '2.5.29.32');
      assert.equal(entries.at(-1).children.length, 2, `${name} noncritical`);
    }
    const sd = signedData(cms);
    assert.equal(
      sd.children
        .find((node) => node.tag === 0xa0)
        .children.some((node) => node.raw.equals(certificate)),
      true,
      `${name} embedded certificate`,
    );
    const info = signerInfo(cms);
    for (let i = 0; i < info.length; i++)
      if (![3, 5].includes(i))
        assert.deepEqual(info[i].raw, baseInfo[i].raw, `${name} signer info ${i}`);
    assert.equal(
      verifySignature('sha256', der(0x31, info[3].value), signerKey, info[5].value),
      true,
      `${name} CMS signature`,
    );
  }
});

test('frozen DER separates absent, empty, nonempty, malformed, and duplicate policy forms', () => {
  assert.equal(
    extensions(variants.absent.certificate).some(
      (entry) => oidText(entry.children[0]) === '2.5.29.32',
    ),
    false,
  );
  assert.equal(policies('policiesEmpty').children.length, 0);
  assert.equal(policies('policyInformationEmpty').children[0].children.length, 0);
  assert.equal(
    policies('policyQualifiersEmpty').children[0].children[1].raw.toString('hex'),
    '3000',
  );
  assert.equal(
    policies('policyQualifierInfoEmpty').children[0].children[1].children[0].raw.toString('hex'),
    '3000',
  );
  assert.equal(policies('policyQualifiersWrongTag').children[0].children[1].tag, 0x04);
  assert.deepEqual(
    policies('duplicatePolicyOID').children.map((item) => oidText(item.children[0])),
    ['1.3.6.1.4.1.55555.91.99', '1.3.6.1.4.1.55555.91.99'],
  );
  assert.deepEqual(
    policies('policyDistinct').children.map((item) => oidText(item.children[0])),
    ['1.3.6.1.4.1.55555.91.99', '1.3.6.1.4.1.55555.91.100'],
  );
  const nonempty = policies('qualifiersNonempty').children[0].children[1].children;
  assert.equal(nonempty.length, 1);
  assert.equal(oidText(nonempty[0].children[0]), '1.3.6.1.5.5.7.2.1');
  assert.equal(nonempty[0].children[1].tag, 0x16);
  assert.equal(
    nonempty[0].children[1].value.toString('ascii'),
    'https://policy.example.invalid/cps',
  );
});

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
        authorityID: keyID(rootKey),
        trustDomainID: domain,
        scope: 'AUTHORITY',
        status: 'GOOD',
        publishedAt: vectors.epoch - 100,
        nextUpdate: deadline,
      },
    },
  ],
});
const policy = (cert) => ({
  trustedRoots: [fixture.root],
  authorityResolver,
  scope,
  algorithmDeadlines: { '1.2.840.10045.4.3.2': deadline },
  hashDeadlines: { '2.16.840.1.101.3.4.2.1': deadline, '2.16.840.1.101.3.4.2.3': deadline },
  keyDeadlines: Object.fromEntries(
    [fixture.root, cert].map((raw) => [
      keyID(new X509Certificate(raw).publicKey).toString('hex'),
      deadline,
    ]),
  ),
  timestampPolicies: ['1.3.6.1.4.1.55555.91.1'],
  currentMaterial: { certificates: [cert, fixture.root], crls: [fixture.rootCRL] },
});

for (const [name, overall, reason] of [
  ['absent', 'VALID', 'CADES_VALID'],
  ['policySingle', 'VALID', 'CADES_VALID'],
  ['policyDistinct', 'VALID', 'CADES_VALID'],
  ['qualifiersNonempty', 'VALID', 'CADES_VALID'],
  ['policiesEmpty', 'INVALID', 'CADES_CERTIFICATE_POLICIES'],
  ['policyInformationEmpty', 'INVALID', 'CADES_CERTIFICATE_POLICIES'],
  ['policyQualifiersEmpty', 'INVALID', 'CADES_CERTIFICATE_POLICIES'],
  ['policyQualifierInfoEmpty', 'INVALID', 'CADES_CERTIFICATE_POLICIES'],
  ['policyQualifiersWrongTag', 'INVALID', 'CADES_CERTIFICATE_POLICIES'],
  ['duplicatePolicyOID', 'INVALID', 'CADES_CERTIFICATE_POLICIES'],
])
  test(`full CAdES signer certificate policy admission: ${name}`, () => {
    const { certificate, cms } = variants[name];
    const result = verifyCAdES(cms, {
      content: fixture.document,
      minimumLevel: 'B',
      validationTime: vectors.epoch + 40,
      knowledgeTime: vectors.epoch + 40,
      policy: policy(certificate),
    });
    assert.equal(result.overall, overall, JSON.stringify(result.checks));
    assert.equal(result.reason, reason, JSON.stringify(result.checks));
    if (overall === 'VALID') assert.equal(result.verifiedLevel, 'B');
  });
