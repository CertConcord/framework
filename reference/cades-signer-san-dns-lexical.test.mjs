import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { keyID, oidText, parseDER } from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { verifyCAdES } from './cades.mjs';
import { cmsView } from './cades-fixtures.mjs';

const raw = readFileSync(new URL('./vectors/cades-signer-san-dns-lexical.json', import.meta.url));
assert.equal(createHash('sha256').update(raw).digest('hex'),
  'dbcda6750b5c424ac08e4a86cac6d35bed3e39f6a387bfad26f826d5058b51eb');
const vectors = JSON.parse(raw);
assert.equal(vectors.schema, 'certconcord.cades-signer-san-dns-lexical.v1');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const decode = entry => {
  const bytes = Buffer.from(entry.derBase64, 'base64');
  assert.equal(bytes.length, entry.bytes);
  assert.equal(sha(bytes), entry.sha256);
  return bytes;
};
const root = decode(vectors.fixture.root);
const document = decode(vectors.fixture.document);
const crl = decode(vectors.fixture.crl);
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
const policy = certificate => ({ trustedRoots: [root], authorityResolver, scope,
  algorithmDeadlines: { '1.2.840.10045.4.3.2': deadline },
  hashDeadlines: { '2.16.840.1.101.3.4.2.1': deadline,
    '2.16.840.1.101.3.4.2.3': deadline },
  keyDeadlines: { [rootID]: deadline,
    [keyID(new X509Certificate(certificate).publicKey).toString('hex')]: deadline },
  timestampPolicies: ['1.3.6.1.4.1.55555.91.1'],
  currentMaterial: { certificates: [certificate, root], crls: [crl] } });

function signerSAN(certificate) {
  const tbs = parseDER(certificate).children[0];
  const extensions = tbs.children.at(-1).children[0].children;
  const san = extensions.find(entry => oidText(entry.children[0]) === '2.5.29.17');
  assert(san);
  return { tbs, extensions, names: parseDER(san.children.at(-1).value) };
}

for (const [name, entry] of Object.entries(vectors.cases))
  test(`CAdES B signer SAN dNSName boundaries: ${name}`, () => {
    const results = {};
    const views = {};
    const certificates = {};
    for (const kind of ['positive', 'negative']) {
      const variant = entry[kind];
      const certificate = decode(variant.certificate);
      const cms = decode(variant.cms);
      certificates[kind] = certificate;
      assert.equal(new X509Certificate(certificate).verify(rootKey), true);
      const actual = signerSAN(certificate);
      views[kind] = actual;
      assert.equal(sha(actual.tbs.raw), variant.tbsSHA256);
      assert.equal(actual.names.raw.toString('hex'), variant.sanDERHex);
      assert.equal(actual.names.children.length, 1);
      assert.equal(actual.names.children[0].tag, 0x82);
      assert.equal(actual.names.children[0].value.toString('ascii'), variant.dnsASCII);
      const cmsParsed = cmsView(cms);
      assert(cmsParsed.certificates.some(item => item.raw.equals(certificate)));
      assert(cmsParsed.certificates.some(item => item.raw.equals(root)));
      assert.equal(cmsParsed.crls.length, 0);
      results[kind] = verifyCAdES(cms, { content: document, minimumLevel: 'B',
        validationTime: vectors.epoch + 40, knowledgeTime: vectors.epoch + 40,
        policy: policy(certificate) });
    }
    const positive = views.positive;
    const negative = views.negative;
    assert.equal(positive.tbs.children.length, negative.tbs.children.length);
    for (let i = 0; i < positive.tbs.children.length - 1; i++)
      assert(positive.tbs.children[i].raw.equals(negative.tbs.children[i].raw));
    assert.equal(positive.extensions.length, negative.extensions.length);
    for (let i = 0; i < positive.extensions.length; i++)
      if (oidText(positive.extensions[i].children[0]) !== '2.5.29.17')
        assert(positive.extensions[i].raw.equals(negative.extensions[i].raw));
    assert(new X509Certificate(certificates.positive).publicKey.export({ type: 'spki', format: 'der' })
      .equals(new X509Certificate(certificates.negative).publicKey.export({ type: 'spki', format: 'der' })));
    if (name === 'dnsLabelLength63To64') {
      assert.equal(entry.positive.dnsASCII, `${'a'.repeat(63)}.example`);
      assert.equal(entry.negative.dnsASCII, `${'a'.repeat(64)}.example`);
    } else if (name === 'dnsLeadingHyphen') {
      assert.equal(entry.positive.dnsASCII, 'a.example');
      assert.equal(entry.negative.dnsASCII, '-.example');
    } else assert.fail(`unexpected case ${name}`);
    assert.equal(results.positive.overall, 'VALID', JSON.stringify(results.positive.checks));
    assert.equal(results.positive.reason, 'CADES_VALID');
    assert.equal(results.positive.verifiedLevel, 'B');
    assert.equal(results.negative.overall, 'INVALID', JSON.stringify(results.negative.checks));
    assert.equal(results.negative.reason, 'CADES_CERTIFICATE_SAN');
  });
