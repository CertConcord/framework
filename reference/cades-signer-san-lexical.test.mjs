import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { keyID, oidText, parseDER } from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { verifyCAdES } from './cades.mjs';

const raw = readFileSync(new URL('./vectors/cades-signer-san-lexical.json', import.meta.url));
assert.equal(createHash('sha256').update(raw).digest('hex'),
  'e06bafe6914bcab731b57d530ba9af072ebbd44b69a20cd041aba49edac7bf03');
const vectors = JSON.parse(raw);
assert.equal(vectors.schema, 'certconcord.cades-signer-san-lexical.v1');
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
  return { tbs: tbs.raw, names: parseDER(san.children.at(-1).value) };
}

for (const [name, entry] of Object.entries(vectors.cases))
  test(`CAdES B signer SAN lexical admission: ${name}`, () => {
    const results = {};
    const tbs = {};
    for (const kind of ['positive', 'negative']) {
      const variant = entry[kind];
      const certificate = decode(variant.certificate);
      const cms = decode(variant.cms);
      assert.equal(new X509Certificate(certificate).verify(rootKey), true);
      const actualSAN = signerSAN(certificate);
      tbs[kind] = actualSAN.tbs;
      assert.equal(sha(actualSAN.tbs), variant.tbsSHA256);
      assert.equal(actualSAN.names.children.length, 1);
      const value = actualSAN.names.children[0];
      assert.equal(value.tag, entry.tag);
      assert.equal(value.value.toString('hex'), variant.valueHex);
      assert.equal(actualSAN.names.raw.toString('hex'), variant.sanDERHex);
      results[kind] = verifyCAdES(cms, { content: document, minimumLevel: 'B',
        validationTime: vectors.epoch + 40, knowledgeTime: vectors.epoch + 40,
        policy: policy(certificate) });
    }
    assert.equal(tbs.positive.length, tbs.negative.length);
    const changed = [...tbs.positive.keys()].filter(i => tbs.positive[i] !== tbs.negative[i]);
    assert.deepEqual(changed, [entry.tbsDifferenceOffset]);
    assert.equal(tbs.positive[changed[0]], entry.positiveByte);
    assert.equal(tbs.negative[changed[0]], entry.negativeByte);
    assert.equal(results.positive.overall, 'VALID', JSON.stringify(results.positive.checks));
    assert.equal(results.positive.reason, 'CADES_VALID');
    assert.equal(results.positive.verifiedLevel, 'B');
    assert.equal(results.negative.overall, 'INVALID', JSON.stringify(results.negative.checks));
    assert.equal(results.negative.reason, 'CADES_CERTIFICATE_SAN');
  });
