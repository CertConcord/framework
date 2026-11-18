import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { der, keyID, oidText, parseDER, verify } from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { verifyCAdES } from './cades.mjs';
import { cmsView, O } from './cades-fixtures.mjs';

const raw = readFileSync(new URL('./vectors/cades-signer-freshestcrl-cardinality.json', import.meta.url));
assert.equal(createHash('sha256').update(raw).digest('hex'),
  '64a32ee554cb78cb5f9071a2ab7b6c4c310e3360dff294b7f9585dda41eb6758');
const vectors = JSON.parse(raw);
assert.equal(vectors.schema, 'certconcord.cades-signer-freshestcrl-cardinality.v1');
assert.equal(vectors.baseMain, '7bfccab63fe43ec9411bb9302fe6f8444bd8aaad');
const decode = entry => {
  const bytes = Buffer.from(entry.derBase64, 'base64');
  assert.equal(bytes.length, entry.bytes);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256);
  return bytes;
};

test('CAdES B admits one FreshestCRL distribution point and rejects present empty points', () => {
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
  const positiveTBS = parseDER(decode(vectors.positive.tbs)).children;
  const negativeTBS = parseDER(decode(vectors.negative.tbs)).children;
  assert.equal(positiveTBS.length, negativeTBS.length);
  for (let i = 0; i < positiveTBS.length - 1; i++)
    assert(positiveTBS[i].raw.equals(negativeTBS[i].raw));
  const positiveExtensions = positiveTBS.at(-1).children[0].children;
  const negativeExtensions = negativeTBS.at(-1).children[0].children;
  assert.equal(positiveExtensions.length, negativeExtensions.length);
  for (let i = 0; i < positiveExtensions.length - 1; i++)
    assert(positiveExtensions[i].raw.equals(negativeExtensions[i].raw));

  for (const [kind, expectedOverall, expectedReason] of [
    ['positive', 'VALID', 'CADES_VALID'],
    ['negative', 'INVALID', 'CADES_CERTIFICATE_FRESHESTCRL'],
  ]) {
    const variant = vectors[kind];
    const extension = (kind === 'positive' ? positiveExtensions : negativeExtensions).at(-1);
    assert.equal(oidText(extension.children[0]), vectors.extensionOID);
    assert(extension.children.at(-1).value.equals(decode(variant.freshestCRL)));
    assert.equal(decode(variant.freshestCRL).toString('hex'), vectors[`${kind}DERHex`]);
    const certificate = decode(variant.certificate);
    const cms = decode(variant.cms);
    const x509 = new X509Certificate(certificate);
    assert(x509.verify(rootKey), `${kind} issuer signature`);
    assert(parseDER(certificate).children[0].raw.equals(decode(variant.tbs)));
    const view = cmsView(cms);
    assert(view.certificates.some(cert => cert.raw.equals(certificate)));
    assert(view.certificates.some(cert => cert.raw.equals(root)));
    assert.equal(view.crls.length, 0);
    const signer = view.signer.children;
    assert(verify(der(0x31, signer[3].value), signer[5].value, x509.publicKey),
      `${kind} CMS signature`);
    const signerID = keyID(x509.publicKey).toString('hex');
    const policy = { trustedRoots: [root], authorityResolver, scope,
      algorithmDeadlines: { [O.es256]: deadline },
      hashDeadlines: { [O.sha256]: deadline, [O.sha512]: deadline },
      keyDeadlines: { [signerID]: deadline, [rootID]: deadline },
      timestampPolicies: [O.policy],
      currentMaterial: { certificates: [certificate, root], crls: [crl] } };
    const result = verifyCAdES(cms, { content: document, minimumLevel: 'B',
      validationTime: vectors.epoch + 40, knowledgeTime: vectors.epoch + 40, policy });
    assert.equal(result.overall, expectedOverall, `${kind}: ${JSON.stringify(result.checks)}`);
    assert.equal(result.reason, expectedReason, `${kind}: ${JSON.stringify(result.checks)}`);
    if (kind === 'positive') assert.equal(result.verifiedLevel, 'B');
  }
});
