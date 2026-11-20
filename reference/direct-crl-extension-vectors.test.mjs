import assert from 'node:assert/strict';
import { createHash, verify as verifySignature, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { verifyCAdES } from './cades.mjs';
import { verifyCRL } from './revocation.mjs';
import { identityCRLValidator } from './identity.mjs';
import { Journal } from './state.mjs';

const raw = readFileSync(new URL('./vectors/direct-crl-extension-admission.json', import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(sha(raw), '5ec33caf367a33d0d379725bccab8e7cf5bc427c811745c29e5c5ab5eaf4653c');
const vectors = JSON.parse(raw);
assert.equal(vectors.schema, 'certconcord.direct-crl-extension-admission.v1');
assert.equal(vectors.baseMain, '723af0d3aa8912e6c2eb14e05ec53e12f61123d3');
const decode = entry => {
  const bytes = Buffer.from(entry.derBase64, 'base64');
  assert.equal(bytes.length, entry.bytes);
  assert.equal(sha(bytes), entry.sha256);
  return bytes;
};
const signedBy = (raw, key) => {
  const parsed = c.parseDER(raw);
  return parsed.tag === 0x30 && parsed.children.length === 3 &&
    verifySignature('sha256', parsed.children[0].raw,
      key, parsed.children[2].value.subarray(1));
};

const document = vectors.document;
const root = decode(document.root);
const signer = decode(document.signer);
const content = decode(document.content);
const cms = decode(document.cms);
const rootKey = new X509Certificate(root).publicKey;
const signerKey = new X509Certificate(signer).publicKey;
assert(new X509Certificate(root).verify(rootKey));
assert(new X509Certificate(signer).verify(rootKey));
const signedData = c.parseDER(cms).children[1].children[0];
const signerInfo = signedData.children.at(-1).children[0].children;
assert(signerInfo[3].tag === 0xa0 && signerInfo[5].tag === 4);
assert(verifySignature('sha256', c.der(0x31, signerInfo[3].value),
  signerKey, signerInfo[5].value), 'CMS signer signature is valid');
const domain = Buffer.alloc(32, 0x91);
const scope = { trustDomainID: domain, issuerID: 'cades-fixture', representation: 'X509' };
const deadline = document.at - 40 + 100000;
const rootID = c.keyID(rootKey).toString('hex');
const signerID = c.keyID(signerKey).toString('hex');
const authorityResolver = createAuthorityResolver({ trustDomainID: domain,
  authorities: [{ mode: 'CERTIFICATE', certificate: root,
    knownAt: document.at - 140, validFrom: document.at - 140,
    validUntil: deadline, roles: ['ISSUER', 'STATUS_AUTHORITY'], scopes: [scope],
    status: { authorityID: Buffer.from(rootID, 'hex'), trustDomainID: domain,
      scope: 'AUTHORITY', status: 'GOOD', publishedAt: document.at - 140,
      nextUpdate: deadline } }] });
const policyFor = crl => ({ trustedRoots: [root], authorityResolver, scope,
  algorithmDeadlines: { '1.2.840.10045.4.3.2': deadline },
  hashDeadlines: { '2.16.840.1.101.3.4.2.1': deadline,
    '2.16.840.1.101.3.4.2.3': deadline },
  keyDeadlines: { [rootID]: deadline, [signerID]: deadline },
  timestampPolicies: ['1.3.6.1.4.1.55555.91.1'],
  currentMaterial: { certificates: [signer, root], crls: [crl] } });

for (const row of document.cases) {
  test(`frozen signed CAdES B complete CRL ${row.id}`, () => {
    const crl = decode(row.crl);
    assert(signedBy(crl, rootKey), 'each CRL has a valid issuer signature');
    const result = verifyCAdES(cms, { content, minimumLevel: 'B',
      validationTime: document.at, knowledgeTime: document.at,
      policy: policyFor(crl) });
    assert.equal(result.overall, row.expected.overall, row.id);
    assert.equal(result.reason, row.expected.reason, row.id);
    if (row.expected.overall === 'VALID') assert.equal(result.verifiedLevel, 'B');
  });
}

test('frozen signed identity CRL rejects critical nonce and preserves journal state', async () => {
  const v = vectors.identity;
  const issuer = decode(v.issuerCertificate);
  const certificate = decode(v.certificate);
  const positive = decode(v.positiveCRL);
  const negative = decode(v.criticalNonceCRL);
  const issuerKey = new X509Certificate(issuer).publicKey;
  assert(signedBy(positive, issuerKey));
  assert(signedBy(negative, issuerKey));
  const options = { issuer: p.parseCertificate(issuer).subject,
    publicKey: issuerKey, serial: BigInt(v.serial), at: v.at };
  assert.equal(verifyCRL(positive, options).status, v.expected.positive);
  assert.equal(verifyCRL(negative, options).reason, v.expected.criticalNonce);
  const journal = new Journal();
  const watermarkID = c.b64u(c.sha512(issuer));
  let current = negative;
  try {
    const admit = identityCRLValidator({ issuerCertificate: issuer,
      journal, fetchCRL: async () => current });
    await assert.rejects(admit({ certificate, at: v.at }),
      { code: v.expected.criticalNonce });
    assert.equal(journal.get('identity-crl-watermark', watermarkID), undefined);
    current = positive;
    assert.equal((await admit({ certificate, at: v.at })).status, 'GOOD');
    const accepted = journal.get('identity-crl-watermark', watermarkID);
    current = negative;
    await assert.rejects(admit({ certificate, at: v.at }),
      { code: v.expected.criticalNonce });
    assert.deepEqual(journal.get('identity-crl-watermark', watermarkID), accepted);
  } finally {
    journal.close();
  }
});
