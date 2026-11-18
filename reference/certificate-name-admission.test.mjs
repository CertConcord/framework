import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, verify, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { der, keyID, parseDER } from './core.mjs';
import { validateCertificate } from './pki.mjs';
import { verifyCAdES } from './cades.mjs';
import { createAuthorityResolver } from './authority-history.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors/certificate-name-admission.json', import.meta.url)));
const original = ({ base64, sha256 }) => {
  const raw = Buffer.from(base64, 'base64');
  assert.equal(createHash('sha256').update(raw).digest('hex'), sha256);
  return raw;
};
const root = original(vectors.root), crl = original(vectors.crl),
  document = original(vectors.document), epoch = vectors.epoch;
const issuerKey = new X509Certificate(root).publicKey;
const cases = new Map(vectors.cases.map((entry) => [entry.id, {
  certificate: original(entry.certificate), cms: original(entry.cms),
}]));

test('frozen certificate and document signatures are independently valid', () => {
  assert.equal(vectors.schema, 'certconcord-certificate-name-admission-v1');
  for (const { certificate, cms } of cases.values()) {
    const x509 = new X509Certificate(certificate);
    const cert = parseDER(certificate);
    assert(verify('sha256', cert.children[0].raw, issuerKey,
      cert.children[2].value.subarray(1)));
    const signedData = parseDER(cms).children[1].children[0];
    const signerInfo = signedData.children[4].children[0].children;
    assert(verify('sha256', der(0x31, signerInfo[3].value), x509.publicKey,
      signerInfo[5].value));
  }
  const subject = (id) => parseDER(cases.get(id).certificate).children[0].children[5];
  assert.equal(subject('empty-subject-no-san').raw.toString('hex'), '3000');
  assert.equal(subject('empty-subject-critical-san').raw.toString('hex'), '3000');
  const goodCN = subject('nonempty-subject').children[0].children[0].children[1];
  const badCN = subject('common-name-ia5string').children[0].children[0].children[1];
  assert.equal(goodCN.tag, 0x0c);
  assert.equal(badCN.tag, 0x16);
  assert(goodCN.value.equals(badCN.value));
});

test('shared certificate admission binds an empty subject to critical SAN', () => {
  assert.equal(validateCertificate(cases.get('nonempty-subject').certificate, issuerKey,
    { at: epoch }).subject.toString('hex').startsWith('30'), true);
  assert.throws(() => validateCertificate(cases.get('empty-subject-no-san').certificate,
    issuerKey, { at: epoch }), (error) => error.code === 'CERTIFICATE_EMPTY_SUBJECT');
  assert.throws(() => validateCertificate(cases.get('empty-subject-critical-san').certificate,
    issuerKey, { at: epoch }), (error) => error.code === 'UNKNOWN_CRITICAL_EXTENSION');
});

test('commonName rejects IA5String while retaining a UTF8String control', () => {
  assert(validateCertificate(cases.get('nonempty-subject').certificate, issuerKey, { at: epoch }));
  assert.throws(() => validateCertificate(cases.get('common-name-ia5string').certificate,
    issuerKey, { at: epoch }), (error) => error.code === 'CERTIFICATE_COMMON_NAME_TYPE');
});

test('full CAdES B admission rejects identityless and mistyped signers', () => {
  const domain = Buffer.alloc(32, 0x91);
  const scope = { trustDomainID: domain, issuerID: 'cades-fixture', representation: 'X509' };
  const rootID = keyID(issuerKey).toString('hex');
  const status = { authorityID: Buffer.from(rootID, 'hex'), trustDomainID: domain,
    scope: 'AUTHORITY', status: 'GOOD', publishedAt: epoch - 100,
    nextUpdate: epoch + 100000 };
  const authorityResolver = createAuthorityResolver({ trustDomainID: domain,
    authorities: [{ mode: 'CERTIFICATE', certificate: root,
      knownAt: epoch - 100, validFrom: epoch - 100, validUntil: epoch + 100000,
      roles: ['ISSUER', 'STATUS_AUTHORITY'], scopes: [scope], status }] });
  const O = { es256: '1.2.840.10045.4.3.2', sha256: '2.16.840.1.101.3.4.2.1',
    sha512: '2.16.840.1.101.3.4.2.3', policy: '1.3.6.1.4.1.55555.91.1' };
  const expected = {
    'nonempty-subject': ['VALID', 'CADES_VALID', 'B'],
    'empty-subject-no-san': ['INVALID', 'CERTIFICATE_EMPTY_SUBJECT', undefined],
    'empty-subject-critical-san': ['UNSUPPORTED', 'CADES_CERTIFICATE_EXTENSION_UNSUPPORTED', undefined],
    'common-name-ia5string': ['INVALID', 'CERTIFICATE_COMMON_NAME_TYPE', undefined],
  };
  for (const [id, { certificate, cms }] of cases) {
    const signerID = keyID(new X509Certificate(certificate).publicKey).toString('hex');
    const policy = { trustedRoots: [root], authorityResolver, scope,
      algorithmDeadlines: { [O.es256]: epoch + 100000 },
      hashDeadlines: { [O.sha256]: epoch + 100000, [O.sha512]: epoch + 100000 },
      keyDeadlines: { [signerID]: epoch + 100000, [rootID]: epoch + 100000 },
      timestampPolicies: [O.policy],
      currentMaterial: { certificates: [certificate, root], crls: [crl] } };
    const result = verifyCAdES(cms, { content: document, minimumLevel: 'B',
      validationTime: epoch + 40, knowledgeTime: epoch + 40, policy });
    assert.deepEqual([result.overall, result.reason, result.verifiedLevel], expected[id], id);
  }
});
