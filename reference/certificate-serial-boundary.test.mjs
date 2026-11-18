import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { issueIACA, issueMdocCertificate, validateMdocCertificate } from './mdoc-pki.mjs';
import { inspectAdESSignature } from './ades-cms.mjs';
import { prepareCAdESSignature, verifyCAdES } from './cades.mjs';
import { fixture, epoch, opensslAvailable } from './cades-fixtures.mjs';

const vector = JSON.parse(readFileSync(new URL('./vectors/certificate-serial-boundary.json', import.meta.url)));
const serialNode = name => c.parseDER(Buffer.from(vector.cases[name].serialDER, 'hex'));
const replaceSerial = (certificate, serial, issuerKey) => {
  const tbs = c.parseDER(certificate).children[0];
  const next = c.seq(...tbs.children.map((field, index) => index === 1 ? serial.raw : field.raw));
  return p.certificateFromTBS(next, 'ec', c.sign(next, issuerKey));
};

test('shared CA issuance rejects zero while external mdoc certificate parsing remains separate', () => {
  const at = epoch, issuer = c.generate('ec'), signer = c.generate('ec');
  assert.equal(c.intValue(serialNode('positive')), 1n);
  assert.equal(c.intValue(serialNode('zero')), 0n);
  const iaca = issueIACA({ publicKey: issuer.publicKey, privateKey: issuer.privateKey,
    subject: p.name('Synthetic IACA'), serial: 17,
    issuerAltName: 'https://synthetic.example', crlURL: 'https://synthetic.example/crl',
    notBefore: at - 100, notAfter: at + 1000 });
  const options = { publicKey: signer.publicKey, subject: p.name('Synthetic mdoc signer'),
    issuerCertificate: iaca, issuerKey: issuer.privateKey,
    notBefore: at - 50, notAfter: at + 100 };
  const positive = issueMdocCertificate({ ...options, serial: 1 });
  assert.equal(p.parseCertificate(positive).serial, 1n);
  assert.equal(validateMdocCertificate(positive, { issuerKey: issuer.publicKey, at }).serial, 1n);
  assert.throws(() => issueMdocCertificate({ ...options, serial: 0 }),
    { code: vector.cases.zero.issuer });
  assert.throws(() => p.issueCertificate({ publicKey: signer.publicKey,
    issuer: p.name('Synthetic IACA'), subject: p.name('Synthetic generic signer'),
    serial: 0, notBefore: at - 50, notAfter: at + 100 }, issuer.privateKey),
  { code: vector.cases.zero.issuer });
  assert.throws(() => p.tbsCertificate({ publicKey: signer.publicKey,
    issuer: p.name('Synthetic IACA'), subject: p.name('Synthetic generic signer'),
    serial: 0, signatureAlgorithm: 'ec', notBefore: at - 50, notAfter: at + 100 }),
  { code: vector.cases.zero.issuer });
  const base = { publicKey: signer.publicKey, issuer: p.name('Synthetic IACA'),
    subject: p.name('Synthetic generic signer'), signatureAlgorithm: 'ec',
    notBefore: at - 50, notAfter: at + 100 };
  assert.equal(c.parseDER(p.tbsCertificate({ ...base, serial: 1n << 151n }))
    .children[1].value.length, 20);
  assert.throws(() => p.tbsCertificate({ ...base, serial: 1n << 159n }),
    { code: 'CERTIFICATE_SERIAL_LENGTH' });

  const externalZero = replaceSerial(positive, serialNode('zero'), issuer.privateKey);
  assert.equal(p.parseCertificate(externalZero).serial, 0n);
  assert(new X509Certificate(externalZero).verify(issuer.publicKey));
  assert.equal(validateMdocCertificate(externalZero, { issuerKey: issuer.publicKey, at }).serial, 0n);
});

test('signed CAdES zero-serial reception reports unsupported status semantics without accepting trust',
  { skip: !opensslAvailable }, () => {
    const f = fixture();
    try {
      const positiveCMS = f.baseCMS({ prepareCAdESSignature }, { detached: false });
      const externalZero = replaceSerial(f.signer.der, serialNode('zero'), f.root.privateKey);
      assert.equal(p.parseCertificate(externalZero).serial, 0n);
      assert(new X509Certificate(externalZero).verify(f.root.publicKey));
      const prepared = prepareCAdESSignature({ content: f.content, certificate: externalZero,
        certificates: [f.root.der], detached: false, signingTime: epoch + 10,
        algorithmProfile: 'ES256' });
      const zeroCMS = prepared.finish(c.sign(prepared.tbs, f.signer.privateKey));
      const options = { content: f.content, minimumLevel: 'B', validationTime: epoch + 40,
        knowledgeTime: epoch + 40, policy: f.policy() };
      assert.equal(inspectAdESSignature(positiveCMS, { profile: 'CADES' }).overall, 'VALID');
      assert.equal(inspectAdESSignature(zeroCMS, { profile: 'CADES' }).overall, 'VALID');
      const positive = verifyCAdES(positiveCMS, options);
      assert.equal(positive.overall, vector.cases.positive.cadesReceiver);
      assert.equal(positive.verifiedLevel, 'B');
      const zero = verifyCAdES(zeroCMS, options);
      assert.equal(zero.overall, vector.cases.zero.cadesReceiver);
      assert.equal(zero.reason, vector.cases.zero.cadesReason);
      assert.notEqual(zero.verifiedLevel, 'B');
    } finally { f.close(); }
  });

test('complete CRL serial-zero entry remains outside selected CAdES status profile',
  { skip: !opensslAvailable }, () => {
    const f = fixture();
    try {
      const cms = f.baseCMS({ prepareCAdESSignature }, { detached: false });
      const policy = f.policy({ currentMaterial: {
        certificates: [f.root.der, f.signer.der],
        crls: [f.crl({ entries: [{ serial: 0, revokedAt: epoch }] })],
      } });
      const decision = verifyCAdES(cms, { content: f.content, minimumLevel: 'B',
        validationTime: epoch + 40, knowledgeTime: epoch + 40, policy });
      assert.equal(decision.overall, 'INVALID');
      assert.equal(decision.reason, 'CADES_CRL_ENTRY');
    } finally { f.close(); }
  });
