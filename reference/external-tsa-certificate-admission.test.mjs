import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { equal } from './core.mjs';
import { OID, parseCertificate, validateKeyUsage } from './pki.mjs';
import { verifyExternalCMS } from './external-cms.mjs';
import { parseTSTInfo, verifyExternalTimestampToken } from './timestamp.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/external-tsa-certificate-admission.json', import.meta.url), 'utf8'),
);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
function bytes(item) {
  const raw = Buffer.from(item.der, 'base64');
  assert.equal(sha256(raw), item.sha256);
  return raw;
}

test('external TSA certificate admission corpus retains three independent signed pairs', () => {
  assert.equal(vectors.schemaVersion, 1);
  assert.equal(vectors.profile, 'rfc5280-external-tsa-certificate-admission');
  assert.deepEqual(vectors.cases.map((row) => row.id), [
    'unknown-critical', 'keyusage-eku', 'issuer-name',
  ]);
  for (const row of vectors.cases) {
    const root = parseCertificate(bytes(row.root));
    const positive = parseCertificate(bytes(row.positive.certificate));
    const negative = parseCertificate(bytes(row.negative.certificate));
    const issuerKey = new X509Certificate(bytes(row.root)).publicKey;
    for (const label of ['positive', 'negative']) {
      const certificate = bytes(row[label].certificate);
      const token = bytes(row[label].token);
      assert(new X509Certificate(certificate).verify(issuerKey));
      assert(equal(verifyExternalCMS(token, {
        certificate, expectedContentType: OID.tstInfo,
      }).content, bytes(row.tstInfo)));
    }
    assert.equal(positive.serial, negative.serial);
    assert(equal(positive.subject, negative.subject));
    assert(equal(positive.spki, negative.spki));
    assert.equal(positive.notBefore, negative.notBefore);
    assert.equal(positive.notAfter, negative.notAfter);
    if (row.id === 'unknown-critical') {
      const unknown = '1.3.6.1.4.1.55555.91.100';
      assert(!positive.extensions.has(unknown));
      assert.equal(negative.extensions.get(unknown)?.critical, true);
      assert(equal(positive.issuer, negative.issuer));
    } else if (row.id === 'keyusage-eku') {
      assert.equal(validateKeyUsage(positive.extensions.get('2.5.29.15'))[0], 0x80);
      assert.equal(validateKeyUsage(negative.extensions.get('2.5.29.15'))[0], 0x20);
      assert(equal(positive.issuer, negative.issuer));
    } else {
      assert(equal(positive.issuer, root.subject));
      assert(!equal(negative.issuer, root.subject));
    }
  }
});

for (const row of vectors.cases)
  test(`external TSA certificate admission: ${row.id}`, () => {
    const root = bytes(row.root);
    const info = parseTSTInfo(bytes(row.tstInfo));
    const input = {
      issuerKey: new X509Certificate(root).publicKey,
      trustedIssuerName: parseCertificate(root).subject,
      imprint: info.imprint,
      hashOID: info.hashOID,
      nonce: info.nonce,
      policy: info.policy,
      at: info.genTime + 10,
      maxFutureSkew: 30,
    };
    const positive = {
      ...input, certificate: bytes(row.positive.certificate),
    };
    assert.deepEqual(
      verifyExternalTimestampToken(bytes(row.positive.token), positive).imprint,
      info.imprint,
    );
    assert.throws(
      () => verifyExternalTimestampToken(bytes(row.positive.token), {
        ...positive, trustedIssuerName: undefined,
      }),
      { code: 'TSA_TRUST_REQUIRED' },
    );
    assert.throws(
      () => verifyExternalTimestampToken(bytes(row.negative.token), {
        ...input, certificate: bytes(row.negative.certificate),
      }),
      { code: row.negative.code },
    );
  });
