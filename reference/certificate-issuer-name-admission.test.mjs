import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify, X509Certificate } from 'node:crypto';
import { der, parseDER, seq, ProtocolError } from './core.mjs';
import { issueCertificate, name, parseCertificate, validateCertificate } from './pki.mjs';

const at = Date.parse('2026-11-10T19:00:00Z') / 1000;

function signedCertificate(issuerField, issuerKey, canonical) {
  const root = parseDER(canonical);
  const original = root.children[0].children;
  const tbs = seq(...original.map((field, i) => (i === 3 ? issuerField : field.raw)));
  const signature = sign(null, tbs, issuerKey.privateKey);
  return {
    raw: seq(tbs, root.children[1].raw, der(3, Buffer.concat([Buffer.from([0]), signature]))),
    tbs,
    signature,
  };
}

test('certificate issuer Name requires a nonempty RDNSequence before native key import', () => {
  const issuerKey = generateKeyPairSync('ed25519');
  const issuer = name('Synthetic issuer Name admission');
  const canonical = issueCertificate(
    {
      publicKey: issuerKey.publicKey,
      issuer,
      subject: issuer,
      serial: 73,
      notBefore: at - 60,
      notAfter: at + 60,
      ca: true,
    },
    issuerKey.privateKey,
  );
  const root = parseDER(canonical);
  const originalTbs = root.children[0].children;
  assert.equal(originalTbs[3].tag, 0x30);
  assert.equal(originalTbs[3].children.length, 1);
  assert.deepEqual(parseCertificate(canonical).issuer, issuer);
  assert.deepEqual(validateCertificate(canonical, issuerKey.publicKey, { at, allowCA: true }).raw, canonical);
  assert.doesNotThrow(() => new X509Certificate(canonical));

  for (const [label, issuerField] of [
    ['SET container', der(0x31, originalTbs[3].value)],
    ['empty RDNSequence', seq()],
  ]) {
    const altered = signedCertificate(issuerField, issuerKey, canonical);
    const fields = parseDER(altered.tbs).children;
    assert.deepEqual(fields[3].raw, issuerField);
    assert(fields.every((field, i) => i === 3 || field.raw.equals(originalTbs[i].raw)));
    assert.equal(verify(null, altered.tbs, issuerKey.publicKey, altered.signature), true);
    assert.throws(
      () => parseCertificate(altered.raw),
      (error) => error instanceof ProtocolError && error.code === 'CERTIFICATE_ISSUER_NAME',
      label,
    );
    assert.throws(
      () => validateCertificate(altered.raw, issuerKey.publicKey, { at, allowCA: true }),
      (error) => error instanceof ProtocolError && error.code === 'CERTIFICATE_ISSUER_NAME',
      label,
    );
    if (label === 'SET container') assert.throws(() => new X509Certificate(altered.raw));
  }

  const badSignature = Buffer.from(canonical);
  badSignature[badSignature.length - 1] ^= 1;
  assert.doesNotThrow(() => parseCertificate(badSignature));
  assert.throws(
    () => validateCertificate(badSignature, issuerKey.publicKey, { at, allowCA: true }),
    (error) => error instanceof ProtocolError && error.code === 'CERTIFICATE_SIGNATURE',
  );
});
