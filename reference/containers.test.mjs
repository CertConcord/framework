import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as a from './archive.mjs';
import * as pdf from './pdf.mjs';
import { Journal } from './state.mjs';

function tsaFixture() {
  const root = c.generate('ml-dsa-87'),
    key = c.generate('ml-dsa-65'),
    journal = new Journal(),
    policy = '2.25.1234567890',
    certificate = p.issueCertificate(
      {
        publicKey: key.publicKey,
        issuer: p.name('Public test root'),
        subject: p.name('Public test TSA'),
        serial: 2,
        profileID: 'CERTCONCORD-TSA-v1',
      },
      root.privateKey,
    ),
    authority = new a.TimestampAuthority({
      certificate,
      privateKey: key.privateKey,
      policy,
      journal,
    });
  return {
    journal,
    authority,
    trust: { certificate, issuerKey: root.publicKey, policy },
    tsa: async (imprint, hashOID) =>
      a.tokenFromResponse(authority.issue(a.timestampRequest(imprint, { hashOID, policy }).der)),
  };
}
test('RFC3161 TSA request/response validates imprint, nonce, policy, EKU and POE interval', () => {
  const f = tsaFixture();
  try {
    const request = a.timestampRequest(c.sha512(Buffer.from('document')), {
        policy: f.trust.policy,
      }),
      token = a.tokenFromResponse(f.authority.issue(request.der));
    const v = a.verifyTimestampToken(token, { ...f.trust, ...request });
    assert.equal(v.poeUpperBound, v.genTime + 1);
    assert.throws(
      () => a.verifyTimestampToken(token, { ...f.trust, ...request, nonce: request.nonce + 1n }),
      /BINDING/,
    );
    assert.throws(
      () => a.verifyTimestampToken(token, { ...f.trust, ...request, revokedAt: 0 }),
      /REVOCATION/,
    );
  } finally {
    f.journal.close();
  }
});
test('RFC4998 creation, timestamp renewal and original-data hash renewal', async () => {
  const f = tsaFixture(),
    data = Buffer.from('Original evidence bytes');
  try {
    let r = await a.createERS(data, { tsa: f.tsa, hashOID: p.OID.sha256 });
    assert.equal(a.verifyERS(r, data, f.trust).chains, 1);
    r = await a.renewERS(r, data, { tsa: f.tsa });
    a.verifyERS(r, data, f.trust);
    r = await a.renewERS(r, data, { tsa: f.tsa, hashRenewal: true, hashOID: p.OID.sha512 });
    assert.equal(a.verifyERS(r, data, f.trust).chains, 2);
    assert.throws(() => a.verifyERS(r, Buffer.from('substituted'), f.trust));
  } finally {
    f.journal.close();
  }
});
test('RFC6283 XMLERS creation and both renewal paths, no DTD/entity expansion', async () => {
  const f = tsaFixture(),
    data = c.random(50);
  try {
    let r = await a.createXMLERS(data, { tsa: f.tsa, hashOID: p.OID.sha256 });
    assert.equal(a.verifyXMLERS(r, data, f.trust).chains, 1);
    r = await a.renewXMLERS(r, data, { tsa: f.tsa });
    a.verifyXMLERS(r, data, f.trust);
    r = await a.renewXMLERS(r, data, { tsa: f.tsa, hashRenewal: true });
    assert.equal(a.verifyXMLERS(r, data, f.trust).chains, 2);
    assert.throws(() => a.verifyXMLERS(r, c.random(50), f.trust));
    assert.throws(() => a.verifyXMLERS('<!DOCTYPE x>' + r, data, f.trust), /ENTITY/);
  } finally {
    f.journal.close();
  }
});
test('PAdES actual PDF ByteRange, detached CMS and incremental second signature', async () => {
  const root = c.generate('ml-dsa-87'),
    key = c.generate('ml-dsa-65'),
    certificate = p.issueCertificate(
      {
        publicKey: key.publicKey,
        issuer: p.name('Test issuer'),
        subject: p.name('Test signer'),
        serial: 3,
      },
      root.privateKey,
    ),
    original = await pdf.examplePDF();
  const preparation = await pdf.preparePDF(original),
    cms = p.signCMS({ content: preparation.content, certificate, detached: true }, key.privateKey),
    signed = preparation.finish(cms),
    verified = await pdf.verifyPDF(signed, { issuerKey: root.publicKey });
  assert(verified.currentRevisionCovered);
  assert.equal(verified.signatures.length, 1);
  assert(c.equal(signed.subarray(0, original.length), original));
  const second = await pdf.preparePDF(signed),
    twice = second.finish(
      p.signCMS({ content: second.content, certificate, detached: true }, key.privateKey),
    ),
    v = await pdf.verifyPDF(twice);
  assert.equal(v.signatures.length, 2);
  assert.equal(v.signatures[0].currentRevisionCovered, false);
  assert(v.signatures[1].currentRevisionCovered);
  const bad = Buffer.from(signed);
  bad[30] ^= 1;
  await assert.rejects(pdf.verifyPDF(bad));
  await assert.rejects(pdf.verifyPDF(signed.subarray(0, -15)));
});
