import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as m from './mtc.mjs';

const profileID = 'CERTCONCORD-PERSON-SIGN-v1';

function changeUsage(tbs, transform) {
  const parsed = c.parseDER(tbs),
    container = parsed.children.find((n) => n.tag === 0xa3),
    extensions = container.children[0].children.map((e) =>
      c.oidText(e.children[0]) === '2.5.29.15' ? transform(e) : e.raw,
    );
  return c.seq(
    ...parsed.children.map((n) => (n === container ? c.der(0xa3, c.seq(...extensions)) : n.raw)),
  );
}

const inner = (raw) => (e) => c.seq(...e.children.slice(0, -1).map((n) => n.raw), c.octet(raw));
const malformed = {
  'OCTET STRING substituted for BIT STRING': inner(c.der(4, Buffer.from([7, 128]))),
  'INTEGER substituted for BIT STRING': inner(c.der(2, Buffer.from([7, 128]))),
  'unused-bit count above seven': inner(c.der(3, Buffer.from([8, 128]))),
  'nonminimal named-bit encoding': inner(c.der(3, Buffer.from([0, 128]))),
  'overlong named-bit encoding': inner(c.der(3, Buffer.from([7, 128, 0]))),
  'additional decipherOnly usage': inner(c.der(3, Buffer.from([7, 128, 128]))),
  'undefined usage beyond bit eight': inner(c.der(3, Buffer.from([6, 128, 64]))),
  'nonzero padding bits': inner(c.der(3, Buffer.from([7, 129]))),
  'zero usages': inner(c.der(3, Buffer.from([0, 0]))),
  'empty BIT STRING': inner(c.der(3, Buffer.from([0]))),
  'trailing value': inner(
    Buffer.concat([c.der(3, Buffer.from([7, 128])), c.der(5, Buffer.alloc(0))]),
  ),
  'extension value has wrong outer tag': (e) =>
    c.seq(...e.children.slice(0, -1).map((n) => n.raw), c.der(0x80, e.children.at(-1).value)),
  'extension OID has wrong tag': (e) =>
    c.seq(c.der(13, e.children[0].value), ...e.children.slice(1).map((n) => n.raw)),
  'extension has extra field': (e) =>
    c.seq(
      ...e.children.slice(0, -1).map((n) => n.raw),
      c.der(5, Buffer.alloc(0)),
      e.children.at(-1).raw,
    ),
};

for (const representation of ['PKIX', 'MTC']) {
  test(representation + ' rejects signed malformed KeyUsage extension schemas', async (t) => {
    const ca = c.generate('ml-dsa-87'),
      key = c.generate('ml-dsa-87'),
      options = { publicKey: key.publicKey, subject: p.name('Synthetic usage subject'), profileID },
      caID = '32473.10',
      members = [{ id: '32473.20', operatorID: 'synthetic-mirror', ...c.generate('ml-dsa-87') }],
      trust = {
        caID,
        caPublicKey: ca.publicKey,
        members,
        threshold: 1,
        policyHash: c.random(64),
        membershipEpoch: 1,
        rtmHash: c.random(64),
        profileID,
      },
      tbs =
        representation === 'PKIX'
          ? p.tbsCertificate({
              ...options,
              issuer: p.name('Synthetic usage CA'),
              serial: 1,
              signatureAlgorithm: 'ml-dsa-87',
            })
          : m.createMTCTBS(options, { caID, logNumber: 1, index: 0 }),
      certify = (value) =>
        representation === 'PKIX'
          ? p.certificateFromTBS(value, 'ml-dsa-87', c.sign(value, ca.privateKey))
          : m.issueMTC(value, {
              entries: [m.logEntryFromTBS(value)],
              index: 0,
              caID,
              logNumber: 1,
              cosigners: [{ id: caID, ...ca }, ...members],
            }),
      validate = (certificate) =>
        representation === 'PKIX'
          ? p.validateCertificate(certificate, ca.publicKey, { profileID })
          : m.verifyMTC(certificate, trust);
    assert.ok(validate(certify(tbs)));
    for (const [description, transform] of Object.entries(malformed))
      await t.test(description, () => {
        const certificate = certify(changeUsage(tbs, transform));
        assert.throws(
          () => validate(certificate),
          (error) => error instanceof c.ProtocolError,
        );
      });
  });
}
