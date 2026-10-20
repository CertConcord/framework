import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal } from './state.mjs';
import { issueCRL } from './revocation.mjs';
import { identityCRLValidator } from './identity.mjs';

const at = 1792530000;

function fixture(usage, critical = true) {
  const key = c.generate('ec'),
    issuerName = p.name('Synthetic CRL issuer'),
    fields = c.parseDER(
      p.tbsCertificate({
        publicKey: key.publicKey,
        issuer: issuerName,
        subject: issuerName,
        serial: 1,
        signatureAlgorithm: 'ec',
        ca: true,
        notBefore: at - 3600,
        notAfter: at + 3600,
      }),
    ).children,
    extensions = fields
      .at(-1)
      .children[0].children.filter((extension) => c.oidText(extension.children[0]) !== '2.5.29.15')
      .map((extension) => extension.raw),
    tbs = c.seq(
      ...fields.slice(0, -1).map((field) => field.raw),
      c.der(
        0xa3,
        c.seq(...extensions, ...(usage ? [p.extension('2.5.29.15', usage, critical)] : [])),
      ),
    ),
    issuerCertificate = p.certificateFromTBS(tbs, 'ec', c.sign(tbs, key.privateKey)),
    certificate = p.issueCertificate(
      {
        publicKey: c.generate('ec').publicKey,
        issuer: issuerName,
        subject: p.name('Synthetic document signer'),
        serial: 2,
        notBefore: at - 3600,
        notAfter: at + 1800,
      },
      key.privateKey,
    ),
    raw = issueCRL({
      issuer: issuerName,
      privateKey: key.privateKey,
      number: 7,
      thisUpdate: at - 60,
      nextUpdate: at + 600,
    });
  return { key, issuerName, issuerCertificate, certificate, raw };
}

for (const [label, usage] of [
  ['missing KeyUsage', undefined],
  ['digitalSignature without cRLSign', c.der(3, Buffer.from([7, 0x80]))],
  ['keyCertSign without cRLSign', c.der(3, Buffer.from([2, 0x04]))],
  ['wrong KeyUsage DER type', c.octet(Buffer.from([1, 0x02]))],
  ['noncanonical KeyUsage padding', c.der(3, Buffer.from([0, 0x02]))],
]) {
  test(`external identity CRL usage rejects ${label} before status work`, () => {
    const value = fixture(usage),
      journal = new Journal();
    let fetches = 0;
    try {
      assert.throws(
        () =>
          identityCRLValidator({
            issuerCertificate: value.issuerCertificate,
            journal,
            fetchCRL: async () => {
              fetches++;
              return value.raw;
            },
          }),
        { code: 'IDENTITY_CRL_KEY_USAGE' },
      );
      assert.equal(fetches, 0);
      assert.equal(
        journal.get('identity-crl-watermark', c.b64u(c.sha512(value.issuerCertificate))),
        undefined,
      );
    } finally {
      journal.close();
    }
  });
}

for (const [label, bits, critical] of [
  ['cRLSign alone', 0x02, true],
  ['cRLSign with digitalSignature', 0x82, true],
  ['noncritical cRLSign', 0x02, false],
]) {
  test(`external identity CRL usage accepts ${label} and records authenticated status`, async () => {
    const value = fixture(c.der(3, Buffer.from([1, bits])), critical),
      journal = new Journal();
    try {
      const validate = identityCRLValidator({
          issuerCertificate: value.issuerCertificate,
          journal,
          fetchCRL: async () => value.raw,
        }),
        status = await validate({ certificate: value.certificate, at }),
        row = journal.get('identity-crl-watermark', c.b64u(c.sha512(value.issuerCertificate)));
      assert.equal(status.status, 'GOOD');
      assert.equal(status.coverage, 'ISSUER_CERTIFICATE');
      assert.equal(status.credentialStatus, 'NOT_PROVIDED');
      assert.equal(status.validUntil, at + 600);
      assert.equal(row.value.number, 7);
      assert.deepEqual(row.value.digest, c.sha512(value.raw));
    } finally {
      journal.close();
    }
  });
}

test('external identity CRL usage does not authorize a different certificate issuer', async () => {
  const value = fixture(c.der(3, Buffer.from([1, 0x02]))),
    journal = new Journal(),
    certificate = p.issueCertificate(
      {
        publicKey: c.generate('ec').publicKey,
        issuer: p.name('Different certificate issuer'),
        subject: p.name('Synthetic document signer'),
        serial: 2,
        notBefore: at - 3600,
        notAfter: at + 1800,
      },
      value.key.privateKey,
    );
  try {
    const validate = identityCRLValidator({
      issuerCertificate: value.issuerCertificate,
      journal,
      fetchCRL: async () => value.raw,
    });
    await assert.rejects(validate({ certificate, at }), { code: 'IDENTITY_CRL_ISSUER' });
    assert.equal(
      journal.get('identity-crl-watermark', c.b64u(c.sha512(value.issuerCertificate))),
      undefined,
    );
  } finally {
    journal.close();
  }
});

test('external identity CRL usage does not authorize a different CRL scope', async () => {
  const value = fixture(c.der(3, Buffer.from([1, 0x02]))),
    journal = new Journal(),
    raw = issueCRL({
      issuer: p.name('Different CRL issuer'),
      privateKey: value.key.privateKey,
      number: 8,
      thisUpdate: at - 60,
      nextUpdate: at + 600,
    });
  try {
    const validate = identityCRLValidator({
      issuerCertificate: value.issuerCertificate,
      journal,
      fetchCRL: async () => raw,
    });
    await assert.rejects(validate({ certificate: value.certificate, at }), { code: 'CRL_SCOPE' });
    assert.equal(
      journal.get('identity-crl-watermark', c.b64u(c.sha512(value.issuerCertificate))),
      undefined,
    );
  } finally {
    journal.close();
  }
});
