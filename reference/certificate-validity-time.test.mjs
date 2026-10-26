import test from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import * as c from './core.mjs';
import * as p from './pki.mjs';

const issuer = c.generate('ec'),
  subject = p.name('Synthetic certificate validity'),
  periods = [
    [
      '1949 compatibility',
      '1949-12-30T00:00:00Z',
      '1949-12-31T23:59:59Z',
      [24, 24],
      ['19491230000000Z', '19491231235959Z'],
    ],
    [
      '1950 pivot',
      '1950-01-01T00:00:00Z',
      '1950-01-02T00:00:00Z',
      [23, 23],
      ['500101000000Z', '500102000000Z'],
    ],
    [
      'before Unix epoch',
      '1969-12-30T00:00:00Z',
      '1969-12-31T23:59:59Z',
      [23, 23],
      ['691230000000Z', '691231235959Z'],
    ],
    [
      '2000 pivot',
      '1999-12-31T23:59:59Z',
      '2000-01-01T00:00:00Z',
      [23, 23],
      ['991231235959Z', '000101000000Z'],
    ],
    [
      'current era',
      '2026-10-26T12:34:56Z',
      '2026-10-27T12:34:56Z',
      [23, 23],
      ['261026123456Z', '261027123456Z'],
    ],
    [
      'leap day',
      '2048-02-28T23:59:59Z',
      '2048-02-29T00:00:01Z',
      [23, 23],
      ['480228235959Z', '480229000001Z'],
    ],
    [
      '2049',
      '2049-01-01T00:00:00Z',
      '2049-01-02T00:00:00Z',
      [23, 23],
      ['490101000000Z', '490102000000Z'],
    ],
    [
      '2050 transition',
      '2049-12-31T23:59:59Z',
      '2050-01-01T00:00:01Z',
      [23, 24],
      ['491231235959Z', '20500101000001Z'],
    ],
    [
      '2050',
      '2050-01-01T00:00:00Z',
      '2050-01-02T00:00:00Z',
      [24, 24],
      ['20500101000000Z', '20500102000000Z'],
    ],
    [
      '9999',
      '9999-12-30T00:00:00Z',
      '9999-12-31T23:59:59Z',
      [24, 24],
      ['99991230000000Z', '99991231235959Z'],
    ],
  ];
const seconds = (text) => Date.parse(text) / 1000,
  validity = (tbs) => c.parseDER(tbs).children[4].children;

for (const [label, before, after, tags, texts] of periods)
  for (const ca of [false, true])
    test('certificate issuer chooses each validity Time: ' + label + (ca ? ' CA' : ' leaf'), () => {
      const notBefore = seconds(before),
        notAfter = seconds(after),
        raw = p.issueCertificate(
          {
            publicKey: issuer.publicKey,
            issuer: subject,
            subject,
            serial: 1,
            profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
            ca,
            notBefore,
            notAfter,
          },
          issuer.privateKey,
        ),
        parsed = p.parseCertificate(raw),
        native = new X509Certificate(raw),
        fields = validity(parsed.tbs);
      assert.deepEqual(
        fields.map((v) => v.tag),
        tags,
      );
      assert.deepEqual(
        fields.map((v) => v.value.toString('ascii')),
        texts,
      );
      assert.equal(parsed.notBefore, notBefore);
      assert.equal(parsed.notAfter, notAfter);
      assert.equal(native.validFromDate.getTime(), notBefore * 1000);
      assert.equal(native.validToDate.getTime(), notAfter * 1000);
      assert.equal(native.verify(issuer.publicKey), true);
      assert.deepEqual(
        p.validateCertificate(raw, issuer.publicKey, { at: notBefore, allowCA: ca }).raw,
        raw,
      );
      // Changing the writer does not change the existing validation-time endpoint contract.
      assert.throws(
        () => p.validateCertificate(raw, issuer.publicKey, { at: notAfter, allowCA: ca }),
        { code: 'CERTIFICATE_TIME' },
      );
    });

test('generalizedTime remains GeneralizedTime for its non-certificate callers', () => {
  for (const [, before, after] of periods)
    for (const value of [before, after])
      assert.equal(c.parseDER(p.generalizedTime(seconds(value))).tag, 24);
});

for (const [label, before, after] of periods.filter((p) => p[3].includes(23)))
  test('signed historical GeneralizedTime certificate retains exact bytes: ' + label, () => {
    const notBefore = seconds(before),
      notAfter = seconds(after),
      current = p.tbsCertificate({
        publicKey: issuer.publicKey,
        issuer: subject,
        subject,
        serial: 2,
        signatureAlgorithm: 'ec',
        profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
        notBefore,
        notAfter,
      }),
      fields = c.parseDER(current).children.map((field) => field.raw);
    fields[4] = c.seq(p.generalizedTime(notBefore), p.generalizedTime(notAfter));
    const oldTBS = c.seq(...fields),
      signature = c.sign(oldTBS, issuer.privateKey),
      old = p.certificateFromTBS(oldTBS, 'ec', signature),
      retained = p.validateCertificate(old, issuer.publicKey, { at: notBefore });
    assert.deepEqual(
      validity(retained.tbs).map((value) => value.tag),
      [24, 24],
    );
    assert.deepEqual(retained.tbs, oldTBS);
    assert.deepEqual(retained.raw, old);
    assert.deepEqual(retained.certificateID, c.H('CertificateTBS', oldTBS));
    assert.deepEqual(retained.representationHash, c.sha512(old));
    assert.equal(new X509Certificate(old).verify(issuer.publicKey), true);
    assert.notDeepEqual(oldTBS, current);
    const rebound = p.certificateFromTBS(current, 'ec', signature);
    assert.throws(() => p.validateCertificate(rebound, issuer.publicKey, { at: notBefore }), {
      code: 'CERTIFICATE_SIGNATURE',
    });
  });

for (const year of ['-195000', '-204900'])
  test('out-of-profile extended year preserves generalized encoder bytes: ' + year, () => {
    const notBefore = seconds(year + '-01-01T00:00:00Z'),
      notAfter = notBefore + 86400,
      tbs = p.tbsCertificate({
        publicKey: issuer.publicKey,
        issuer: subject,
        subject,
        serial: 3,
        signatureAlgorithm: 'ec',
        ca: true,
        notBefore,
        notAfter,
      });
    const fields = validity(tbs);
    assert.deepEqual(
      fields.map((value) => value.tag),
      [24, 24],
    );
    assert.deepEqual(fields[0].raw, p.generalizedTime(notBefore));
    assert.deepEqual(fields[1].raw, p.generalizedTime(notAfter));
  });
