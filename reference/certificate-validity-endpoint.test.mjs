import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as m from './mtc.mjs';

const notBefore = 1792972800,
  notAfter = notBefore + 10,
  profileID = 'CERTCONCORD-PERSON-SIGN-v1',
  issuer = c.generate('ml-dsa-87'),
  holder = c.generate('ml-dsa-65'),
  caID = '32473.510',
  members = [1, 2].map((n) => ({
    id: '32473.' + (510 + n),
    operatorID: 'endpoint-mirror-' + n,
    ...c.generate('ml-dsa-87'),
  })),
  points = [
    ['before notBefore', notBefore - 1, false],
    ['at notBefore', notBefore, true],
    ['before notAfter', notAfter - 0.125, true],
    ['at notAfter', notAfter, true],
    ['fraction after notAfter', notAfter + 0.125, false],
    ['second after notAfter', notAfter + 1, false],
  ];
function encodedTBS(tbs, encoding) {
  if (encoding === 'utc') return tbs;
  const fields = c.parseDER(tbs).children.map((field) => field.raw);
  fields[4] = c.seq(p.generalizedTime(notBefore), p.generalizedTime(notAfter));
  return c.seq(...fields);
}
for (const encoding of ['utc', 'generalized']) {
  const tbs = encodedTBS(
      p.tbsCertificate({
        publicKey: holder.publicKey,
        issuer: p.name('Synthetic endpoint issuer'),
        subject: p.name('Synthetic endpoint holder'),
        serial: 1,
        signatureAlgorithm: 'ml-dsa-87',
        profileID,
        notBefore,
        notAfter,
      }),
      encoding,
    ),
    raw = p.certificateFromTBS(tbs, 'ml-dsa-87', c.sign(tbs, issuer.privateKey));
  for (const [label, at, valid] of points)
    test('X.509 ' + encoding + ' certificate ' + label, () => {
      const validate = () => p.validateCertificate(raw, issuer.publicKey, { at, profileID });
      if (!valid) return assert.throws(validate, { code: 'CERTIFICATE_TIME' });
      const result = validate();
      assert.deepEqual(result.raw, raw);
      assert.deepEqual(result.tbs, tbs);
      assert.deepEqual(result.certificateID, c.H('CertificateTBS', tbs));
      assert.deepEqual(result.representationHash, c.sha512(raw));
    });
  test('X.509 ' + encoding + ' endpoint retains signature and profile checks', () => {
    const corrupted = Buffer.from(raw);
    corrupted[corrupted.length - 1] ^= 1;
    assert.throws(
      () => p.validateCertificate(corrupted, issuer.publicKey, { at: notAfter, profileID }),
      { code: 'CERTIFICATE_SIGNATURE' },
    );
    assert.throws(
      () =>
        p.validateCertificate(raw, issuer.publicKey, {
          at: notAfter,
          profileID: 'CERTCONCORD-TSA-v1',
        }),
      { code: 'CERTIFICATE_EKU' },
    );
  });
  test('CMS ' + encoding + ' explicit certificate endpoint remains signature checked', () => {
    const content = Buffer.from('Synthetic CMS certificate endpoint'),
      cms = p.signCMS({ content, certificate: raw }, holder.privateKey);
    const result = p.verifyCMS(cms, { issuerKey: issuer.publicKey, at: notAfter, profileID });
    assert.deepEqual(result.content, content);
    assert.equal(result.cryptographicValidity, 'VALID');
    assert.throws(
      () => p.verifyCMS(cms, { issuerKey: issuer.publicKey, at: notAfter + 0.125, profileID }),
      { code: 'CERTIFICATE_TIME' },
    );
    const corrupted = Buffer.from(cms);
    corrupted[corrupted.length - 1] ^= 1;
    assert.throws(
      () => p.verifyCMS(corrupted, { issuerKey: issuer.publicKey, at: notAfter, profileID }),
      { code: 'CMS_SIGNATURE' },
    );
  });

  const mtcTBS = encodedTBS(
      m.createMTCTBS(
        {
          publicKey: holder.publicKey,
          subject: p.name('Synthetic endpoint MTC'),
          profileID,
          notBefore,
          notAfter,
        },
        { caID, logNumber: 1, index: 0 },
      ),
      encoding,
    ),
    entries = [m.logEntryFromTBS(mtcTBS)],
    standalone = m.issueMTC(mtcTBS, {
      entries,
      index: 0,
      caID,
      logNumber: 1,
      cosigners: [{ id: caID, ...issuer }, ...members],
    }),
    options = {
      caID,
      caPublicKey: issuer.publicKey,
      members,
      threshold: 2,
      policyHash: Buffer.alloc(64, 1),
      rtmHash: Buffer.alloc(64, 2),
      membershipEpoch: 7,
      profileID,
    },
    root = m.verifyMTC(standalone, { ...options, at: notBefore }).root,
    landmark = p.certificateFromTBS(
      mtcTBS,
      p.OID.mtc,
      m.encodeProof({ start: 0, end: 1, inclusion: [] }),
    ),
    cache = {
      ...options,
      logNumber: 1,
      start: 0,
      end: 1,
      root,
      mode: 'LIVE',
      validFrom: notBefore,
      expiresAt: notAfter + 1,
    };
  for (const [mode, certificate, trustedSubtrees] of [
    ['STANDALONE', standalone, []],
    ['LANDMARK', landmark, [cache]],
  ])
    for (const [label, at, valid] of points)
      test('MTC ' + encoding + ' ' + mode + ' ' + label, () => {
        const verify = () => m.verifyMTC(certificate, { ...options, trustedSubtrees, at });
        if (!valid) return assert.throws(verify, { code: 'MTC_SERIAL_OR_TIME' });
        const result = verify();
        assert.equal(result.mode, mode);
        assert.deepEqual(result.root, root);
        assert.deepEqual(result.certificate.raw, certificate);
        assert.deepEqual(result.certificate.tbs, mtcTBS);
        assert.deepEqual(result.certificate.certificateID, c.H('CertificateTBS', mtcTBS));
      });
  test('MTC ' + encoding + ' inclusive certificate keeps cache expiry exclusive', () => {
    const trustedSubtrees = [{ ...cache, expiresAt: notAfter }];
    assert.equal(
      m.verifyMTC(landmark, { ...options, trustedSubtrees, at: notAfter - 0.125 }).mode,
      'LANDMARK',
    );
    assert.throws(() => m.verifyMTC(landmark, { ...options, trustedSubtrees, at: notAfter }), {
      code: 'MTC_CACHE_FRESHNESS',
    });
  });
  test('MTC ' + encoding + ' endpoint retains revocation, proof and profile checks', () => {
    const at = notAfter;
    assert.throws(
      () =>
        m.verifyMTC(standalone, {
          ...options,
          at,
          revokedRanges: [{ logNumber: 1, start: 0, end: 1 }],
        }),
      { code: 'MTC_REVOKED' },
    );
    assert.throws(
      () =>
        m.verifyMTC(standalone, {
          ...options,
          at,
          members: members.slice(0, 1),
          threshold: 1,
          caPublicKey: members[0].publicKey,
        }),
      { code: 'MTC_COSIGNATURE' },
    );
    assert.throws(
      () =>
        m.verifyMTC(standalone, {
          ...options,
          at,
          members: [members[0], { ...members[1], id: '32473.599' }],
        }),
      { code: 'MTC_QUORUM' },
    );
    assert.throws(
      () => m.verifyMTC(standalone, { ...options, at, profileID: 'CERTCONCORD-TSA-v1' }),
      { code: 'MTC_CERTIFICATE_PROFILE' },
    );
    const fields = c.parseDER(mtcTBS).children.map((field) => field.raw);
    fields[1] = c.integer(0);
    const zero = p.certificateFromTBS(
      c.seq(...fields),
      p.OID.mtc,
      p.parseCertificate(standalone).signature,
    );
    assert.throws(() => m.verifyMTC(zero, { ...options, at }), { code: 'MTC_SERIAL_OR_TIME' });
    const badRoot = Buffer.from(root);
    badRoot[0] ^= 1;
    assert.throws(
      () =>
        m.verifyMTC(landmark, { ...options, at, trustedSubtrees: [{ ...cache, root: badRoot }] }),
      { code: 'MTC_CACHED_ROOT' },
    );
  });
}
