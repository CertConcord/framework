import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as m from './mtc.mjs';

const vectors = JSON.parse(
    readFileSync(new URL('./vectors/certificate-validity-endpoints.json', import.meta.url)),
  ),
  decode = (value) => Buffer.from(value, 'base64'),
  root = p.parseCertificate(decode(vectors.syntheticRootDER));
assert.equal(vectors.format, 'certconcord-certificate-validity-endpoints-v1');
assert.equal(vectors.certificates.length, 2);
assert.equal(vectors.mtc.length, 2);
assert.equal(vectors.points.length, 8);

for (const fixture of vectors.certificates) {
  const raw = decode(fixture.certificateDER),
    parsed = p.parseCertificate(raw);
  test(fixture.id + ' preserves original signed bytes and identities', () => {
    assert.equal(c.sha256(raw).toString('hex'), fixture.certificateSHA256);
    assert.equal(c.sha256(parsed.tbs).toString('hex'), fixture.tbsSHA256);
    assert.equal(parsed.certificateID.toString('hex'), fixture.certificateID);
    assert.equal(parsed.representationHash.toString('hex'), fixture.representationHash);
    assert.equal(parsed.notBefore, vectors.notBefore);
    assert.equal(parsed.notAfter, vectors.notAfter);
    assert.equal(p.nativeCertificate(raw).verify(root.publicKey), true);
    assert.deepEqual(
      c.parseDER(parsed.tbs).children[4].children.map((x) => x.tag),
      fixture.encoding === 'utc' ? [23, 23] : [24, 24],
    );
  });
  for (const { label, at, valid } of vectors.points)
    test(fixture.id + ' raw vector ' + label, () => {
      const validate = () =>
        p.validateCertificate(raw, root.publicKey, { at, profileID: fixture.profileID });
      if (!valid) return assert.throws(validate, { code: 'CERTIFICATE_TIME' });
      assert.deepEqual(validate().raw, raw);
    });
  test(fixture.id + ' endpoint rejects modified signature and TBS', () => {
    const signature = Buffer.from(parsed.signature);
    signature[signature.length - 1] ^= 1;
    const changed = p.certificateFromTBS(parsed.tbs, 'ec', signature),
      fields = c.parseDER(parsed.tbs).children.map((x) => x.raw);
    fields[5] = p.name('Substituted endpoint subject');
    const rebound = p.certificateFromTBS(c.seq(...fields), 'ec', parsed.signature);
    for (const certificate of [changed, rebound])
      assert.throws(
        () =>
          p.validateCertificate(certificate, root.publicKey, {
            at: vectors.notAfter,
            profileID: fixture.profileID,
          }),
        { code: 'CERTIFICATE_SIGNATURE' },
      );
  });
}

for (const fixture of vectors.mtc) {
  const standalone = decode(fixture.standaloneDER),
    landmark = decode(fixture.landmarkDER),
    parsed = p.parseCertificate(standalone),
    expectedRoot = Buffer.from(fixture.root, 'hex'),
    options = {
      caID: fixture.caID,
      caPublicKey: c.publicFromDER(decode(fixture.caPublicKeyDER)),
      members: fixture.members.map(({ publicKeyDER, ...member }) => ({
        ...member,
        publicKey: c.publicFromDER(decode(publicKeyDER)),
      })),
      threshold: fixture.threshold,
      profileID: fixture.profileID,
      policyHash: Buffer.from(fixture.policyHash, 'hex'),
      rtmHash: Buffer.from(fixture.rtmHash, 'hex'),
      membershipEpoch: fixture.membershipEpoch,
    },
    cache = {
      ...options,
      logNumber: fixture.logNumber,
      start: fixture.start,
      end: fixture.end,
      root: expectedRoot,
      mode: 'LIVE',
      validFrom: fixture.cacheValidFrom,
      expiresAt: fixture.cacheExpiresAt,
    };
  test(fixture.id + ' retains exact TBS, leaf, root and cosigned messages', () => {
    assert.equal(c.sha256(parsed.tbs).toString('hex'), fixture.tbsSHA256);
    assert.equal(parsed.certificateID.toString('hex'), fixture.certificateID);
    assert.equal(parsed.representationHash.toString('hex'), fixture.standaloneRepresentationHash);
    assert.equal(c.sha512(landmark).toString('hex'), fixture.landmarkRepresentationHash);
    assert.deepEqual(p.parseCertificate(landmark).tbs, parsed.tbs);
    assert.deepEqual(m.logEntryFromTBS(parsed.tbs), decode(fixture.logEntry));
    assert.deepEqual(m.treeHash([decode(fixture.logEntry)]), expectedRoot);
    assert.equal(parsed.notBefore, vectors.notBefore);
    assert.equal(parsed.notAfter, vectors.notAfter);
    const proof = m.decodeProof(parsed.signature);
    assert.equal(proof.signatures.length, fixture.cosignatures.length);
    for (const raw of fixture.cosignatures) {
      const found = proof.signatures.find((item) => item.cosignerID === raw.id);
      assert.deepEqual(found.signature, decode(raw.signature));
      assert.deepEqual(
        m.cosignedMessage({
          cosignerID: raw.id,
          caID: fixture.caID,
          logNumber: fixture.logNumber,
          start: fixture.start,
          end: fixture.end,
          root: expectedRoot,
        }),
        decode(raw.message),
      );
    }
  });
  for (const [mode, certificate, trustedSubtrees] of [
    ['STANDALONE', standalone, []],
    ['LANDMARK', landmark, [cache]],
  ])
    for (const { label, at, valid } of vectors.points)
      test(fixture.id + ' raw ' + mode + ' ' + label, () => {
        const verify = () => m.verifyMTC(certificate, { ...options, at, trustedSubtrees });
        if (!valid) return assert.throws(verify, { code: 'MTC_SERIAL_OR_TIME' });
        const result = verify();
        assert.equal(result.mode, mode);
        assert.deepEqual(result.root, expectedRoot);
        assert.deepEqual(result.certificate.raw, certificate);
      });
  test(fixture.id + ' endpoint rejects TBS rebinding and wrong cosigner key', () => {
    const fields = c.parseDER(parsed.tbs).children.map((x) => x.raw);
    fields[5] = p.name('Substituted MTC endpoint subject');
    const rebound = p.certificateFromTBS(c.seq(...fields), p.OID.mtc, parsed.signature);
    assert.throws(() => m.verifyMTC(rebound, { ...options, at: vectors.notAfter }), {
      code: 'MTC_COSIGNATURE',
    });
    assert.throws(
      () =>
        m.verifyMTC(standalone, {
          ...options,
          at: vectors.notAfter,
          caPublicKey: options.members[0].publicKey,
        }),
      { code: 'MTC_COSIGNATURE' },
    );
  });
  test(fixture.id + ' endpoint keeps independent cache, revocation and quorum gates', () => {
    const at = vectors.notAfter;
    assert.throws(
      () =>
        m.verifyMTC(landmark, { ...options, at, trustedSubtrees: [{ ...cache, expiresAt: at }] }),
      { code: 'MTC_CACHE_FRESHNESS' },
    );
    assert.throws(
      () =>
        m.verifyMTC(standalone, {
          ...options,
          at,
          revokedRanges: [{ logNumber: fixture.logNumber, start: 0, end: 1 }],
        }),
      { code: 'MTC_REVOKED' },
    );
    assert.throws(
      () =>
        m.verifyMTC(standalone, {
          ...options,
          at,
          members: [options.members[0], { ...options.members[1], id: '32473.599' }],
        }),
      { code: 'MTC_QUORUM' },
    );
  });
}
