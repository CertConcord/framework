import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as m from './mtc.mjs';

const vectors = JSON.parse(
    readFileSync(new URL('./vectors/certificate-validity/vectors.json', import.meta.url)),
  ),
  bytes = (value) => Buffer.from(value, 'hex'),
  times = (tbs) => c.parseDER(tbs).children[4].children,
  mtcs = new Map(vectors.mtcCases.map((value) => [value.id, value]));
function options(value) {
  return {
    caID: value.caID,
    caPublicKey: c.publicFromDER(bytes(value.caSPKIHex)),
    members: value.members.map((member) => ({
      id: member.id,
      operatorID: member.operatorID,
      publicKey: c.publicFromDER(bytes(member.publicKeyHex)),
    })),
    threshold: value.threshold,
    policyHash: bytes(value.policyHashHex),
    rtmHash: bytes(value.rtmHashHex),
    membershipEpoch: value.membershipEpoch,
    at: value.at,
    profileID: 'CERTCONCORD-PERSON-SIGN-v1',
  };
}
function cache(value, expiresAt = value.at + 3600) {
  return [
    {
      ...options(value),
      logNumber: value.logNumber,
      start: 0,
      end: value.entriesHex.length,
      root: bytes(value.rootHex),
      mode: 'LIVE',
      validFrom: value.at - 1,
      expiresAt,
    },
  ];
}
test('certificate Time corpus has the complete public synthetic case set', () => {
  assert.equal(vectors.schemaVersion, 1);
  assert.equal(vectors.synthetic, true);
  assert.equal(vectors.certificateCases.length, 20);
  assert.equal(vectors.mtcCases.length, 8);
  assert.equal(vectors.nonInterchangeablePairs.length, 2);
  assert.equal(new Set(vectors.certificateCases.map((value) => value.id)).size, 20);
  assert.equal(mtcs.size, 8);
});
for (const value of vectors.certificateCases)
  test('retained raw certificate Time vector: ' + value.id, () => {
    const raw = bytes(value.certificateHex),
      key = c.publicFromDER(bytes(value.issuerSPKIHex)),
      parsed = p.validateCertificate(raw, key, { at: value.notBefore }),
      native = new X509Certificate(raw);
    assert.equal(native.verify(key), true);
    assert.equal(native.validFromDate.getTime(), value.notBefore * 1000);
    assert.equal(native.validToDate.getTime(), value.notAfter * 1000);
    assert.equal(parsed.notBefore, value.notBefore);
    assert.equal(parsed.notAfter, value.notAfter);
    assert.deepEqual(parsed.raw, raw);
    assert.deepEqual(
      times(parsed.tbs).map((field) => field.tag),
      value.timeTags,
    );
    assert.deepEqual(
      times(parsed.tbs).map((field) => field.value.toString('ascii')),
      value.timeValues,
    );
    assert.equal(c.sha256(parsed.tbs).toString('hex'), value.tbsSHA256);
    assert.equal(parsed.certificateID.toString('hex'), value.certificateIDHex);
    assert.equal(parsed.representationHash.toString('hex'), value.representationHashHex);
    const endpoint = p.validateCertificate(raw, key, { at: value.notAfter });
    assert.deepEqual(endpoint.raw, raw);
    assert.deepEqual(endpoint.tbs, parsed.tbs);
    assert.deepEqual(endpoint.certificateID, parsed.certificateID);
    assert.deepEqual(endpoint.representationHash, parsed.representationHash);
    for (const at of [value.notBefore - 0.125, value.notAfter + 0.125])
      assert.throws(() => p.validateCertificate(raw, key, { at }), {
        code: 'CERTIFICATE_TIME',
      });
    const tampered = Buffer.from(raw);
    tampered[tampered.length - 1] ^= 1;
    for (const at of [value.notBefore, value.notAfter])
      assert.throws(() => p.validateCertificate(tampered, key, { at }), {
        code: 'CERTIFICATE_SIGNATURE',
      });
    assert.equal(new X509Certificate(tampered).verify(key), false);
  });
for (const value of vectors.mtcCases)
  test('retained raw MTC Time vector and proof modes: ' + value.id, () => {
    const tbs = bytes(value.tbsHex),
      entries = value.entriesHex.map(bytes),
      trust = options(value),
      standalone = bytes(value.standaloneHex),
      landmark = bytes(value.landmarkHex);
    assert.equal(c.sha256(tbs).toString('hex'), value.tbsSHA256);
    assert.deepEqual(m.logEntryFromTBS(tbs), bytes(value.leafHex));
    assert.deepEqual(entries[value.index], bytes(value.leafHex));
    assert.deepEqual(m.treeHash(entries), bytes(value.rootHex));
    assert.deepEqual(
      times(tbs).map((field) => field.tag),
      value.timeTags,
    );
    assert.deepEqual(
      times(tbs).map((field) => field.value.toString('ascii')),
      value.timeValues,
    );
    for (const [raw, mode, settings] of [
      [standalone, 'STANDALONE', trust],
      [landmark, 'LANDMARK', { ...trust, trustedSubtrees: cache(value, value.notAfter + 1) }],
    ]) {
      for (const at of [value.notBefore, value.notAfter]) {
        const proof = m.verifyMTC(raw, { ...settings, at });
        assert.equal(proof.mode, mode);
        assert.deepEqual(proof.certificate.tbs, tbs);
        assert.deepEqual(proof.certificate.raw, raw);
        assert.equal(proof.certificate.notBefore, value.notBefore);
        assert.equal(proof.certificate.notAfter, value.notAfter);
      }
      for (const at of [value.notBefore - 0.125, value.notAfter + 0.125])
        assert.throws(() => m.verifyMTC(raw, { ...settings, at }), {
          code: 'MTC_SERIAL_OR_TIME',
        });
    }
    const expiring = { ...trust, trustedSubtrees: cache(value, value.notAfter) };
    assert.equal(
      m.verifyMTC(landmark, { ...expiring, at: value.notAfter - 0.125 }).mode,
      'LANDMARK',
    );
    assert.throws(() => m.verifyMTC(landmark, { ...expiring, at: value.notAfter }), {
      code: 'MTC_CACHE_FRESHNESS',
    });
    for (const at of [value.notBefore, value.notAfter])
      assert.throws(() => m.verifyMTC(landmark, { ...trust, at }), { code: 'MTC_QUORUM' });
  });
for (const pair of vectors.nonInterchangeablePairs)
  for (const reverse of [false, true])
    test(
      'same dates cannot reuse differently encoded MTC proof: ' +
        pair.retained +
        (reverse ? ' reverse' : ''),
      () => {
        const from = mtcs.get(reverse ? pair.current : pair.retained),
          to = mtcs.get(reverse ? pair.retained : pair.current),
          oldTBS = bytes(from.tbsHex),
          replacementTBS = bytes(to.tbsHex),
          original = p.parseCertificate(bytes(from.standaloneHex)),
          originalLandmark = p.parseCertificate(bytes(from.landmarkHex)),
          rebound = p.certificateFromTBS(replacementTBS, p.OID.mtc, original.signature),
          reboundLandmark = p.certificateFromTBS(
            replacementTBS,
            p.OID.mtc,
            originalLandmark.signature,
          );
        assert.equal(from.notBefore, to.notBefore);
        assert.equal(from.notAfter, to.notAfter);
        assert.notDeepEqual(oldTBS, replacementTBS);
        assert.notEqual(from.leafHex, to.leafHex);
        assert.notEqual(from.rootHex, to.rootHex);
        for (const at of [from.notBefore, from.notAfter]) {
          assert.throws(() => m.verifyMTC(rebound, { ...options(from), at }), {
            code: pair.standaloneError,
          });
          assert.throws(
            () =>
              m.verifyMTC(reboundLandmark, {
                ...options(from),
                at,
                trustedSubtrees: cache(from, from.notAfter + 1),
              }),
            { code: pair.landmarkError },
          );
        }
        assert.throws(
          () =>
            m.issueMTC(replacementTBS, {
              entries: from.entriesHex.map(bytes),
              index: 0,
              caID: from.caID,
              logNumber: from.logNumber,
              cosigners: [],
            }),
          { code: pair.logEntryError },
        );
      },
    );
test('raw mixed MTC log keeps the original first leaf and prefix root', () => {
  const original = mtcs.get('2026-retained-generalized'),
    retained = mtcs.get('mixed-retained'),
    current = mtcs.get('mixed-current'),
    entries = retained.entriesHex.map(bytes);
  assert.deepEqual(retained.entriesHex, current.entriesHex);
  assert.equal(retained.rootHex, current.rootHex);
  assert.equal(retained.tbsHex, original.tbsHex);
  assert.deepEqual(entries[0], bytes(original.leafHex));
  assert.deepEqual(m.treeHash(entries.slice(0, 1)), bytes(original.rootHex));
  assert.notEqual(retained.rootHex, original.rootHex);
});
