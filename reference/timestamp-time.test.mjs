import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, X509Certificate, verify } from 'node:crypto';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { parseTSTInfo, verifyTimestampToken } from './timestamp.mjs';

const vectors = JSON.parse(
    readFileSync(new URL('./vectors/timestamp-time-contract.json', import.meta.url)),
  ),
  bytes = (s) => Buffer.from(s, 'base64'),
  hash = (b) => createHash('sha256').update(b).digest('hex'),
  roots = Object.fromEntries(
    Object.entries(vectors.roots).map(([id, raw]) => [
      id,
      createPublicKey({ key: bytes(raw), format: 'der', type: 'spki' }),
    ]),
  ),
  query = { ...vectors.query, imprint: bytes(vectors.query.imprint) };

// Independent rational oracle: binary64 is an integer significand times a power of two.
function rational(value) {
  const b = Buffer.alloc(8);
  b.writeDoubleBE(value);
  const word = b.readBigUInt64BE(),
    e = Number((word >> 52n) & 2047n),
    significand = (word & 0xfffffffffffffn) | (e ? 0x10000000000000n : 0n),
    power = e ? e - 1075 : -1074,
    numerator = (word >> 63n ? -significand : significand) << BigInt(Math.max(0, power)),
    denominator = 1n << BigInt(Math.max(0, -power));
  return { numerator, denominator };
}
function checkInterval(info, timeMicros, accuracyMicros) {
  const lower = rational(info.poeLowerBound),
    upper = rational(info.poeUpperBound);
  assert(lower.numerator * 1000000n <= (timeMicros - accuracyMicros) * lower.denominator);
  assert(upper.numerator * 1000000n >= (timeMicros + accuracyMicros) * upper.denominator);
  assert(info.poeLowerBound <= info.genTime && info.genTime <= info.poeUpperBound);
}

test('time corpus retains signed raw bytes, certificate trust and independent signature controls', () => {
  assert.equal(vectors.profile, 'rfc3161-helper-time-interval');
  assert.equal(vectors.cases.length, 28);
  assert.equal(new Set(vectors.cases.map((r) => r.id)).size, 28);
  for (const entry of Object.values(vectors.certificates)) {
    assert.equal(hash(bytes(entry.raw)), entry.sha256);
    const cert = new X509Certificate(bytes(entry.raw));
    assert(cert.verify(roots.issuer));
    assert(!cert.verify(roots.other));
  }
  for (const row of vectors.cases) {
    const raw = bytes(row.raw),
      sd = c.parseDER(raw).children[1].children[0].children,
      si = sd.at(-1).children[0].children,
      attrs = c.der(0x31, si[3].value),
      cert = new X509Certificate(bytes(vectors.certificates[row.certificate].raw)),
      content = sd[2].children[1].children[0].value,
      digest = si[3].children.find((a) => c.oidText(a.children[0]) === p.OID.messageDigest)
        .children[1].children[0].value;
    assert.equal(hash(raw), row.sha256, row.id);
    assert.deepEqual(content, bytes(row.tstInfo));
    assert.deepEqual(attrs, bytes(row.signedAttributes));
    assert.deepEqual(si[5].value, bytes(row.signature));
    assert.equal(verify(null, attrs, cert.publicKey, si[5].value), row.signatureValid, row.id);
    assert.equal(row.signatureValid, row.id !== 'signature-tamper');
    assert.equal(
      digest.equals(createHash('sha512').update(content).digest()),
      row.id !== 'content-tamper',
    );
    if (row.units)
      checkInterval(
        parseTSTInfo(content),
        BigInt(row.units.timeMicros),
        BigInt(row.units.accuracyMicros),
      );
  }
});

for (const signatureProfile of ['CERTCONCORD-PQ', 'EXTERNAL-RFC3161'])
  for (const row of vectors.cases)
    for (const extra of [{ id: 'default', expected: row.expected }, ...row.queries])
      test(`timestamp time ${signatureProfile}: ${row.id}/${extra.id}`, () => {
        const expected = extra.expected[signatureProfile] ?? extra.expected,
          run = () =>
            verifyTimestampToken(bytes(row.raw), {
              ...query,
              ...extra,
              certificate: bytes(vectors.certificates[row.certificate].raw),
              issuerKey: roots[extra.issuer ?? 'issuer'],
              signatureProfile,
            });
        if (expected.overall === 'VALID') {
          const info = run();
          assert.equal(info.serial, 1001n);
          assert.deepEqual(info.imprint, query.imprint);
          if (row.units)
            checkInterval(info, BigInt(row.units.timeMicros), BigInt(row.units.accuracyMicros));
          if (row.id === 'missing-accuracy') {
            assert.equal(info.accuracy, undefined);
            assert.equal(info.poeLowerBound, undefined);
            assert.equal(info.poeUpperBound, undefined);
          }
          if (row.id === 'rounded-equal-millisecond') {
            assert.equal(info.poeLowerBound, 1793275200);
            assert(info.poeUpperBound >= 1793275200.002);
            assert.notEqual(info.poeUpperBound, info.genTime + info.accuracy);
          }
          if (row.id === 'binary-fraction') assert.equal(info.poeLowerBound, info.poeUpperBound);
        } else
          assert.throws(run, (error) => {
            assert.equal(error.code, expected.code);
            assert.equal(error.overall ?? 'INVALID', expected.overall);
            return true;
          });
      });

test('finite revocation cutoffs are numeric and cannot disable the accuracy requirement by coercion', () => {
  const row = vectors.cases.find((r) => r.id === 'missing-accuracy');
  for (const signatureProfile of ['CERTCONCORD-PQ', 'EXTERNAL-RFC3161'])
    for (const revokedAt of ['1793275210', NaN, -Infinity, null])
      assert.throws(
        () =>
          verifyTimestampToken(bytes(row.raw), {
            ...query,
            revokedAt,
            signatureProfile,
            certificate: bytes(vectors.certificates.tsa.raw),
            issuerKey: roots.issuer,
          }),
        { code: 'TSA_TIME_OR_REVOCATION' },
      );
});

test('integer microsecond endpoints enclose remote dates, negative epochs and large signed accuracy', () => {
  const original = c.parseDER(bytes(vectors.cases[0].tstInfo)).children;
  for (const [time, ms] of [
    ['00000101000000.001Z', -62167219199999],
    ['19691231235959.999Z', -1],
    ['19700101000000Z', 0],
    ['20000229000000.125Z', 951782400125],
    ['99991231235959.999Z', 253402300799999],
  ])
    for (const seconds of [0, 9007199254740991]) {
      const raw = c.seq(
          ...original.slice(0, 4).map((n) => n.raw),
          c.der(24, Buffer.from(time)),
          c.seq(c.integer(seconds), c.der(0x80, Buffer.from([1])), c.der(0x81, Buffer.from([1]))),
        ),
        info = parseTSTInfo(raw);
      checkInterval(info, BigInt(ms) * 1000n, BigInt(seconds) * 1000000n + 1001n);
    }
});
