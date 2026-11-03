import fs from 'node:fs';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { parseDER, seq, set, oid, octet } from '../reference/core.mjs';
import { OID, name, tbsCertificate, certificateFromTBS } from '../reference/pki.mjs';

// Fresh synthetic Ed25519 keys are used only to build public, fixed test inputs.
// The proof and signature transcript are encoded independently of mtc.mjs.
const keys = Object.fromEntries(
  ['ca', 'mirror', 'unknown', 'wrong', 'holder'].map((k) => [k, generateKeyPairSync('ed25519')]),
);
const publicKeys = Object.fromEntries(
  Object.entries(keys).map(([k, v]) => [
    k,
    v.publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
  ]),
);
const at = 1800000000,
  caID = '32473.1',
  memberID = '32474.1';
const sizedID = (pen, length) => String(pen) + '.1'.repeat(length - 3);
const hash = (b) => createHash('sha256').update(b).digest();
const uint = (value, width) => {
  let n = BigInt(value);
  const b = Buffer.alloc(width);
  for (let i = width - 1; i >= 0; i--) {
    b[i] = Number(n & 255n);
    n >>= 8n;
  }
  assert.equal(n, 0n);
  return b;
};
const vector = (b, width) => Buffer.concat([uint(b.length, width), b]);
const identity = (text) =>
  Buffer.concat(
    text.split('.').map((v) => {
      let n = BigInt(v);
      const out = [Number(n & 127n)];
      while ((n >>= 7n) > 0n) out.unshift(Number(n & 127n) | 128);
      return Buffer.from(out);
    }),
  );
const transcript = (signerID, origin, root) =>
  Buffer.concat([
    Buffer.from('subtree/v1\n\0'),
    vector(Buffer.from('oid/1.3.6.1.4.1.' + signerID), 1),
    uint(0, 8),
    vector(Buffer.from('oid/1.3.6.1.4.1.' + origin), 1),
    uint(0, 8),
    uint(1, 8),
    root,
  ]);
const fixtures = [];
function fixture(
  id,
  ca = caID,
  member = memberID,
  logNumber = 1,
  { unknown = false, known = true, signatures = true } = {},
) {
  const tbs = tbsCertificate({
    publicKey: keys.holder.publicKey,
    subject: name('Synthetic MTC identity boundary'),
    issuer: seq(set(seq(oid(OID.trustAnchorID), oid(ca, true)))),
    serial: BigInt(logNumber) << 48n,
    signatureAlgorithm: OID.mtc,
    notBefore: at - 60,
    notAfter: at + 60,
    profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
  });
  const t = parseDER(tbs).children,
    pk = t[6];
  const entry = Buffer.concat([
    vector(Buffer.alloc(0), 2),
    uint(1, 2),
    t[0].raw,
    t[3].raw,
    t[4].raw,
    t[5].raw,
    pk.children[0].raw,
    octet(hash(pk.raw)),
    ...t.slice(7).map((v) => v.raw),
  ]);
  const root = hash(Buffer.concat([Buffer.from([0]), entry])),
    origin = ca + '.0.' + logNumber;
  const signers = signatures
    ? [
        { id: ca, key: 'ca' },
        ...(known ? [{ id: member, key: 'mirror' }] : []),
        ...(unknown ? [{ id: sizedID(32475, 33), key: 'unknown' }] : []),
      ]
    : [];
  const signed = signers.map((s) => {
    const input = transcript(s.id, origin, root),
      signature = sign(null, input, keys[s.key].privateKey);
    assert(verify(null, input, keys[s.key].publicKey, signature));
    return {
      id: s.id,
      key: s.key,
      contentHex: identity(s.id).toString('hex'),
      transcriptHex: input.toString('hex'),
      signatureHex: signature.toString('hex'),
    };
  });
  const sorted = signed
    .map((s) => ({
      id: Buffer.from(s.contentHex, 'hex'),
      signature: Buffer.from(s.signatureHex, 'hex'),
    }))
    .sort((a, b) => a.id.length - b.id.length || Buffer.compare(a.id, b.id));
  const proof = Buffer.concat([
    vector(Buffer.alloc(0), 2),
    uint(0, 6),
    uint(1, 6),
    vector(Buffer.alloc(0), 2),
    vector(
      Buffer.concat(sorted.map((s) => Buffer.concat([vector(s.id, 1), vector(s.signature, 2)]))),
      3,
    ),
  ]);
  const raw = certificateFromTBS(tbs, OID.mtc, proof);
  fixtures.push({
    id,
    caID: ca,
    memberID: member,
    logNumber,
    caContentHex: identity(ca).toString('hex'),
    memberContentHex: identity(member).toString('hex'),
    logContentHex: identity(origin).toString('hex'),
    tbsHex: tbs.toString('hex'),
    entryHex: entry.toString('hex'),
    rootHex: root.toString('hex'),
    proofHex: proof.toString('hex'),
    certificateHex: raw.toString('hex'),
    signatures: signed,
  });
}
fixture('short');
fixture('member32', caID, sizedID(32474, 32));
fixture('member33', caID, sizedID(32474, 33));
fixture('ca33', sizedID(32473, 33));
fixture('log32', sizedID(32473, 30));
fixture('log33', sizedID(32473, 31));
fixture('multibyte-log32', sizedID(32473, 29), memberID, 128);
fixture('multibyte-log33', sizedID(32473, 30), memberID, 128);
fixture('unknown33-known', caID, memberID, 1, { unknown: true });
fixture('unknown33-only', caID, memberID, 1, { unknown: true, known: false });
for (const [id, ca, member] of [
  ['cache-short', caID, memberID],
  ['cache-ca33', sizedID(32473, 33), memberID],
  ['cache-member33', caID, sizedID(32474, 33)],
  ['cache-log33', sizedID(32473, 31), memberID],
])
  fixture(id, ca, member, 1, { signatures: false });
const cases = [];
const add = (id, fixture, expected, options = {}) =>
  cases.push({ id, fixture, expected, ...options });
for (const id of ['short', 'member32', 'log32', 'multibyte-log32', 'unknown33-known'])
  add(id, id, 'STANDALONE');
for (const id of ['member33', 'ca33', 'log33', 'multibyte-log33']) add(id, id, 'TRUST_ANCHOR_ID');
add('unknown33-only', 'unknown33-only', 'MTC_QUORUM');
add('cache-short', 'cache-short', 'LANDMARK', { cache: true });
for (const id of ['cache-ca33', 'cache-member33', 'cache-log33'])
  add(id, id, 'TRUST_ANCHOR_ID', { cache: true });
add('unused-member33', 'short', 'TRUST_ANCHOR_ID', { extraMemberID: sizedID(32476, 33) });
add('cache-unused-member33', 'cache-short', 'TRUST_ANCHOR_ID', {
  cache: true,
  extraMemberID: sizedID(32476, 33),
});
add('wrong-ca-key', 'short', 'MTC_COSIGNATURE', { wrongCA: true });
add('wrong-member-key', 'short', 'MTC_COSIGNATURE', { wrongMember: true });
add('cache-expired', 'cache-short', 'MTC_CACHE_FRESHNESS', { cache: true, expired: true });
add('cache-root-mismatch', 'cache-short', 'MTC_CACHED_ROOT', { cache: true, wrongRoot: true });
add('cache-scope-mismatch', 'cache-short', 'MTC_QUORUM', { cache: true, wrongScope: true });
add('signatureless-without-cache', 'cache-short', 'MTC_QUORUM');
add('insufficient-operators', 'short', 'MTC_QUORUM', { additionalValidMember: true, threshold: 2 });
const result = {
  schema: 'certconcord-mtc-identity-vectors-v1',
  synthetic: true,
  at,
  publicKeys,
  fixtures,
  cases,
};
fs.writeFileSync(
  new URL('../reference/vectors/mtc-identity-boundaries.json', import.meta.url),
  JSON.stringify(result, null, 2) + '\n',
);
console.log(
  JSON.stringify({ fixtures: fixtures.length, cases: cases.length, privateKeysWritten: false }),
);
