import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';

// Fresh synthetic keys stay in memory. Encoding and signing are independent of
// the certificate producer, parser and verifier under test.
const output = process.argv[2];
assert(output && process.argv.length === 3, 'Provide a new output JSON path');
const registry = JSON.parse(readFileSync(new URL('../reference/registry.json', import.meta.url)));
const serviceEKU = registry.entries.find(
  (entry) => entry.name === 'id-kp-certconcordServiceSigning',
).oid;
const at = Date.parse('2026-11-03T00:00:00Z') / 1000;
const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const wrongIssuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
let ed25519;
for (let attempt = 0; attempt < 256; attempt++) {
  ed25519 = generateKeyPairSync('ed25519');
  if (!(ed25519.publicKey.export({ type: 'spki', format: 'der' }).at(-1) & 1)) break;
}
const publicDER = (key) => key.publicKey.export({ type: 'spki', format: 'der' });
const subjects = {
  ed25519: publicDER(ed25519),
  ec: publicDER(generateKeyPairSync('ec', { namedCurve: 'prime256v1' })),
  'ml-dsa-65': publicDER(generateKeyPairSync('ml-dsa-65')),
};
const key = subjects.ed25519.subarray(-32);
assert.equal(key.at(-1) & 1, 0);
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const artifact = (bytes) => ({
  der: bytes.toString('base64'),
  bytes: bytes.length,
  sha256: hash(bytes),
});
function tlv(tag, value) {
  let length = Buffer.from([value.length]);
  if (value.length >= 128) {
    let hex = value.length.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    const encoded = Buffer.from(hex, 'hex');
    length = Buffer.concat([Buffer.from([0x80 | encoded.length]), encoded]);
  }
  return Buffer.concat([Buffer.from([tag]), length, value]);
}
const sequence = (...fields) => tlv(0x30, Buffer.concat(fields));
function oid(value) {
  const arcs = value.split('.').map(BigInt);
  assert(arcs.length >= 2 && arcs[0] <= 2n && (arcs[0] === 2n || arcs[1] < 40n));
  const bytes = [];
  for (let arc of [arcs[0] * 40n + arcs[1], ...arcs.slice(2)]) {
    const part = [Number(arc & 127n)];
    while ((arc >>= 7n) > 0n) part.unshift(Number(arc & 127n) | 128);
    bytes.push(...part);
  }
  return tlv(6, Buffer.from(bytes));
}
const integer = (value) => {
  assert(Number.isInteger(value) && value > 0 && value < 128);
  return tlv(2, Buffer.from([value]));
};
const name = (value) => sequence(tlv(0x31, sequence(oid('2.5.4.3'), tlv(12, Buffer.from(value)))));
const time = (value) =>
  tlv(
    23,
    Buffer.from(new Date(value * 1000).toISOString().slice(2, 19).replace(/[-:T]/g, '') + 'Z'),
  );
const algorithm = sequence(oid('1.2.840.10045.4.3.2'));
const edAlgorithm = sequence(oid('1.3.101.112'));
const bitKey = (unused, bytes) => tlv(3, Buffer.concat([Buffer.from([unused]), bytes]));
const nullValue = tlv(5, Buffer.alloc(0));
function extension(id, value, critical = false) {
  return sequence(oid(id), ...(critical ? [tlv(1, Buffer.from([255]))] : []), tlv(4, value));
}
const extensions = tlv(
  0xa3,
  sequence(
    extension('2.5.29.19', sequence(), true),
    extension('2.5.29.15', tlv(3, Buffer.from([7, 128])), true),
    extension('2.5.29.37', sequence(oid(serviceEKU))),
  ),
);
const uid = (tag, hex) => tlv(tag, Buffer.from(hex, 'hex'));
const issuerUID = uid(0x81, '00a0'),
  subjectUID = uid(0x82, '0780');
const rows = [];
function encodeTBS(spki, tail, serial) {
  return sequence(
    tlv(0xa0, integer(2)),
    integer(serial),
    algorithm,
    name('Synthetic ASN.1 issuer'),
    sequence(time(at - 3600), time(at + 3600)),
    name('Synthetic ASN.1 subject'),
    spki,
    ...tail,
  );
}
function add(
  id,
  {
    spki = subjects.ed25519,
    tail = [extensions],
    subject = 'ed25519',
    parseError = null,
    validationError = parseError,
    signatureValid = true,
    tbs,
    signature,
    verificationIssuer = 'issuer',
  } = {},
) {
  tbs ??= encodeTBS(spki, tail, rows.length + 1);
  signature ??= sign('sha256', tbs, issuer.privateKey);
  const raw = sequence(tbs, algorithm, tlv(3, Buffer.concat([Buffer.from([0]), signature])));
  const row = {
    id,
    certificate: artifact(raw),
    tbs: artifact(tbs),
    spki: artifact(spki),
    signature: artifact(signature),
    optionalTail: tail.map(artifact),
    subject,
    verificationIssuer,
    signatureValid,
    parseError,
    validationError,
  };
  rows.push(row);
  return { tbs, signature, row };
}
add('canonical-ed25519');
add('canonical-ec', { spki: subjects.ec, subject: 'ec' });
add('canonical-ml-dsa-65', { spki: subjects['ml-dsa-65'], subject: 'ml-dsa-65' });
const badSPKI = [
  ['ed-parameters-null', sequence(sequence(oid('1.3.101.112'), nullValue), bitKey(0, key))],
  ['ed-parameters-integer', sequence(sequence(oid('1.3.101.112'), integer(1)), bitKey(0, key))],
  ['ed-unused-one', sequence(edAlgorithm, bitKey(1, key))],
  ['ed-unused-eight', sequence(edAlgorithm, bitKey(8, key))],
  ['ed-key-empty', sequence(edAlgorithm, bitKey(0, Buffer.alloc(0)))],
  ['ed-key-short', sequence(edAlgorithm, bitKey(0, key.subarray(0, 31)))],
  ['ed-key-long', sequence(edAlgorithm, bitKey(0, Buffer.concat([key, Buffer.from([0])])))],
  ['ed-count-missing', sequence(edAlgorithm, tlv(3, Buffer.alloc(0)))],
  ['spki-extra-child', sequence(edAlgorithm, bitKey(0, key), nullValue)],
  ['spki-key-missing', sequence(edAlgorithm)],
  ['spki-key-octet-string', sequence(edAlgorithm, tlv(4, key))],
  ['spki-algorithm-not-sequence', sequence(oid('1.3.101.112'), bitKey(0, key))],
  ['spki-algorithm-empty', sequence(sequence(), bitKey(0, key))],
  ['spki-algorithm-not-oid', sequence(sequence(nullValue), bitKey(0, key))],
  [
    'spki-algorithm-extra-parameter',
    sequence(sequence(oid('1.3.101.112'), nullValue, nullValue), bitKey(0, key)),
  ],
  ['spki-not-sequence', tlv(0xa0, Buffer.concat([edAlgorithm, bitKey(0, key)]))],
  ['spki-key-constructed', sequence(edAlgorithm, tlv(0x23, tlv(4, key)))],
];
for (const [id, spki] of badSPKI) add(id, { spki, parseError: 'CERTIFICATE_SPKI' });
for (const [id, fields] of [
  ['none', []],
  ['issuer', [issuerUID]],
  ['subject', [subjectUID]],
  ['both', [issuerUID, subjectUID]],
]) {
  add('tail-' + id + '-no-extensions', { tail: fields, validationError: 'CA_NOT_ALLOWED' });
  add('tail-' + id + '-extensions', { tail: [...fields, extensions] });
}
for (const [id, tag, value] of [
  ['uid-issuer-empty', 0x81, '00'],
  ['uid-subject-zero', 0x82, '0000'],
  ['uid-issuer-trailing-zero', 0x81, '0080'],
  ['uid-subject-partial', 0x82, '0340'],
])
  add(id, { tail: [uid(tag, value), extensions] });
for (const [position, tag] of [
  ['issuer', 0x81],
  ['subject', 0x82],
])
  for (const [suffix, hex] of [
    ['missing-count', ''],
    ['count-only-one', '01'],
    ['count-eight', '0800'],
    ['nonzero-padding', '0341'],
  ])
    add('uid-' + position + '-' + suffix, {
      tail: [uid(tag, hex), extensions],
      parseError: 'CERTIFICATE_OPTIONAL_FIELDS',
    });
for (const [id, tail, parseError] of [
  ['tail-unknown-primitive', [uid(0x84, '00'), extensions], 'CERTIFICATE_OPTIONAL_FIELDS'],
  ['tail-unknown-constructed', [tlv(0xa4, nullValue), extensions], 'CERTIFICATE_OPTIONAL_FIELDS'],
  ['tail-unknown-no-extensions', [uid(0x84, '00')], 'CERTIFICATE_OPTIONAL_FIELDS'],
  ['tail-universal-null', [nullValue, extensions], 'CERTIFICATE_OPTIONAL_FIELDS'],
  ['tail-duplicate-issuer', [issuerUID, issuerUID, extensions], 'CERTIFICATE_OPTIONAL_FIELDS'],
  ['tail-duplicate-subject', [subjectUID, subjectUID, extensions], 'CERTIFICATE_OPTIONAL_FIELDS'],
  ['tail-duplicate-extensions', [extensions, extensions], 'CERTIFICATE_EXTENSIONS'],
  [
    'tail-subject-before-issuer',
    [subjectUID, issuerUID, extensions],
    'CERTIFICATE_OPTIONAL_FIELDS',
  ],
  ['tail-issuer-after-extensions', [extensions, issuerUID], 'CERTIFICATE_EXTENSIONS'],
  ['tail-subject-after-extensions', [extensions, subjectUID], 'CERTIFICATE_EXTENSIONS'],
  [
    'tail-explicit-issuer',
    [tlv(0xa1, tlv(3, Buffer.from([0]))), extensions],
    'CERTIFICATE_OPTIONAL_FIELDS',
  ],
  [
    'tail-explicit-subject',
    [tlv(0xa2, tlv(3, Buffer.from([0]))), extensions],
    'CERTIFICATE_OPTIONAL_FIELDS',
  ],
  ['tail-primitive-extensions', [tlv(0x83, sequence())], 'CERTIFICATE_OPTIONAL_FIELDS'],
  ['tail-empty-extensions', [tlv(0xa3, sequence())], 'CERTIFICATE_EXTENSIONS'],
])
  add(id, { tail, parseError });
const canonical = rows[0];
const changedSignature = Buffer.from(canonical.signature.der, 'base64');
changedSignature[changedSignature.length - 1] ^= 1;
add('signature-changed', {
  tbs: Buffer.from(canonical.tbs.der, 'base64'),
  signature: changedSignature,
  signatureValid: false,
  validationError: 'CERTIFICATE_SIGNATURE',
});
add('wrong-issuer', {
  tbs: Buffer.from(canonical.tbs.der, 'base64'),
  signature: Buffer.from(canonical.signature.der, 'base64'),
  verificationIssuer: 'wrongIssuer',
  signatureValid: false,
  validationError: 'CERTIFICATE_SIGNATURE',
});
const uidSource = add('uid-signature-source', { tail: [uid(0x81, '0080'), extensions] });
const changedTail = [uid(0x81, '00c0'), extensions];
add('uid-signed-byte-changed', {
  tail: changedTail,
  tbs: encodeTBS(subjects.ed25519, changedTail, rows.length),
  signature: uidSource.signature,
  signatureValid: false,
  validationError: 'CERTIFICATE_SIGNATURE',
});
assert.equal(new Set(rows.map((row) => row.id)).size, rows.length);
const corpus = {
  schemaVersion: 1,
  scope: 'Synthetic certificate raw ASN.1 admission',
  at,
  profileID: 'CERTCONCORD-SERVICE-SIGN-v1',
  issuerSPKI: artifact(publicDER(issuer)),
  wrongIssuerSPKI: artifact(publicDER(wrongIssuer)),
  subjects: Object.fromEntries(
    Object.entries(subjects).map(([id, value]) => [id, artifact(value)]),
  ),
  rows,
};
writeFileSync(output, JSON.stringify(corpus, null, 2) + '\n', { flag: 'wx' });
console.log('Wrote ' + rows.length + ' synthetic certificate vectors; no private keys serialized');
