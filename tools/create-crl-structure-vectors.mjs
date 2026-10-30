import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { issueCertificate, name } from '../reference/pki.mjs';

// Fresh synthetic keys remain in memory. CRL encoding and signing do not use
// the reference CRL producer, parser or verifier.
const output = process.argv[2];
assert(output && process.argv.length === 3, 'Provide a new output JSON path');
const at = Date.parse('2026-10-30T01:00:00Z') / 1000;
const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const subject = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const issuerName = name('Synthetic CRL structure issuer');
const algorithm = Buffer.from('300a06082a8648ce3d040302', 'hex');
const spki = key.publicKey.export({ type: 'spki', format: 'der' });
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const artifact = (bytes) => ({
  der: bytes.toString('base64'),
  bytes: bytes.length,
  sha256: hash(bytes),
});

function tlv(tag, value) {
  let length;
  if (value.length < 128) length = Buffer.from([value.length]);
  else {
    let hex = value.length.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    const raw = Buffer.from(hex, 'hex');
    length = Buffer.concat([Buffer.from([0x80 | raw.length]), raw]);
  }
  return Buffer.concat([Buffer.from([tag]), length, value]);
}
const sequence = (...fields) => tlv(0x30, Buffer.concat(fields));
function integer(value) {
  assert(BigInt(value) >= 0n);
  let hex = BigInt(value).toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let bytes = Buffer.from(hex, 'hex');
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return tlv(2, bytes);
}
const time = (seconds) =>
  tlv(
    0x17,
    Buffer.from(
      new Date(seconds * 1000).toISOString().slice(2, 19).replace(/[-:T]/g, '') + 'Z',
      'ascii',
    ),
  );
const extension = (encodedOID, value) => sequence(Buffer.from(encodedOID, 'hex'), tlv(4, value));

function signed(number, { revoked = false, thisUpdate = at - 60 } = {}) {
  const entries = revoked
    ? [
        sequence(
          sequence(
            integer(2),
            time(at - 90),
            sequence(extension('0603551d15', tlv(10, Buffer.from([1])))),
          ),
        ),
      ]
    : [];
  const tbs = sequence(
    integer(1),
    algorithm,
    issuerName,
    time(thisUpdate),
    time(at + 600),
    ...entries,
    tlv(
      0xa0,
      sequence(
        extension('0603551d14', integer(number)),
        extension('0603551d23', sequence(tlv(0x80, createHash('sha256').update(spki).digest()))),
      ),
    ),
  );
  const signature = tlv(
    3,
    Buffer.concat([
      Buffer.from([0]),
      sign('sha256', tbs, { key: key.privateKey, dsaEncoding: 'der' }),
    ]),
  );
  const parts = [tbs, algorithm, signature];
  return { parts, raw: sequence(...parts) };
}

const good = signed(7),
  revoked = signed(7, { revoked: true }),
  fork = signed(7, { thisUpdate: at - 61 }),
  next = signed(8, { thisUpdate: at - 59 });
const rows = [];
function add(id, raw, expected, details = {}) {
  rows.push({ id, ...artifact(raw), expected, ...details });
}
const valid = { status: 'GOOD', overall: 'VALID' };
add('good', good.raw, valid, { number: 7, payloadTLVCount: 3 });
add(
  'revoked',
  revoked.raw,
  { status: 'REVOKED', overall: 'INVALID', reason: 'CRL_REVOKED' },
  { number: 7, payloadTLVCount: 3 },
);
add('signed-same-number-fork', fork.raw, valid, { number: 7, payloadTLVCount: 3 });
add('next-number', next.raw, valid, { number: 8, payloadTLVCount: 3 });
const invalid = { status: 'INVALID', overall: 'INVALID', reason: 'CRL_STRUCTURE' };
for (const [id, tag, fields, ancestor] of [
  ['extra-null', 0x30, [...good.parts, Buffer.from('0500', 'hex')], 'good'],
  ['extra-two', 0x30, [...good.parts, Buffer.from('0500', 'hex'), integer(0)], 'good'],
  ['context-root', 0xa0, good.parts, 'good'],
  ['octet-root', 4, good.parts, 'good'],
  ['missing-signature', 0x30, good.parts.slice(0, 2), 'good'],
  ['only-tbs', 0x30, good.parts.slice(0, 1), 'good'],
  ['empty-sequence', 0x30, [], 'good'],
  ['extra-null-next-number', 0x30, [...next.parts, Buffer.from('0500', 'hex')], 'next-number'],
])
  add(id, tlv(tag, Buffer.concat(fields)), invalid, {
    ancestor,
    rootTag: tag,
    payloadTLVCount: fields.length,
    ancestorChildrenRetained: Math.min(fields.length, 3),
  });
const changedTBS = Buffer.from(good.parts[0]);
const numberEncoding = Buffer.from('0603551d140403020107', 'hex');
const numberIndex = changedTBS.indexOf(numberEncoding);
assert(numberIndex > 0);
const changedIndex = numberIndex + numberEncoding.length - 1;
assert(changedIndex > 0);
changedTBS[changedIndex] ^= 1;
add(
  'signed-tbs-altered',
  sequence(changedTBS, ...good.parts.slice(1)),
  { status: 'INVALID', overall: 'INVALID', reason: 'CRL_SIGNATURE' },
  { ancestor: 'good', changedTBSByte: changedIndex, payloadTLVCount: 3 },
);
const issuerCertificate = issueCertificate(
  {
    publicKey: key.publicKey,
    issuer: issuerName,
    subject: issuerName,
    serial: 1,
    ca: true,
    notBefore: at - 86400,
    notAfter: at + 86400,
  },
  key.privateKey,
);
const certificate = issueCertificate(
  {
    publicKey: subject.publicKey,
    issuer: issuerName,
    subject: name('Synthetic CRL structure subject'),
    serial: 2,
    notBefore: at - 86400,
    notAfter: at + 86400,
  },
  key.privateKey,
);
const corpus = {
  schemaVersion: 1,
  scope: 'Synthetic complete direct CRL outer-structure admission',
  at,
  serial: 2,
  algorithm: 'ECDSA-SHA256',
  issuerName: artifact(issuerName),
  issuerSPKI: artifact(spki),
  issuerCertificate: artifact(issuerCertificate),
  certificate: artifact(certificate),
  rows,
};
assert.equal(rows.length, 13);
writeFileSync(output, JSON.stringify(corpus, null, 2) + '\n', { flag: 'wx' });
console.log('Wrote 13 synthetic CRL vectors; no private keys serialized');
