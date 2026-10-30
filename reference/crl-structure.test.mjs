import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  verify,
  X509Certificate,
} from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { verifyCRL } from './revocation.mjs';
import { identityCRLValidator } from './identity.mjs';
import { Journal } from './state.mjs';

const corpus = JSON.parse(readFileSync(new URL('./vectors/crl-structure.json', import.meta.url)));
const decode = (entry) => Buffer.from(entry.der, 'base64');
const raw = (id) => decode(corpus.rows.find((row) => row.id === id));
const issuerCertificate = decode(corpus.issuerCertificate),
  certificate = decode(corpus.certificate);
const issuer = decode(corpus.issuerName),
  publicKey = createPublicKey({
    key: decode(corpus.issuerSPKI),
    type: 'spki',
    format: 'der',
  });
const digest = (bytes) => createHash('sha512').update(bytes).digest();
const watermarkID = digest(issuerCertificate).toString('base64url');
const rowAt = (journal) => journal.get('identity-crl-watermark', watermarkID);
const query = { certificate, at: corpus.at };
const structural = corpus.rows.filter((row) => row.expected.reason === 'CRL_STRUCTURE');

function validator(journal, getBytes) {
  return identityCRLValidator({ issuerCertificate, journal, fetchCRL: async () => getBytes() });
}
function assertWatermark(journal, bytes, number, revision) {
  const row = rowAt(journal);
  assert.equal(BigInt(row.value.number), BigInt(number));
  assert.deepEqual(Buffer.from(row.value.digest), digest(bytes));
  assert.equal(row.revision, revision);
  return row;
}
function temporary(t) {
  const parent = resolve(tmpdir()),
    dir = mkdtempSync(join(parent, 'certconcord-crl-structure-'));
  t.after(() => {
    assert(resolve(dir).startsWith(parent + sep));
    rmSync(dir, { recursive: true, force: true });
  });
  return dir;
}

for (const row of corpus.rows) {
  test(`CRL structure vector: ${row.id}`, () => {
    const result = verifyCRL(decode(row), {
      issuer,
      publicKey,
      serial: corpus.serial,
      at: corpus.at,
    });
    assert.equal(result.status, row.expected.status);
    assert.equal(result.overall, row.expected.overall);
    assert.equal(result.reason, row.expected.reason);
    assert(Object.isFrozen(result));
    if (row.expected.reason === 'CRL_STRUCTURE' || row.expected.reason === 'CRL_SIGNATURE') {
      for (const key of ['number', 'thisUpdate', 'nextUpdate', 'scope'])
        assert.equal(Object.hasOwn(result, key), false);
    } else {
      assert.equal(BigInt(result.number), BigInt(row.number));
      assert.equal(result.scope, 'COMPLETE_ISSUER_CRL');
      assert.equal(result.nextUpdate, corpus.at + 600);
    }
  });
}

for (const row of structural) {
  test(`identity CRL structure preserves both journal orders: ${row.id}`, async () => {
    const journal = new Journal();
    let bytes = decode(row);
    const admit = validator(journal, () => bytes);
    try {
      await assert.rejects(admit(query), { code: 'CRL_STRUCTURE' });
      assert.equal(rowAt(journal), undefined);
      bytes = raw('good');
      assert.equal((await admit(query)).status, 'GOOD');
      const before = assertWatermark(journal, bytes, 7, 0);
      bytes = decode(row);
      await assert.rejects(admit(query), { code: 'CRL_STRUCTURE' });
      assert.deepEqual(rowAt(journal), before);
    } finally {
      journal.close();
    }
  });
}

for (const [label, ids] of [
  ['malformed then canonical', ['extra-null', 'good']],
  ['canonical then malformed then canonical', ['good', 'extra-null', 'good']],
]) {
  test(`identity CRL structure survives journal reopen: ${label}`, async (t) => {
    const path = join(temporary(t), 'journal.sqlite');
    let saved;
    for (const id of ids) {
      const journal = new Journal(path),
        bytes = raw(id),
        admit = validator(journal, () => bytes);
      try {
        assert.deepEqual(rowAt(journal), saved);
        if (id === 'extra-null') {
          await assert.rejects(admit(query), { code: 'CRL_STRUCTURE' });
          assert.deepEqual(rowAt(journal), saved);
        } else {
          assert.equal((await admit(query)).status, 'GOOD');
          saved = assertWatermark(journal, bytes, 7, (saved?.revision ?? -1) + 1);
        }
      } finally {
        journal.close();
      }
    }
    const reopened = new Journal(path);
    try {
      assert.deepEqual(rowAt(reopened), saved);
    } finally {
      reopened.close();
    }
  });
}

test('identity CRL structure retains signed same-number fork rejection', async () => {
  const journal = new Journal();
  let bytes = raw('good');
  const admit = validator(journal, () => bytes);
  try {
    assert.equal((await admit(query)).status, 'GOOD');
    const before = assertWatermark(journal, bytes, 7, 0);
    bytes = raw('signed-same-number-fork');
    await assert.rejects(admit(query), { code: 'IDENTITY_CRL_FORK' });
    assert.deepEqual(rowAt(journal), before);
  } finally {
    journal.close();
  }
});

test('identity CRL structure rejects a malformed higher number before watermark advance', async () => {
  const journal = new Journal();
  let bytes = raw('good');
  const admit = validator(journal, () => bytes);
  try {
    assert.equal((await admit(query)).status, 'GOOD');
    const before = assertWatermark(journal, bytes, 7, 0);
    bytes = raw('extra-null-next-number');
    await assert.rejects(admit(query), { code: 'CRL_STRUCTURE' });
    assert.deepEqual(rowAt(journal), before);
    bytes = raw('next-number');
    assert.equal((await admit(query)).status, 'GOOD');
    assertWatermark(journal, bytes, 8, before.revision + 1);
  } finally {
    journal.close();
  }
});

// This cursor only measures the frozen wire fields; it does not import the
// reference DER parser or decide whether a CertificateList is admissible.
function readTLV(bytes, start = 0) {
  let offset = start;
  assert(offset + 2 <= bytes.length);
  const tag = bytes[offset++];
  let length = bytes[offset++];
  if (length & 128) {
    const width = length & 127;
    assert(width > 0 && width <= 4 && offset + width <= bytes.length);
    length = 0;
    for (let i = 0; i < width; i++) length = length * 256 + bytes[offset++];
  }
  const end = offset + length;
  assert(end <= bytes.length);
  return { tag, raw: bytes.subarray(start, end), value: bytes.subarray(offset, end), end };
}
function payloadFields(bytes) {
  const outer = readTLV(bytes);
  assert.equal(outer.end, bytes.length);
  const fields = [];
  let offset = 0;
  while (offset < outer.value.length) {
    const field = readTLV(outer.value, offset);
    fields.push(field);
    offset = field.end;
  }
  return { outer, fields };
}
function signatureValid(fields, key = publicKey) {
  assert.equal(fields[1].raw.toString('hex'), '300a06082a8648ce3d040302');
  assert.equal(fields[2].tag, 3);
  assert.equal(fields[2].value[0], 0);
  return verify('sha256', fields[0].raw, { key, dsaEncoding: 'der' }, fields[2].value.subarray(1));
}

test('CRL structure raw corpus preserves signed bytes and independent signature controls', () => {
  assert.equal(corpus.schemaVersion, 1);
  assert.equal(corpus.rows.length, 13);
  assert.equal(structural.length, 8);
  assert.equal(new Set(corpus.rows.map((row) => row.id)).size, 13);
  for (const entry of [
    corpus.issuerName,
    corpus.issuerSPKI,
    corpus.issuerCertificate,
    corpus.certificate,
    ...corpus.rows,
  ]) {
    const bytes = decode(entry);
    assert.equal(bytes.length, entry.bytes);
    assert.equal(bytes.toString('base64'), entry.der);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256);
  }
  assert(new X509Certificate(issuerCertificate).verify(publicKey));
  assert(new X509Certificate(certificate).verify(publicKey));
  for (const row of corpus.rows) {
    const { outer, fields } = payloadFields(decode(row));
    assert.equal(outer.tag, row.rootTag ?? 0x30);
    assert.equal(fields.length, row.payloadTLVCount);
    if (row.expected.reason === 'CRL_STRUCTURE') {
      const ancestor = payloadFields(raw(row.ancestor)).fields;
      assert.deepEqual(
        fields.slice(0, row.ancestorChildrenRetained).map((field) => field.raw),
        ancestor.slice(0, row.ancestorChildrenRetained).map((field) => field.raw),
      );
      // A missing field has no complete embedded signature to verify. The
      // ancestor remains the signed control, not an accepted malformed CRL.
      assert(signatureValid(ancestor));
      if (fields.length >= 3) assert(signatureValid(fields));
      if (fields.length > 3) assert.equal(fields[3].raw.toString('hex'), '0500');
    } else {
      assert.equal(signatureValid(fields), row.id !== 'signed-tbs-altered');
    }
  }
  const good = payloadFields(raw('good')).fields;
  const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey;
  assert.equal(signatureValid(good, other), false);
  const changedSignature = Buffer.from(good[2].value.subarray(1));
  changedSignature[changedSignature.length - 1] ^= 1;
  assert.equal(
    verify('sha256', good[0].raw, { key: publicKey, dsaEncoding: 'der' }, changedSignature),
    false,
  );
  const altered = payloadFields(raw('signed-tbs-altered')).fields;
  const before = good[0].raw,
    after = altered[0].raw;
  assert.equal(before.length, after.length);
  assert.equal(before.filter((byte, index) => byte !== after[index]).length, 1);
  assert.deepEqual(
    good.slice(1).map((field) => field.raw),
    altered.slice(1).map((field) => field.raw),
  );
});

const executable = process.env.OPENSSL_BIN ?? 'openssl';
const available = spawnSync(executable, ['version'], { encoding: 'utf8' }).status === 0;
if (!available && process.env.CERTCONCORD_REQUIRE_OPENSSL === '1')
  throw Error('OpenSSL is required by this test environment');
test(
  'OpenSSL independently parses and verifies the exact CRL structure corpus',
  { skip: !available && 'OpenSSL is required' },
  (t) => {
    const dir = temporary(t),
      ca = join(dir, 'issuer.pem');
    writeFileSync(ca, new X509Certificate(issuerCertificate).toString());
    for (const row of corpus.rows) {
      const path = join(dir, row.id + '.der');
      writeFileSync(path, decode(row));
      const result = spawnSync(
        executable,
        ['crl', '-inform', 'DER', '-in', path, '-noout', '-verify', '-CAfile', ca],
        { encoding: 'utf8' },
      );
      assert.equal(result.error, undefined);
      const text = result.stdout + result.stderr;
      if (row.expected.reason === 'CRL_STRUCTURE') {
        assert.notEqual(result.status, 0, row.id);
        assert.equal(text.includes('verify OK'), false, row.id);
      } else if (row.id === 'signed-tbs-altered') {
        assert.match(text, /verify failure/i);
        assert.equal(text.includes('verify OK'), false);
      } else {
        assert.equal(result.status, 0, row.id + ': ' + text);
        assert(text.includes('verify OK'), row.id);
      }
    }
  },
);
