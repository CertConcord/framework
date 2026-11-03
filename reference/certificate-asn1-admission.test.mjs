import test from 'node:test';
import assert from 'node:assert/strict';
import crypto, { createHash, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { readFileSync } from 'node:fs';
import * as c from './core.mjs';
import * as p from './pki.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/certificate-asn1-admission.json', import.meta.url)),
);
const expected = new Map();
function expect(ids, parseError = null, validationError = parseError) {
  for (const id of ids) {
    assert(!expected.has(id));
    expected.set(id, { parseError, validationError });
  }
}
expect(['canonical-ed25519', 'canonical-ec', 'canonical-ml-dsa-65']);
expect(
  [
    'ed-parameters-null',
    'ed-parameters-integer',
    'ed-unused-one',
    'ed-unused-eight',
    'ed-key-empty',
    'ed-key-short',
    'ed-key-long',
    'ed-count-missing',
    'spki-extra-child',
    'spki-key-missing',
    'spki-key-octet-string',
    'spki-algorithm-not-sequence',
    'spki-algorithm-empty',
    'spki-algorithm-not-oid',
    'spki-algorithm-extra-parameter',
    'spki-not-sequence',
    'spki-key-constructed',
  ],
  'CERTIFICATE_SPKI',
);
for (const tail of ['none', 'issuer', 'subject', 'both']) {
  expect(['tail-' + tail + '-no-extensions'], null, 'CA_NOT_ALLOWED');
  expect(['tail-' + tail + '-extensions']);
}
expect(['uid-issuer-empty', 'uid-subject-zero', 'uid-issuer-trailing-zero', 'uid-subject-partial']);
for (const position of ['issuer', 'subject'])
  for (const suffix of ['missing-count', 'count-only-one', 'count-eight', 'nonzero-padding'])
    expect(['uid-' + position + '-' + suffix], 'CERTIFICATE_OPTIONAL_FIELDS');
expect(
  [
    'tail-unknown-primitive',
    'tail-unknown-constructed',
    'tail-unknown-no-extensions',
    'tail-universal-null',
    'tail-duplicate-issuer',
    'tail-duplicate-subject',
    'tail-subject-before-issuer',
    'tail-explicit-issuer',
    'tail-explicit-subject',
    'tail-primitive-extensions',
  ],
  'CERTIFICATE_OPTIONAL_FIELDS',
);
expect(
  [
    'tail-duplicate-extensions',
    'tail-issuer-after-extensions',
    'tail-subject-after-extensions',
    'tail-empty-extensions',
  ],
  'CERTIFICATE_EXTENSIONS',
);
expect(
  ['signature-changed', 'wrong-issuer', 'uid-signed-byte-changed'],
  null,
  'CERTIFICATE_SIGNATURE',
);
expect(['uid-signature-source']);
const signatureFailures = new Set(['signature-changed', 'wrong-issuer', 'uid-signed-byte-changed']);
const hash = (raw) => createHash('sha256').update(raw).digest('hex');
function bytes(record) {
  const raw = Buffer.from(record.der, 'base64');
  assert.equal(raw.toString('base64'), record.der);
  assert.equal(raw.length, record.bytes);
  assert.equal(hash(raw), record.sha256);
  return raw;
}
// Slice actual saved wire bytes independently of the changed certificate parser.
function split(raw) {
  let offset = 0;
  const result = [];
  while (offset < raw.length) {
    const start = offset;
    assert(offset + 2 <= raw.length);
    const tag = raw[offset++];
    let length = raw[offset++];
    if (length & 128) {
      const count = length & 127;
      assert(count > 0 && count <= 4 && offset + count <= raw.length);
      length = 0;
      for (let i = 0; i < count; i++) length = length * 256 + raw[offset++];
    }
    assert(offset + length <= raw.length);
    const value = raw.subarray(offset, offset + length);
    offset += length;
    result.push({ tag, value, raw: raw.subarray(start, offset) });
  }
  assert.equal(offset, raw.length);
  return result;
}
function wire(raw) {
  const root = split(raw);
  assert.equal(root.length, 1);
  assert.equal(root[0].tag, 0x30);
  const certificate = split(root[0].value);
  assert.equal(certificate.length, 3);
  assert.equal(certificate[0].tag, 0x30);
  assert.equal(certificate[2].tag, 3);
  assert.equal(certificate[2].value[0], 0);
  return { certificate, fields: split(certificate[0].value) };
}
const issuers = {
  issuer: createPublicKey({ key: bytes(vectors.issuerSPKI), type: 'spki', format: 'der' }),
  wrongIssuer: createPublicKey({
    key: bytes(vectors.wrongIssuerSPKI),
    type: 'spki',
    format: 'der',
  }),
};
const rowByID = new Map(vectors.rows.map((row) => [row.id, row]));
const rejects = (fn, code) =>
  assert.throws(fn, (error) => error instanceof c.ProtocolError && error.code === code);

test('certificate ASN.1 corpus retains independently verified original signed inputs', () => {
  assert.equal(vectors.schemaVersion, 1);
  assert.equal(vectors.profileID, 'CERTCONCORD-SERVICE-SIGN-v1');
  assert.equal(vectors.at, Date.parse('2026-11-03T00:00:00Z') / 1000);
  assert.equal(rowByID.size, vectors.rows.length);
  assert.deepEqual([...rowByID.keys()].sort(), [...expected.keys()].sort());
  for (const row of vectors.rows) {
    const raw = bytes(row.certificate),
      { certificate, fields } = wire(raw);
    assert.deepEqual(certificate[0].raw, bytes(row.tbs), row.id);
    assert.deepEqual(fields[6].raw, bytes(row.spki), row.id);
    assert.deepEqual(certificate[1].raw, Buffer.from('300a06082a8648ce3d040302', 'hex'));
    assert.deepEqual(fields[2].raw, certificate[1].raw);
    assert.deepEqual(certificate[2].value.subarray(1), bytes(row.signature));
    assert.deepEqual(
      fields.slice(7).map((field) => field.raw),
      row.optionalTail.map(bytes),
    );
    const wanted = expected.get(row.id);
    assert.equal(row.parseError, wanted.parseError);
    assert.equal(row.validationError, wanted.validationError);
    assert.equal(row.verificationIssuer, row.id === 'wrong-issuer' ? 'wrongIssuer' : 'issuer');
    assert.equal(
      row.subject,
      row.id === 'canonical-ec' ? 'ec' : row.id === 'canonical-ml-dsa-65' ? 'ml-dsa-65' : 'ed25519',
    );
    assert.equal(row.signatureValid, !signatureFailures.has(row.id));
    assert.equal(
      verify(
        'sha256',
        certificate[0].raw,
        issuers[row.verificationIssuer],
        certificate[2].value.subarray(1),
      ),
      !signatureFailures.has(row.id),
      row.id,
    );
  }
  const canonical = bytes(rowByID.get('canonical-ed25519').spki);
  const partial = split(split(bytes(rowByID.get('ed-unused-one').spki))[0].value)[1];
  assert.equal(partial.value[0], 1);
  assert.equal(partial.value.at(-1) & 1, 0);
  assert.deepEqual(partial.value.subarray(1), canonical.subarray(-32));
  const original = bytes(rowByID.get('uid-signature-source').tbs);
  const altered = bytes(rowByID.get('uid-signed-byte-changed').tbs);
  assert.equal(original.length, altered.length);
  assert.equal(
    original.reduce((n, value, i) => n + (value !== altered[i]), 0),
    1,
  );
  assert.deepEqual(
    bytes(rowByID.get('uid-signature-source').signature),
    bytes(rowByID.get('uid-signed-byte-changed').signature),
  );
});

for (const row of vectors.rows)
  test('certificate ASN.1 ' + row.id, () => {
    const raw = bytes(row.certificate),
      before = Buffer.from(raw),
      wanted = expected.get(row.id);
    try {
      if (wanted.parseError) {
        rejects(() => p.parseCertificate(raw), wanted.parseError);
        rejects(
          () =>
            p.validateCertificate(raw, issuers.issuer, {
              at: vectors.at,
              profileID: vectors.profileID,
            }),
          wanted.parseError,
        );
        return;
      }
      const parsed = p.parseCertificate(raw);
      assert.deepEqual(parsed.raw, raw);
      assert.deepEqual(parsed.tbs, bytes(row.tbs));
      assert.deepEqual(parsed.spki, bytes(row.spki));
      assert.deepEqual(
        parsed.publicKey.export({ type: 'spki', format: 'der' }),
        bytes(vectors.subjects[row.subject]),
      );
      assert.equal(parsed.publicKey.asymmetricKeyType, row.subject);
      assert.deepEqual(parsed.certificateID, c.H('CertificateTBS', bytes(row.tbs)));
      assert.deepEqual(parsed.representationHash, c.sha512(raw));
      const validate = () =>
        p.validateCertificate(raw, issuers[row.verificationIssuer], {
          at: vectors.at,
          profileID: vectors.profileID,
        });
      if (wanted.validationError) rejects(validate, wanted.validationError);
      else assert.deepEqual(validate().raw, raw);
    } finally {
      assert.deepEqual(raw, before);
    }
  });

test('certificate ASN.1 rejects malformed input before native public-key import', () => {
  const original = crypto.createPublicKey,
    calls = [];
  crypto.createPublicKey = function (...args) {
    calls.push(args);
    return original.apply(this, args);
  };
  syncBuiltinESMExports();
  try {
    const good = rowByID.get('canonical-ed25519');
    p.parseCertificate(bytes(good.certificate));
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0][0], { key: bytes(good.spki), format: 'der', type: 'spki' });
    for (const row of vectors.rows.filter((entry) => expected.get(entry.id).parseError)) {
      calls.length = 0;
      rejects(() => p.parseCertificate(bytes(row.certificate)), expected.get(row.id).parseError);
      assert.equal(calls.length, 0, row.id);
    }
  } finally {
    crypto.createPublicKey = original;
    syncBuiltinESMExports();
  }
  assert.equal(createPublicKey, original);
});

test('certificate issuer omits UniqueIdentifier fields', () => {
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const subject = generateKeyPairSync('ed25519');
  const raw = p.issueCertificate(
    {
      publicKey: subject.publicKey,
      issuer: p.name('Synthetic issuer'),
      subject: p.name('Synthetic subject'),
      serial: 1,
      notBefore: vectors.at - 60,
      notAfter: vectors.at + 60,
      profileID: vectors.profileID,
    },
    issuer.privateKey,
  );
  const { certificate, fields } = wire(raw);
  assert.deepEqual(
    fields.slice(7).map((field) => field.tag),
    [0xa3],
  );
  const key = split(fields[6].value);
  assert.equal(split(key[0].value).length, 1);
  assert.equal(key[1].value.length, 33);
  assert.equal(key[1].value[0], 0);
  assert.equal(
    verify('sha256', certificate[0].raw, issuer.publicKey, certificate[2].value.subarray(1)),
    true,
  );
  assert.deepEqual(
    p.validateCertificate(raw, issuer.publicKey, { at: vectors.at, profileID: vectors.profileID })
      .raw,
    raw,
  );
});

for (const [fault, code] of [
  ['malformed-entry', 'CERTIFICATE_EXTENSION'],
  ['duplicate-oid', 'DUPLICATE_EXTENSION'],
  ['noncanonical-critical', 'BAD_CRITICAL'],
])
  for (const companion of ['none', 'ed-spki', 'unknown-tail'])
    test('certificate ASN.1 extension error precedence ' + fault + ' with ' + companion, () => {
      // Parse-only compound faults retain the old diagnostic. These TBS edits
      // keep the original signature and are not new valid signed fixtures.
      const original = rowByID.get('canonical-ed25519');
      const { certificate, fields } = wire(bytes(original.certificate));
      const extensionSequence = split(fields[7].value)[0];
      const entries = split(extensionSequence.value);
      let replacements = entries.map((entry) => entry.raw);
      if (fault === 'malformed-entry') replacements[0] = c.der(4, entries[0].value);
      else if (fault === 'duplicate-oid') replacements.push(entries[0].raw);
      else {
        const entryFields = split(entries[0].value);
        assert.equal(entryFields.length, 3);
        replacements[0] = c.seq(entryFields[0].raw, c.der(1, Buffer.from([1])), entryFields[2].raw);
      }
      const prefix = fields.slice(0, 7).map((field) => field.raw);
      if (companion === 'ed-spki') prefix[6] = bytes(rowByID.get('ed-unused-one').spki);
      const tail = [c.der(0xa3, c.seq(...replacements))];
      if (companion === 'unknown-tail') tail.unshift(c.der(0x84, Buffer.from([0])));
      const tbs = c.seq(...prefix, ...tail);
      const raw = c.seq(tbs, certificate[1].raw, certificate[2].raw),
        before = Buffer.from(raw);
      assert.equal(verify('sha256', tbs, issuers.issuer, certificate[2].value.subarray(1)), false);
      rejects(() => p.parseCertificate(raw), code);
      rejects(
        () =>
          p.validateCertificate(raw, issuers.issuer, {
            at: vectors.at,
            profileID: vectors.profileID,
          }),
        code,
      );
      assert.deepEqual(raw, before);
    });
