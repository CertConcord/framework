import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as e from './enrollment.mjs';

const corpus = JSON.parse(fs.readFileSync(new URL('./vectors/pkcs10-structure.json', import.meta.url)));
const unpack = row => {
  const bytes = Buffer.from(row.base64, 'base64');
  assert.equal(bytes.length, row.bytes);
  assert.equal(c.sha256(bytes).toString('hex'), row.sha256);
  return bytes;
};
const key = id => c.publicFromDER(unpack(corpus.keys[id]));
const rowFor = id => { const row = corpus.cases.find(row => row.id === id); assert(row); return row; };
const certificate = unpack(corpus.certificate);

test('PKCS10 structure corpus keeps raw signatures and public key bindings', () => {
  assert.equal(corpus.schemaVersion, 1);
  assert.equal(new Set(corpus.cases.map(row => row.id)).size, corpus.cases.length);
  assert.notDeepEqual(unpack(corpus.keys.holder), unpack(corpus.keys.wrong));
  p.validateCertificate(certificate, key('issuer'), { at: corpus.at });
  for (const row of Object.values(corpus.keys)) assert.deepEqual(c.spki(c.publicFromDER(unpack(row))), unpack(row));
  for (const row of corpus.cases) {
    let mathematicalSignature = null;
    try {
      const [info,,signature] = c.parseDER(unpack(row.raw)).children;
      mathematicalSignature = c.verify(info.raw, signature.value.subarray(1), key(row.signer));
    } catch {}
    assert.equal(mathematicalSignature, row.expected.signatureValid, row.id);
  }
});

for (const row of corpus.cases) test('PKCS10 typed admission: ' + row.id, () => {
  const raw = unpack(row.raw), before = Buffer.from(raw);
  let policyCalls = 0;
  const options = {
    ...(row.expectedSubject ? { expectedSubject: unpack(row.expectedSubject) } : {}),
    ...(row.expectedSPKI ? { expectedSPKI: unpack(row.expectedSPKI) } : {}),
    validatePossessionCertificate: value => {
      policyCalls++;
      assert.deepEqual(value, certificate);
      p.validateCertificate(value, key('issuer'), { at: corpus.at });
      return row.trust !== false;
    },
  };
  if (row.expected.accepted) {
    const parsed = e.verifyCSR(raw, options), info = c.parseDER(raw).children[0];
    assert.equal(parsed.possessionMode, row.expected.mode);
    assert.deepEqual(parsed.requestHash, c.sha512(raw));
    assert.deepEqual(parsed.subject, info.children[1].raw);
    assert.deepEqual(parsed.spki, info.children[2].raw);
    assert.deepEqual(c.spki(parsed.publicKey), parsed.spki);
    assert.equal(policyCalls, row.expected.policyCalls);
    assert.deepEqual(e.verifyCSR(raw, { ...options, expectedSubject: parsed.subject, expectedSPKI: parsed.spki }).requestHash, parsed.requestHash);
  } else {
    assert.throws(() => e.verifyCSR(raw, options), error => {
      assert(!(error instanceof TypeError), row.id + ' must reject through validation');
      if (row.expected.error) assert.equal(error.code ?? error.message, row.expected.error);
      return true;
    });
  }
  assert.equal(policyCalls, row.expected.policyCalls * (row.expected.accepted ? 2 : 1));
  assert.deepEqual(raw, before);
});

test('PKCS10 external signature completion preserves the exact valid request', () => {
  const raw = unpack(rowFor('direct/valid').raw), [info, algorithm, signature] = c.parseDER(raw).children;
  assert.deepEqual(e.completeCSR({ info: info.raw, algorithm: algorithm.raw, publicKey: key('holder') }, signature.value.subarray(1)), raw);
});
test('PKCS10 external signature completion rejects a signed wrong information type', () => {
  const raw = unpack(rowFor('direct/info-context').raw), [info, algorithm, signature] = c.parseDER(raw).children;
  assert(c.verify(info.raw, signature.value.subarray(1), key('holder')));
  assert.throws(() => e.completeCSR({ info: info.raw, algorithm: algorithm.raw, publicKey: key('holder') }, signature.value.subarray(1)), /CSR_STRUCTURE/);
});

for (const [id, error, expected] of [
  ['statement/valid', 'RA_DENIED', { policy: 1, kem: 1, approve: 1, journal: 0 }],
  ['statement/outer-context', 'CSR_STRUCTURE', { policy: 0, kem: 0, approve: 0, journal: 0 }],
  ['statement/name-context', 'CSR_SUBJECT_STRUCTURE', { policy: 0, kem: 0, approve: 0, journal: 0 }],
]) test('PKCS10 DOC-ENC admission boundary: ' + id, async () => {
  const calls = { policy: 0, kem: 0, approve: 0, journal: 0 };
  const journal = new Proxy({}, { get() { calls.journal++; throw new Error('UNEXPECTED_JOURNAL_ACCESS'); } });
  const authority = new e.RegistrationAuthority({
    journal, certificate,
    approve: async () => { calls.approve++; return { approved: false }; },
    kemPossession: { verify: () => { calls.kem++; return { evidenceHash: Buffer.alloc(64, 3) }; } },
  });
  await assert.rejects(authority.authorize({
    csr: unpack(rowFor(id).raw), subjectID: Buffer.alloc(32, 1), profileID: 'CERTCONCORD-DOC-ENC-v1',
    policyHash: Buffer.alloc(64, 2), identityEvidenceHash: Buffer.alloc(64, 3),
    issuanceScope: { trustDomainID: Buffer.alloc(32, 4), issuerID: 'synthetic-pkcs10-issuer', issuerKeyID: c.keyID(key('issuer')), representation: 'X509' },
    kemProof: { requestID: Buffer.alloc(32, 5), response: Buffer.alloc(32, 6) },
    validatePossessionCertificate: value => {
      calls.policy++;
      assert.deepEqual(value, certificate);
      p.validateCertificate(value, key('issuer'), { at: corpus.at });
      return true;
    },
  }), value => { assert.equal(value.code ?? value.message, error); return true; });
  assert.deepEqual(calls, expected);
});
