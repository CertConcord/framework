import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { createAuthorityResolver } from './authority-history.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors/certificate-validity-endpoints.json', import.meta.url)));
const original = vectors.certificates.find((entry) => entry.id === 'x509-utc');
const certificate = Buffer.from(original.certificateDER, 'base64');
const root = p.parseCertificate(Buffer.from(vectors.syntheticRootDER, 'base64')).publicKey;
const signer = p.parseCertificate(certificate).publicKey;
const start = vectors.notBefore;
const end = vectors.notAfter;
const trustDomainID = Buffer.alloc(32, 0x11);
const scope = { trustDomainID, profileID: original.profileID };
const status = {
  authorityID: c.keyID(signer), trustDomainID,
  scope: 'AUTHORITY', status: 'GOOD', publishedAt: start, nextUpdate: end + 2000,
};
const base = {
  mode: 'CERTIFICATE', certificate, roles: ['TIMESTAMP_AUTHORITY'], scopes: [scope],
  knownAt: start, validFrom: start, validUntil: end + 2000, status,
};
const query = (stateTime, knowledgeTime = stateTime) => ({
  certificate, role: 'TIMESTAMP_AUTHORITY', scope, stateTime, knowledgeTime,
});
const select = (change = {}) => createAuthorityResolver({
  trustDomainID, authorities: [{ ...base, ...change }],
});

test('X.509 certificate endpoint is inclusive in both primitive and authority selection', () => {
  const selected = select();
  assert.equal(c.sha256(certificate).toString('hex'), original.certificateSHA256);
  for (const at of [end - 0.125, end]) {
    assert.equal(p.validateCertificate(certificate, root, {
      at, profileID: original.profileID,
    }).notAfter, end);
    assert.equal(selected(query(at)).overall, 'VALID');
  }
  assert.throws(() => p.validateCertificate(certificate, root, {
    at: end + 0.125, profileID: original.profileID,
  }), { code: 'CERTIFICATE_TIME' });
  assert.equal(selected(query(end + 0.125)).reason, 'AUTHORITY_EXPIRED');
});

test('appointment and algorithm deadlines retain exclusive upper bounds', () => {
  const appointed = select({ validUntil: end });
  assert.equal(appointed(query(end - 0.125)).overall, 'VALID');
  assert.equal(appointed(query(end)).reason, 'AUTHORITY_EXPIRED');
  assert.equal(appointed(query(end + 0.125)).reason, 'AUTHORITY_EXPIRED');

  const algorithm = select({ algorithmValidUntil: end });
  assert.equal(algorithm(query(end - 0.125)).overall, 'VALID');
  assert.equal(algorithm(query(end)).reason, 'AUTHORITY_ALGORITHM_EXPIRED');
  assert.equal(algorithm(query(end + 0.125)).reason, 'AUTHORITY_EXPIRED');
});

test('status nextUpdate is a freshness deadline at knowledge time', () => {
  const selected = select({ status: { ...status, nextUpdate: end } });
  assert.equal(selected(query(start + 1, end - 0.125)).overall, 'VALID');
  assert.equal(selected(query(start + 1, end)).reason, 'AUTHORITY_STATUS_STALE');
  assert.equal(selected(query(start + 1, end + 0.125)).reason, 'AUTHORITY_STATUS_STALE');
});
