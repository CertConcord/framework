import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { createAuthorityResolver, requireAuthority } from './authority-history.mjs';

function fixture() {
  const root = c.generate('ml-dsa-87'), key = c.generate('ml-dsa-87');
  const certificate = p.issueCertificate({ publicKey: key.publicKey, serial: 1,
    issuer: p.name('Synthetic governance'), subject: p.name('Synthetic permit authority'),
    profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1', notBefore: 1800000000, notAfter: 1800001000 }, root.privateKey);
  const trustDomainID = c.random(), scope = { trustDomainID, profileID: 'CERTCONCORD-PERSON-SIGN-v1' };
  const record = { mode: 'CERTIFICATE', certificate, roles: ['PERMIT_AUTHORITY'], scopes: [scope],
    knownAt: 1800000000, validFrom: 1800000000, validUntil: 1800002000,
    status: { authorityID: c.keyID(key.publicKey), trustDomainID,
      scope: 'AUTHORITY', status: 'GOOD', publishedAt: 1800000000, nextUpdate: 1800003000 } };
  const query = { certificate, role: 'PERMIT_AUTHORITY', scope, stateTime: 1800000010, knowledgeTime: 1800000011 };
  const resolver = (records = [record]) => createAuthorityResolver({ trustDomainID, authorities: records });
  return { certificate, key, trustDomainID, record, query, resolver };
}

test('control authority pins require role, scope, certificate validity and knowledge coverage', () => {
  const f = fixture(), resolve = f.resolver();
  assert.equal(resolve(f.query).overall, 'VALID');
  assert.equal(resolve({ ...f.query, stateTime: 1800000010.5 }).overall, 'VALID');
  assert.equal(resolve({ ...f.query, role: 'ISSUER' }).reason, 'AUTHORITY_ROLE');
  assert.equal(resolve({ ...f.query, scope: { ...f.query.scope, profileID: 'CERTCONCORD-ORG-SEAL-v1' } }).reason, 'AUTHORITY_SCOPE');
  assert.equal(resolve({ ...f.query, scope: { ...f.query.scope, trustDomainID: c.random() } }).reason, 'AUTHORITY_SCOPE');
  assert.equal(resolve({ ...f.query, stateTime: 1799999999 }).reason, 'AUTHORITY_NOT_YET_VALID');
  assert.equal(resolve({ ...f.query, stateTime: 1800001000, knowledgeTime: 1800001000 }).reason, 'AUTHORITY_EXPIRED');
  assert.equal(resolve({ ...f.query, knowledgeTime: 1800003000 }).overall, 'INDETERMINATE');
  assert.equal(resolve({ ...f.query, knowledgeTime: 1800000010 }).overall, 'VALID');
});

test('a later discovered compromise changes current authorization without rewriting history', () => {
  const f = fixture();
  const compromised = { ...f.record, status: { ...f.record.status, status: 'REVOKED',
    publishedAt: 1800000100, nextUpdate: 1800003000, effectiveTime: 1800000100, compromiseStart: 1800000005 } };
  const resolve = f.resolver([compromised]);
  assert.equal(resolve(f.query).overall, 'INDETERMINATE');
  assert.equal(resolve({ ...f.query, knowledgeTime: 1800000100 }).reason, 'AUTHORITY_REVOKED');
  // A known revocation takes precedence over unavailable fresh evidence.
  assert.equal(resolve({ ...f.query, knowledgeTime: 1800004000 }).overall, 'INVALID');
  assert.equal(resolve({ ...f.query, stateTime: 1800000001, knowledgeTime: 1800000100 }).overall, 'VALID');
});

test('authority status cannot be transplanted from another key or domain', () => {
  const f = fixture();
  for (const change of [{ authorityID: c.random(64) }, { trustDomainID: c.random() }])
    assert.equal(f.resolver([{ ...f.record, status: { ...f.record.status, ...change } }])(f.query).overall, 'INVALID');
});

test('nonoverlapping appointments resolve at state time and future grants cannot be backdated', () => {
  const f = fixture();
  const earlier = { ...f.record, validUntil: 1800000020 };
  const later = { ...f.record, knownAt: 1800000020, validFrom: 1800000020 };
  assert.equal(f.resolver([earlier, later])(f.query).overall, 'VALID');
  assert.equal(f.resolver([later])(f.query).overall, 'INDETERMINATE');
  assert.equal(f.resolver([earlier, later])({ ...f.query, stateTime: 1800000030, knowledgeTime: 1800000030 }).overall, 'VALID');
  const revoked = { ...f.record, status: { ...f.record.status, status: 'REVOKED', effectiveTime: 1800000005 } };
  assert.equal(f.resolver([f.record, revoked])(f.query).overall, 'INVALID');
});

test('raw key admission has an explicit lifecycle independent of a wrapping certificate', () => {
  const f = fixture(), raw = { ...f.record, mode: 'RAW_KEY', publicKeyDER: c.spki(f.key.publicKey) };
  delete raw.certificate;
  const resolve = f.resolver([raw]);
  assert.equal(resolve({ ...f.query, stateTime: 1800001500, knowledgeTime: 1800001500 }).overall, 'VALID');
  assert.equal(resolve({ ...f.query, stateTime: 1800002000, knowledgeTime: 1800002000 }).reason, 'AUTHORITY_EXPIRED');
  assert.throws(() => f.resolver([{ ...raw, validUntil: undefined }]), /UNSUPPORTED_TYPE|CONFIGURATION/);
});

test('authority configuration is snapshotted and cannot gain roles after selection', () => {
  const f = fixture(), resolve = f.resolver();
  f.record.roles.push('ISSUER');
  f.record.status.status = 'REVOKED';
  f.record.scopes[0].profileID = 'CERTCONCORD-ORG-SEAL-v1';
  assert.equal(resolve({ ...f.query, scope: { trustDomainID: f.trustDomainID, profileID: 'CERTCONCORD-PERSON-SIGN-v1' } }).overall, 'VALID');
  assert.equal(resolve({ ...f.query, role: 'ISSUER' }).reason, 'AUTHORITY_ROLE');
});

test('missing, conflicting, unavailable and unsupported authority decisions prevent acceptance', () => {
  const f = fixture();
  assert.equal(f.resolver([])(f.query).overall, 'INDETERMINATE');
  assert.equal(f.resolver([f.record, f.record])(f.query).reason, 'AUTHORITY_CONFLICT');
  assert.equal(f.resolver([{ ...f.record, status: () => { throw Error('offline'); } }])(f.query).overall, 'INDETERMINATE');
  assert.equal(f.resolver([{ ...f.record, status: { overall: 'VALID' } }])(f.query).overall, 'INVALID');
  assert.equal(f.resolver()( { ...f.query, role: 'UNKNOWN' }).overall, 'UNSUPPORTED');
  assert.throws(() => requireAuthority(undefined, f.query), (error) => error.overall === 'INDETERMINATE');
  assert.throws(() => requireAuthority(f.resolver(), { ...f.query, role: 'ISSUER' }), (error) => error.overall === 'INVALID');
});
