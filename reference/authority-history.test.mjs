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
  return { certificate, root, key, trustDomainID, record, query, resolver };
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

test('key compromise survives role changes and subsequent appointments', () => {
  const f = fixture();
  const status = { ...f.record.status, status: 'REVOKED', effectiveTime: 1800000005 };
  for (const earlier of [{ ...f.record, roles: ['ISSUER'], status },
    { ...f.record, validUntil: 1800000006, status }])
    assert.equal(f.resolver([f.record, earlier])(f.query).reason, 'AUTHORITY_REVOKED');
  assert.equal(f.resolver([{ ...f.record, status: { ...f.record.status, critical: ['futureConstraint'] } }])(f.query).overall, 'UNSUPPORTED');
});

test('raw key admission has an explicit lifecycle independent of a wrapping certificate', () => {
  const f = fixture(), raw = { ...f.record, mode: 'RAW_KEY', publicKeyDER: c.spki(f.key.publicKey) };
  delete raw.certificate;
  const resolve = f.resolver([raw]);
  assert.equal(resolve({ ...f.query, stateTime: 1800001500, knowledgeTime: 1800001500 }).overall, 'VALID');
  assert.equal(resolve({ ...f.query, stateTime: 1800002000, knowledgeTime: 1800002000 }).reason, 'AUTHORITY_EXPIRED');
  assert.throws(() => f.resolver([{ ...raw, validUntil: undefined }]), /UNSUPPORTED_TYPE|CONFIGURATION/);
});

test('known key compromise survives a different certificate wrapping the same key', () => {
  const f = fixture();
  const previousCertificate = p.issueCertificate({ publicKey: f.key.publicKey, serial: 2,
    issuer: p.name('Synthetic governance'), subject: p.name('Earlier authority certificate'),
    profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1', notBefore: 1799999000, notAfter: 1800000001 }, f.root.privateKey);
  const incident = { ...f.record, certificate: previousCertificate, roles: ['ISSUER'],
    status: { ...f.record.status, status: 'REVOKED', effectiveTime: 1800000005 } };
  assert.equal(f.resolver([f.record, incident])(f.query).reason, 'AUTHORITY_REVOKED');
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


test('authority guard accepts own synchronous decisions and preserves query metadata', () => {
  const query = { role: 'TIMESTAMP_AUTHORITY', stateTime: 1800000000.25, knowledgeTime: 1800000200 };
  for (const decision of [{ overall: 'VALID', reason: 'AUTHORITY_ADMITTED', coverageUntil: 1800000300 },
    Object.assign(Object.create(null), { overall: 'VALID' })]) {
    let calls = 0;
    const actual = requireAuthority((received) => { calls++; assert.equal(received, query); return decision; }, query);
    assert.equal(actual, decision);
    assert.equal(actual.overall, 'VALID');
    assert.equal(calls, 1);
    assert.deepEqual(query, { role: 'TIMESTAMP_AUTHORITY', stateTime: 1800000000.25, knowledgeTime: 1800000200 });
  }
});

test('authority guard rejects malformed decisions without executing accessors or proxy traps', () => {
  let hooks = 0;
  const forged = new Proxy({}, {
    get() { hooks++; return 'VALID'; },
    getPrototypeOf() { hooks++; return Object.prototype; },
    getOwnPropertyDescriptor() { hooks++; return { value: 'VALID', configurable: true }; },
    has() { hooks++; return false; },
  });
  const revoked = Proxy.revocable({}, {}); revoked.revoke();
  const cases = [undefined, null, true, 'VALID', 1, {}, { overall: 'UNKNOWN' },
    { overall: new Proxy({}, { get() { hooks++; throw Error('must not coerce'); } }) },
    Object.assign([], { overall: 'VALID' }), Object.assign(() => {}, { overall: 'VALID' }),
    Object.assign(new Date(), { overall: 'VALID' }), Object.create({ overall: 'VALID' }),
    { get overall() { hooks++; return hooks === 1 ? 'INVALID' : 'VALID'; } },
    { overall: 'VALID', then() { hooks++; } },
    { overall: 'VALID', get then() { hooks++; throw Error('must not read then'); } },
    forged, revoked.proxy];
  for (const [index, decision] of cases.entries()) {
    assert.throws(() => requireAuthority(() => decision, {}),
      { overall: 'INDETERMINATE', code: 'AUTHORITY_DECISION_MISSING' }, 'case ' + index);
  }
  assert.equal(hooks, 0);
});

test('authority guard preserves negative verdicts with safe reason metadata', () => {
  let hooks = 0;
  for (const overall of ['INVALID', 'INDETERMINATE', 'UNSUPPORTED']) {
    assert.throws(() => requireAuthority(() => ({ overall, reason: 'SELECTED_POLICY_FAILURE' }), {}),
      { overall, code: 'SELECTED_POLICY_FAILURE' });
    for (const decision of [{ overall }, { overall, reason: 7 }, { overall, reason: Symbol('reason') },
      { overall, reason: new Proxy({}, { get() { hooks++; throw Error('must not coerce'); } }) },
      { overall, get reason() { hooks++; throw Error('must not read reason'); } }]) {
      assert.throws(() => requireAuthority(() => decision, {}),
        { overall, code: 'AUTHORITY_DECISION_MISSING' });
    }
  }
  assert.equal(hooks, 0);
});

test('authority guard rejects native promises and observes ordinary rejected results', async () => {
  const decisions = [Promise.resolve({ overall: 'VALID' }),
    Object.assign(Promise.resolve({ overall: 'INVALID' }), { overall: 'VALID' }),
    Promise.reject(Error('unavailable asynchronous authority')),
    Object.assign(Promise.reject(Error('decorated asynchronous authority')), { overall: 'VALID' })];
  for (const decision of decisions) {
    assert.throws(() => requireAuthority(() => decision, {}),
      { overall: 'INDETERMINATE', code: 'AUTHORITY_DECISION_MISSING' });
  }
  await new Promise((resolve) => setImmediate(resolve));
});

test('authority guard rejects promises when rejection observation throws', () => {
  const constructorFailure = Promise.resolve({ overall: 'VALID' });
  Object.defineProperty(constructorFailure, 'constructor', { get() { throw Error('constructor unavailable'); } });
  class SpeciesFailure extends Promise {
    static get [Symbol.species]() { throw Error('species unavailable'); }
  }
  for (const decision of [constructorFailure, SpeciesFailure.resolve({ overall: 'VALID' })]) {
    Object.assign(decision, { overall: 'VALID' });
    assert.throws(() => requireAuthority(() => decision, {}),
      { overall: 'INDETERMINATE', code: 'AUTHORITY_DECISION_MISSING' });
  }
});

test('authority guard preserves missing resolver and synchronous exception behavior', () => {
  assert.throws(() => requireAuthority(undefined, {}),
    { overall: 'INDETERMINATE', code: 'AUTHORITY_RESOLVER_REQUIRED' });
  const unavailable = Error('selected policy unavailable');
  assert.throws(() => requireAuthority(() => { throw unavailable; }, {}), (error) => error === unavailable);
});
