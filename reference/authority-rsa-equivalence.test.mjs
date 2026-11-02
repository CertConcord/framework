import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import * as c from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';

const corpus = JSON.parse(fs.readFileSync(new URL('./vectors/authority-rsa-equivalence.json', import.meta.url)));
const unpack = row => {
  const raw = Buffer.from(row.cbor, 'base64');
  assert.equal(raw.length, row.bytes); assert.equal(c.sha256(raw).toString('hex'), row.sha256);
  assert.deepEqual(c.dcbor(c.decodeCBOR(raw)), raw);
  return c.decodeCBOR(raw);
};
const getCase = id => { const row = corpus.cases.find(row => row.id === id); assert(row); return row; };
const material = id => c.publicFromDER(Buffer.from(corpus.keys[id].der, 'base64'));

test('RSA authority corpus preserves distinct original SPKI identities and mathematical controls', () => {
  assert.equal(corpus.schemaVersion, 1);
  assert.equal(new Set(corpus.cases.map(row => row.id)).size, corpus.cases.length);
  const ids = new Set(), bits = new Map();
  for (const [name, row] of Object.entries(corpus.keys)) {
    const der = Buffer.from(row.der, 'base64'), key = material(name);
    assert.equal(der.length, row.bytes); assert.equal(c.sha256(der).toString('hex'), row.sha256);
    assert.deepEqual(c.spki(key), der); assert.equal(c.keyID(key).toString('hex'), row.keyID);
    assert.equal(key.asymmetricKeyType, row.nativeType); ids.add(row.keyID);
    if (name !== 'unrelatedEC') bits.set(name, c.parseDER(c.parseDER(der).children[1].value.subarray(1)).children);
  }
  assert.equal(ids.size, 13);
  for (const name of Object.keys(corpus.keys).filter(name => name.startsWith('pss')))
    assert.deepEqual(bits.get(name).map(row => row.raw), bits.get('rsa').map(row => row.raw));
  assert.deepEqual(bits.get('differentExponent')[0].raw, bits.get('rsa')[0].raw);
  assert.notDeepEqual(bits.get('differentExponent')[1].raw, bits.get('rsa')[1].raw);
  assert.notDeepEqual(bits.get('differentModulus')[0].raw, bits.get('rsa')[0].raw);
  assert.deepEqual(bits.get('differentModulus')[1].raw, bits.get('rsa')[1].raw);
  assert.equal(c.intValue(bits.get('zeroExponent')[1]), 0n);
  assert.equal(c.intValue(bits.get('zeroModulus')[0]), 0n);
  assert(bits.get('zeroBoth').every(value => c.intValue(value) === 0n));
  // The ordinary RSA native export is an independent n/e control for the saved DER.
  const jwk = material('rsa').export({ format: 'jwk' });
  const positiveIntegerBytes = row => row.value[0] === 0 ? row.value.subarray(1) : row.value;
  assert.deepEqual(positiveIntegerBytes(bits.get('rsa')[0]), Buffer.from(jwk.n, 'base64url'));
  assert.deepEqual(positiveIntegerBytes(bits.get('rsa')[1]), Buffer.from(jwk.e, 'base64url'));
});

for (const row of corpus.cases) test('RSA authority equivalence: ' + row.id, () => {
  const config = unpack(row.config), query = unpack(row.query);
  const beforeConfig = c.dcbor(config), beforeQuery = c.dcbor(query);
  assert.deepEqual(createAuthorityResolver(config)(query), row.expected);
  assert.deepEqual(c.dcbor(config), beforeConfig); assert.deepEqual(c.dcbor(query), beforeQuery);
});

for (const [target, source] of [['pss256', 'rsa'], ['rsa', 'pss256']]) {
  test('RSA authority fractional query time retains the compromise boundary: ' + target, () => {
    const row = getCase(source === 'rsa' ? 'rsa-revokes-pss256' : 'pss256-revokes-rsa');
    const config = unpack(row.config), query = unpack(row.query);
    query.stateTime += 0.5;
    const before = unpack(row.query); before.stateTime = query.stateTime;
    Object.assign(config.authorities[1].status, { effectiveTime: 1800000100, compromiseStart: 1800000041 });
    assert.deepEqual(createAuthorityResolver(config)(query), getCase(target + '/both-good').expected);
    config.authorities[1].status.compromiseStart = 1800000040;
    assert.deepEqual(createAuthorityResolver(config)(query), row.expected);
    assert.deepEqual(query, before);
  });
  test('RSA authority callbacks retain original bindings and one evaluation: ' + target, () => {
    const row = getCase(source === 'rsa' ? 'rsa-revokes-pss256' : 'pss256-revokes-rsa');
    const config = unpack(row.config), query = unpack(row.query), calls = [], contexts = [];
    const original = config.authorities.map(record => record.status);
    for (const [index, record] of config.authorities.entries()) record.status = context => {
      calls.push(index);
      contexts.push(c.dcbor(context));
      // The callback receives a copy; mutation cannot rewrite the resolver's binding.
      context.authorityID.fill(0); context.scope.trustDomainID.fill(0);
      return original[index];
    };
    assert.deepEqual(createAuthorityResolver(config)(query), row.expected);
    assert.deepEqual(calls, [0, 1]); assert.deepEqual(query, unpack(row.query));
    assert.deepEqual(contexts, original.map(statement => c.dcbor({ authorityID: statement.authorityID,
      role: query.role, scope: query.scope, stateTime: query.stateTime, knowledgeTime: query.knowledgeTime })));
  });
  test('RSA authority callback failures cannot transfer unrelated status: ' + target, () => {
    const row = getCase(target + '/both-good'), base = unpack(row.config), query = unpack(row.query);
    const failures = [
      () => { throw new Error('unavailable'); }, () => undefined,
      () => ({ overall: 'INDETERMINATE', reason: 'AUTHORITY_STATUS_UNAVAILABLE' }),
      () => ({ overall: 'UNSUPPORTED', reason: 'AUTHORITY_STATUS_CRITICAL_UNSUPPORTED' }),
      () => ({ overall: 'INVALID', reason: 'AUTHORITY_STATUS_BINDING' }),
      () => ({ overall: 'INDETERMINATE', reason: 'AUTHORITY_REVOKED' }),
      () => ({ then() {} }),
    ];
    for (const failure of failures) {
      const config = c.decodeCBOR(c.dcbor(base)); let calls = 0;
      config.authorities[1].status = () => { calls++; return failure(); };
      assert.deepEqual(createAuthorityResolver(config)(query), row.expected); assert.equal(calls, 1);
    }
    const config = c.decodeCBOR(c.dcbor(base));
    config.authorities[1].status = () => ({ overall: 'INVALID', reason: 'AUTHORITY_REVOKED' });
    assert.deepEqual(createAuthorityResolver(config)(query), { overall: 'INVALID', reason: 'AUTHORITY_REVOKED' });
  });
}

test('RSA negative equivalence preserves native PSS signature restrictions and governed algorithm limits', () => {
  const controls = corpus.signatureControls, message = Buffer.from(controls.message, 'base64');
  const signatures = Object.fromEntries(Object.entries(controls).filter(([name]) => name !== 'message')
    .map(([name, value]) => [name, Buffer.from(value, 'base64')]));
  const verify = (key, hash, signature, padding = crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength = 32) =>
    crypto.verify(hash, message, { key: material(key), padding, saltLength }, signatures[signature]);
  const rejected = action => {
    let actual;
    try { actual = action(); }
    catch (error) { assert.match(error.code ?? '', /^ERR_(OSSL|CRYPTO)_/); return; }
    assert.equal(actual, false);
  };
  assert.equal(verify('pss256', 'sha256', 'pss256Salt32'), true);
  assert.equal(verify('pss384', 'sha384', 'pss384Salt48', crypto.constants.RSA_PKCS1_PSS_PADDING, 48), true);
  assert.equal(verify('pssSalt64', 'sha256', 'pss256Salt64', crypto.constants.RSA_PKCS1_PSS_PADDING, 64), true);
  assert.equal(verify('pssAbsent', 'sha256', 'pss256Salt32'), true);
  rejected(() => verify('pss256', 'sha384', 'pss384Salt48', crypto.constants.RSA_PKCS1_PSS_PADDING, 48));
  rejected(() => verify('pss256', 'sha256', 'pss256Salt32', crypto.constants.RSA_PKCS1_PSS_PADDING, 20));
  rejected(() => verify('pss256', 'sha256', 'pkcs1Sha256', crypto.constants.RSA_PKCS1_PADDING));
  rejected(() => verify('pssSalt64', 'sha256', 'pss256Salt32'));
  rejected(() => verify('pssMgf384', 'sha256', 'pss256Salt32'));
  rejected(() => verify('pssDefaults', 'sha256', 'pss256Salt32'));
  for (const key of ['rsa', 'pss256'])
    assert.throws(() => c.verify(message, signatures.pss256Salt32, material(key)), /NOT_SIGNING_KEY/);
});

test('RSA equivalence cannot repair an invalid identity encoding', () => {
  const row = getCase('rsa-revokes-pss256'), config = unpack(row.config), query = unpack(row.query);
  const resolve = createAuthorityResolver(config);
  for (const malformed of [Buffer.alloc(0), query.publicKeyDER.subarray(0, 12), Buffer.from([0x30, 0])]) {
    assert.deepEqual(resolve({ ...query, publicKeyDER: malformed }), { overall: 'INVALID', reason: 'AUTHORITY_IDENTITY' });
    const input = unpack(row.config); input.authorities[1].publicKeyDER = malformed;
    assert.throws(() => createAuthorityResolver(input));
  }
});
