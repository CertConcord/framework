import fs from 'node:fs';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import * as c from '../reference/core.mjs';

// Public synthetic inputs for the generic resolver's authenticated-policy boundary.
// Private keys are generated only in memory and are never included in the corpus.
const t = 1800000000, role = 'DOCUMENT_SEAL';
const domain = c.sha256(Buffer.from('synthetic RSA authority equivalence domain'));
const scope = { trustDomainID: domain, purpose: 'document-signature' };
const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const original = c.spki(pair.publicKey), originalParts = c.parseDER(original).children;
const nullValue = c.der(5, Buffer.alloc(0));
const hashes = { sha256: '2.16.840.1.101.3.4.2.1', sha384: '2.16.840.1.101.3.4.2.2' };
const hashID = hash => c.seq(c.oid(hashes[hash]), nullValue);
const pss = (hash, mgfHash, salt) => c.seq(c.oid('1.2.840.113549.1.1.10'), c.seq(
  c.der(0xa0, hashID(hash)), c.der(0xa1, c.seq(c.oid('1.2.840.113549.1.1.8'), hashID(mgfHash))),
  c.der(0xa2, c.integer(salt))));
const wrap = algorithm => c.seq(algorithm, originalParts[1].raw);
const rsaParts = c.parseDER(originalParts[1].value.subarray(1)).children;
const keys = {
  rsa: original,
  pss256: wrap(pss('sha256', 'sha256', 32)),
  pss384: wrap(pss('sha384', 'sha384', 48)),
  pssSalt64: wrap(pss('sha256', 'sha256', 64)),
  pssMgf384: wrap(pss('sha256', 'sha384', 32)),
  pssAbsent: wrap(c.seq(c.oid('1.2.840.113549.1.1.10'))),
  pssDefaults: wrap(c.seq(c.oid('1.2.840.113549.1.1.10'), c.seq())),
  differentExponent: c.seq(originalParts[0].raw, c.bit(c.seq(rsaParts[0].raw, c.integer(3)))),
  zeroExponent: c.seq(originalParts[0].raw, c.bit(c.seq(rsaParts[0].raw, c.integer(0)))),
  zeroModulus: c.seq(originalParts[0].raw, c.bit(c.seq(c.integer(0), rsaParts[1].raw))),
  zeroBoth: c.seq(originalParts[0].raw, c.bit(c.seq(c.integer(0), c.integer(0)))),
  differentModulus: c.spki(crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey),
  unrelatedEC: c.spki(crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey),
};
const status = name => ({ authorityID: c.keyID(c.publicFromDER(keys[name])), trustDomainID: domain,
  scope: 'AUTHORITY', status: 'GOOD', publishedAt: t, nextUpdate: t + 500 });
const record = name => ({ mode: 'RAW_KEY', publicKeyDER: keys[name], knownAt: t,
  validFrom: t, validUntil: t + 1000, roles: [role], scopes: [scope], status: status(name) });
const query = name => ({ publicKeyDER: keys[name], role, scope, stateTime: t + 40, knowledgeTime: t + 80 });
const revoke = row => Object.assign(row.status, { status: 'REVOKED', publishedAt: t + 60,
  effectiveTime: t + 10, compromiseStart: t + 5 });
const expected = reason => reason === 'AUTHORITY_ADMITTED'
  ? { overall: 'VALID', reason, role, mode: 'RAW_KEY', coverageUntil: t + 500 }
  : { overall: ['AUTHORITY_MISSING', 'AUTHORITY_NOT_YET_KNOWN', 'AUTHORITY_STATUS_MISSING', 'AUTHORITY_STATUS_STALE'].includes(reason)
    ? 'INDETERMINATE' : 'INVALID', reason, ...(reason === 'AUTHORITY_REVOKED' ? { status: 'REVOKED' } :
    reason === 'AUTHORITY_STATUS_STALE' ? { status: 'STALE' } : {}) };
const packed = value => { const bytes = c.dcbor(value); return { bytes: bytes.length, sha256: c.sha256(bytes).toString('hex'), cbor: bytes.toString('base64') }; };
const cases = [];
function add(id, target = 'pss256', source = 'rsa', change = () => {}, reason = 'AUTHORITY_REVOKED') {
  const config = { trustDomainID: domain, authorities: [record(target), record(source)] }, q = query(target);
  revoke(config.authorities[1]); change(config, q);
  cases.push({ id, config: packed(config), query: packed(q), expected: expected(reason) });
}
for (const name of Object.keys(keys).filter(name => name.startsWith('pss'))) {
  add('rsa-revokes-' + name, name, 'rsa');
  add(name + '-revokes-rsa', 'rsa', name);
}
add('pss256-revokes-pss384', 'pss384', 'pss256');
add('pss384-revokes-pss256', 'pss256', 'pss384');
for (const [target, source] of [['pss256', 'rsa'], ['rsa', 'pss256']]) {
  const addFor = (id, change, reason) => add(target + '/' + id, target, source, change, reason);
  addFor('both-good', config => { config.authorities[1].status = status(source); }, 'AUTHORITY_ADMITTED');
  addFor('exact-revoked', config => { revoke(config.authorities[0]); });
  addFor('target-unselected', config => { config.authorities.shift(); }, 'AUTHORITY_MISSING');
  addFor('target-future-known', config => { config.authorities[0].knownAt = t + 81; }, 'AUTHORITY_NOT_YET_KNOWN');
  addFor('source-future-known', config => { config.authorities[1].knownAt = t + 81; }, 'AUTHORITY_ADMITTED');
  addFor('source-known-at-boundary', config => { config.authorities[1].knownAt = t + 80; });
  addFor('source-wrong-status-key', config => { config.authorities[1].status.authorityID = status(target).authorityID; }, 'AUTHORITY_ADMITTED');
  addFor('source-wrong-status-domain', config => { config.authorities[1].status.trustDomainID = Buffer.alloc(32, 0x83); }, 'AUTHORITY_ADMITTED');
  for (const field of ['authorityID', 'trustDomainID'])
    addFor('target-wrong-' + field, config => {
      config.authorities[1].status = status(source);
      config.authorities[0].status[field] = Buffer.alloc(field === 'authorityID' ? 64 : 32, 0x83);
    }, 'AUTHORITY_STATUS_BINDING');
  addFor('future-publication', config => { config.authorities[1].status.publishedAt = t + 81; }, 'AUTHORITY_ADMITTED');
  addFor('publication-at-knowledge', config => { config.authorities[1].status.publishedAt = t + 80; });
  for (const [offset, reason] of [[39, 'AUTHORITY_REVOKED'], [40, 'AUTHORITY_REVOKED'], [41, 'AUTHORITY_ADMITTED']]) {
    addFor('effective-' + offset, config => {
      config.authorities[1].status.effectiveTime = t + offset;
      delete config.authorities[1].status.compromiseStart;
    }, reason);
    addFor('compromise-' + offset, config => Object.assign(config.authorities[1].status,
      { effectiveTime: t + 100, compromiseStart: t + offset }), reason);
  }
  addFor('invalid-query-time', (config, q) => { q.stateTime = t + 81; }, 'AUTHORITY_TIME');
  addFor('stale-revocation', config => { config.authorities[1].status.nextUpdate = t + 70; });
  addFor('expired-other-role-source', config => Object.assign(config.authorities[1], { validUntil: t + 1, roles: ['ISSUER'] }));
  addFor('revoke-before-role-gate', config => { config.authorities[0].roles = ['ISSUER']; });
  for (const [id, change] of [
    ['source-missing', r => { delete r.status; }],
    ['source-unknown', r => { r.status.status = 'UNKNOWN'; }],
    ['source-stale-good', r => { r.status.status = 'GOOD'; r.status.nextUpdate = t + 70; }],
    ['source-unsupported-good', r => { r.status.status = 'GOOD'; r.status.critical = ['future']; }],
    ['source-malformed', r => { r.status.effectiveTime = 'invalid'; }],
  ]) addFor(id, config => change(config.authorities[1]), 'AUTHORITY_ADMITTED');
  for (const [id, change, reason] of [
    ['wrong-role', r => { r.roles = ['ISSUER']; }, 'AUTHORITY_ROLE'],
    ['narrow-scope', r => { r.scopes = [{ ...scope, issuerID: 'other' }]; }, 'AUTHORITY_SCOPE'],
    ['not-yet-valid', r => { r.validFrom = t + 41; }, 'AUTHORITY_NOT_YET_VALID'],
    ['expired', r => { r.validUntil = t + 40; }, 'AUTHORITY_EXPIRED'],
    ['algorithm-equal', r => { r.algorithmValidUntil = t + 40; }, 'AUTHORITY_ALGORITHM_EXPIRED'],
    ['algorithm-after', r => { r.algorithmValidUntil = t + 41; }, 'AUTHORITY_ADMITTED'],
    ['missing-status', r => { delete r.status; }, 'AUTHORITY_STATUS_MISSING'],
    ['stale-status', r => { r.status.nextUpdate = t + 80; }, 'AUTHORITY_STATUS_STALE'],
  ]) addFor('good-alias-cannot-repair-' + id, config => {
    config.authorities[1].status = status(source); change(config.authorities[0]);
  }, reason);
  addFor('foreign-query-domain', (config, q) => { q.scope = { ...scope, trustDomainID: Buffer.alloc(32, 0x83) }; }, 'AUTHORITY_SCOPE');
}
for (const other of ['differentExponent', 'differentModulus', 'unrelatedEC'])
  add('unrelated-' + other, 'pss256', other, () => {}, 'AUTHORITY_ADMITTED');
// Native import accepts these unusable RSA values. A negative-equivalence lookup
// must not turn an unrelated record into a query exception or a positive grant.
for (const target of ['rsa', 'pss256']) for (const source of ['zeroExponent', 'zeroModulus', 'zeroBoth']) {
  add(target + '/unusable-revoked-' + source, target, source, () => {}, 'AUTHORITY_ADMITTED');
  add(target + '/unusable-good-' + source, target, source, config => {
    config.authorities[1].status = status(source);
  }, 'AUTHORITY_ADMITTED');
}
const message = Buffer.from('Synthetic generic authority RSA parameter restriction control.');
const sign = (hash, padding, saltLength) => crypto.sign(hash, message,
  { key: pair.privateKey, padding, ...(saltLength === undefined ? {} : { saltLength }) }).toString('base64');
const corpus = { schemaVersion: 1,
  description: 'Fresh synthetic generic RAW_KEY policy inputs. Status and appointments are assumed authenticated by the caller. These vectors do not add an RSA signature profile or production assurance.',
  keys: Object.fromEntries(Object.entries(keys).map(([id, der]) => {
    const key = c.publicFromDER(der); assert.deepEqual(c.spki(key), der);
    return [id, { der: der.toString('base64'), bytes: der.length, sha256: c.sha256(der).toString('hex'),
      keyID: c.keyID(key).toString('hex'), nativeType: key.asymmetricKeyType }];
  })),
  signatureControls: { message: message.toString('base64'),
    pss256Salt32: sign('sha256', crypto.constants.RSA_PKCS1_PSS_PADDING, 32),
    pss256Salt64: sign('sha256', crypto.constants.RSA_PKCS1_PSS_PADDING, 64),
    pss384Salt48: sign('sha384', crypto.constants.RSA_PKCS1_PSS_PADDING, 48),
    pkcs1Sha256: sign('sha256', crypto.constants.RSA_PKCS1_PADDING) }, cases };
assert.equal(new Set(cases.map(row => row.id)).size, cases.length);
fs.writeFileSync(new URL('../reference/vectors/authority-rsa-equivalence.json', import.meta.url), JSON.stringify(corpus, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ keys: Object.keys(keys).length, cases: cases.length }));
