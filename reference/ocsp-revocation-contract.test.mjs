import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { bit, der, integer, octet, parseDER, seq } from './core.mjs';
import { generalizedTime, name } from './pki.mjs';
import { issueOCSP, ocspRequest, verifyOCSP } from './revocation.mjs';

const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
  issuer = name('Synthetic OCSP reason issuer'), serial = 47n,
  base = Date.parse('2026-02-02T00:00:00Z') / 1000,
  thisUpdate = base + 120, nextUpdate = base + 300, revokedAt = base + 60,
  request = ocspRequest({ issuer, issuerPublicKey: key.publicKey, serial });
const time = generalizedTime(revokedAt);
const reasonField = (bytes) => der(0xa0, der(10, Buffer.from(bytes)));
const issue = (reason, timing = {}) => issueOCSP(request.raw, {
  issuer, issuerPublicKey: key.publicKey, privateKey: key.privateKey,
  thisUpdate, nextUpdate, ...timing,
  records: new Map([[String(serial), { status: 'REVOKED', revokedAt, reason }]]),
});
const evaluate = (raw, at = base + 150, knowledgeTime = at, selectedRequest = request.raw) =>
  verifyOCSP(raw, { request: selectedRequest, issuerPublicKey: key.publicKey, at, knowledgeTime });
function replaceInfo(raw, contents) {
  const outer = parseDER(raw).children, response = outer[1].children[0].children,
    [oldTBS, algorithm] = parseDER(response[1].value).children,
    single = oldTBS.children[2].children[0].children,
    changed = seq(...single.map((n, i) => i === 1 ? der(0xa1, contents) : n.raw)),
    tbs = seq(...oldTBS.children.map((n, i) => i === 2 ? seq(changed) : n.raw));
  return seq(outer[0].raw, der(0xa0, seq(response[0].raw,
    octet(seq(tbs, algorithm.raw, bit(sign('sha256', tbs, key.privateKey)))))));
}
const held = issue(6);
const details = (revocationReason) => ({ thisUpdate, nextUpdate, producedAt: thisUpdate, revokedAt,
  ...(revocationReason === undefined ? {} : { revocationReason }) });

for (const reason of [0, 1, 2, 3, 4, 5, 6, 9, 10])
  test('OCSP issuer preserves numeric reason ' + reason, () => {
    const raw = issue(reason), current = evaluate(raw);
    assert.deepEqual(current, { ...details(reason), status: 'REVOKED', overall: 'INVALID', reason: 'OCSP_REVOKED' });
    assert.deepEqual(evaluate(raw, base + 30, base + 130), {
      ...details(reason), status: 'GOOD', overall: 'VALID',
    });
    assert(Object.isFrozen(current));
  });

for (const [label, reason] of [
  ['negative', -1], ['reserved', 7], ['unknown', 11], ['byte overflow', 256],
  ['hold after byte truncation', 262], ['fraction', 6.5], ['NaN', NaN],
  ['infinity', Infinity], ['string', '6'], ['true', true], ['false', false],
  ['bigint', 6n], ['object', {}], ['buffer', Buffer.from([6])],
]) test('OCSP issuer rejects ' + label + ' reason without coercion', () => {
  assert.throws(() => issue(reason), { code: 'OCSP_REVOCATION_REASON' });
});

test('OCSP issuer rejects removeFromCRL and retains nullish unspecified default', () => {
  assert.throws(() => issue(8), { code: 'OCSP_REVOCATION_REASON_UNSUPPORTED' });
  for (const value of [undefined, null]) assert.equal(evaluate(issue(value)).revocationReason, 0);
});

const malformed = [
  ['INTEGER reason', Buffer.concat([time, der(0xa0, integer(6))]), 'OCSP_REVOCATION_REASON'],
  ['empty reason', Buffer.concat([time, reasonField([])]), 'OCSP_REVOCATION_REASON'],
  ['negative reason', Buffer.concat([time, reasonField([255])]), 'OCSP_REVOCATION_REASON'],
  ['reserved reason', Buffer.concat([time, reasonField([7])]), 'OCSP_REVOCATION_REASON'],
  ['unknown reason', Buffer.concat([time, reasonField([11])]), 'OCSP_REVOCATION_REASON'],
  ['nonminimal reason', Buffer.concat([time, reasonField([0, 6])]), 'OCSP_REVOCATION_REASON'],
  ['multiple values', Buffer.concat([time, der(0xa0, Buffer.concat([der(10, Buffer.from([6])), der(10, Buffer.from([1]))]))]), 'OCSP_REVOCATION_REASON'],
  ['wrong wrapper', Buffer.concat([time, der(0xa1, der(10, Buffer.from([6])))]), 'OCSP_REVOCATION_REASON'],
  ['empty wrapper', Buffer.concat([time, der(0xa0, Buffer.alloc(0))]), 'OCSP_REVOCATION_REASON'],
  ['duplicate wrapper', Buffer.concat([time, reasonField([6]), reasonField([1])]), 'OCSP_REVOKED_INFO'],
  ['extra NULL', Buffer.concat([time, reasonField([6]), der(5, Buffer.alloc(0))]), 'OCSP_REVOKED_INFO'],
  ['empty RevokedInfo', Buffer.alloc(0), 'OCSP_REVOKED_INFO'],
  ['wrong time type', Buffer.concat([der(23, Buffer.from('260202000100Z')), reasonField([6])]), 'STATUS_TIME'],
  ['impossible date', Buffer.concat([der(24, Buffer.from('20260230000100Z')), reasonField([6])]), 'STATUS_TIME'],
];
for (const [label, contents, reason] of malformed)
  test('OCSP rejects ' + label + ' before temporal classification', () => {
    const raw = replaceInfo(held, contents);
    for (const [at, knowledgeTime] of [
      [base + 30, base + 130], [base + 150, base + 150],
      [base + 90, base + 90], [base + 610, base + 610],
    ]) {
      const result = evaluate(raw, at, knowledgeTime);
      assert.deepEqual(result, { status: 'INVALID', overall: 'INVALID', reason });
      assert(Object.isFrozen(result));
    }
  });

test('OCSP distinguishes omitted and explicit unspecified reasons from a temporary hold', () => {
  const absent = replaceInfo(held, time);
  assert.deepEqual(evaluate(absent), { ...details(), status: 'REVOKED', overall: 'INVALID', reason: 'OCSP_REVOKED' });
  for (const raw of [absent, issue(0), issue(1), issue(9), issue(10)]) {
    const result = evaluate(raw, nextUpdate, nextUpdate);
    assert.equal(result.status, 'REVOKED');
    assert.equal(result.overall, 'INVALID');
  }
  assert.equal(Object.hasOwn(evaluate(absent), 'revocationReason'), false);
  assert.equal(evaluate(issue(0)).revocationReason, 0);
});

test('OCSP temporary hold expires by knowledge time without asserting release', () => {
  assert.equal(evaluate(held, nextUpdate - 1).status, 'REVOKED');
  for (const [at, knowledgeTime] of [
    [nextUpdate, nextUpdate], [nextUpdate + 1, nextUpdate + 1],
    [base + 150, nextUpdate], [base + 30, nextUpdate],
  ]) assert.deepEqual(evaluate(held, at, knowledgeTime), {
    ...details(6), status: 'STALE', overall: 'INDETERMINATE', reason: 'OCSP_STALE',
  });
  assert.deepEqual(evaluate(held, base + 90, base + 90), {
    ...details(6), status: 'UNKNOWN', overall: 'INDETERMINATE', reason: 'OCSP_NOT_YET_KNOWN',
  });
  assert.equal(evaluate(held, nextUpdate + 10, nextUpdate - 1).status, 'REVOKED');
});

test('OCSP removeFromCRL is unsupported only after publication is known', () => {
  const raw = replaceInfo(held, Buffer.concat([time, reasonField([8])]));
  for (const [at, knowledgeTime] of [[base + 30, base + 130], [base + 150, base + 150], [nextUpdate, nextUpdate]])
    assert.deepEqual(evaluate(raw, at, knowledgeTime), {
      ...details(8), status: 'UNSUPPORTED', overall: 'UNSUPPORTED', reason: 'OCSP_REVOCATION_REASON_UNSUPPORTED',
    });
  assert.deepEqual(evaluate(raw, base + 90, base + 90), {
    ...details(8), status: 'UNKNOWN', overall: 'INDETERMINATE', reason: 'OCSP_NOT_YET_KNOWN',
  });
  const invalidInterval = replaceInfo(issue(6, { nextUpdate: thisUpdate }), Buffer.concat([time, reasonField([8])]));
  assert.deepEqual(evaluate(invalidInterval, base + 90, base + 90), {
    status: 'INVALID', overall: 'INVALID', reason: 'OCSP_INTERVAL',
  });
});

test('OCSP authentication and request binding precede unsupported and stale reasons', () => {
  for (const reason of [6, 8]) {
    const raw = replaceInfo(held, Buffer.concat([time, reasonField([reason])])), bad = Buffer.from(raw);
    bad[bad.length - 1] ^= 1;
    assert.deepEqual(evaluate(bad, nextUpdate), { status: 'INVALID', overall: 'INVALID', reason: 'OCSP_SIGNATURE' });
    const wrongNonce = ocspRequest({ issuer, issuerPublicKey: key.publicKey, serial });
    assert.deepEqual(evaluate(raw, nextUpdate, nextUpdate, wrongNonce.raw), {
      status: 'INVALID', overall: 'INVALID', reason: 'OCSP_NONCE',
    });
    const wrongSerial = ocspRequest({ issuer, issuerPublicKey: key.publicKey, serial: serial + 1n });
    assert.deepEqual(evaluate(raw, nextUpdate, nextUpdate, wrongSerial.raw), {
      status: 'INVALID', overall: 'INVALID', reason: 'OCSP_CONTEXT',
    });
  }
});
