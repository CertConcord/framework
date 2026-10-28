import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { seq, integer, der, bit, octet, parseDER, oidText } from './core.mjs';
import { name, algID, extension } from './pki.mjs';
import { issueCRL, verifyCRL, ocspRequest, issueOCSP, verifyOCSP } from './revocation.mjs';

const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const issuer = name('Synthetic CRL Time choice');
const number = 23n;
const unix = (text) => Date.parse(text) / 1000;
const encoded = (tag, text) => der(tag, Buffer.from(text, 'ascii'));
const text = (seconds) =>
  new Date(seconds * 1000).toISOString().slice(0, 19).replace(/[-:T]/g, '') + 'Z';
const canonical = (seconds) => {
  const year = new Date(seconds * 1000).getUTCFullYear();
  return year >= 1950 && year <= 2049 ? 23 : 24;
};
const time = (seconds, tag = canonical(seconds)) =>
  encoded(tag, tag === 23 ? text(seconds).slice(2) : text(seconds));
const instants = (iso) => {
  const thisUpdate = unix(iso);
  return {
    thisUpdate,
    nextUpdate: thisUpdate + 300,
    revokedAt: thisUpdate - 60,
    invalidityDate: thisUpdate - 60,
  };
};
const boundaries = [
  ['before-1950', '1949-12-31T23:50:00Z', [24, 24, 24]],
  ['cross-1950', '1949-12-31T23:59:30Z', [24, 23, 24]],
  ['exact-1950-revocation', '1950-01-01T00:01:00Z', [23, 23, 23]],
  ['negative-unix-to-epoch', '1969-12-31T23:59:30Z', [23, 23, 23]],
  ['year-1999', '1999-12-31T23:50:00Z', [23, 23, 23]],
  ['year-2000-leap', '2000-02-29T12:00:00Z', [23, 23, 23]],
  ['year-2049', '2049-12-31T23:50:00Z', [23, 23, 23]],
  ['cross-2050-update', '2049-12-31T23:59:30Z', [23, 24, 23]],
  ['cross-2050-revocation', '2050-01-01T00:00:30Z', [24, 24, 23]],
  ['year-2050', '2050-01-01T00:10:00Z', [24, 24, 24]],
];
function signedCRL(t, overrides = {}, signer = key) {
  const algorithm = algID('ec');
  const entry = seq(
    integer(7),
    overrides.revokedAt ?? time(t.revokedAt),
    seq(
      extension('2.5.29.21', der(10, Buffer.from([1]))),
      extension('2.5.29.24', overrides.invalidityDate ?? time(t.invalidityDate, 24)),
    ),
  );
  const tbs = seq(
    integer(1),
    algorithm,
    issuer,
    overrides.thisUpdate ?? time(t.thisUpdate),
    overrides.nextUpdate ?? time(t.nextUpdate),
    seq(entry),
    der(0xa0, seq(extension('2.5.29.20', integer(number)))),
  );
  return seq(tbs, algorithm, bit(sign('sha256', tbs, signer.privateKey)));
}
function crlNodes(raw) {
  const [tbs, , signature] = parseDER(raw).children;
  assert.equal(verify('sha256', tbs.raw, key.publicKey, signature.value.subarray(1)), true);
  const a = tbs.children,
    entry = a[5].children[0].children;
  const ext = entry[2].children.find((e) => oidText(e.children[0]) === '2.5.29.24');
  return {
    thisUpdate: a[3],
    nextUpdate: a[4],
    revokedAt: entry[1],
    invalidityDate: parseDER(ext.children.at(-1).value),
  };
}
function expected(t, status = 'GOOD', reason) {
  return {
    number,
    thisUpdate: t.thisUpdate,
    nextUpdate: t.nextUpdate,
    scope: 'COMPLETE_ISSUER_CRL',
    status,
    overall: status === 'GOOD' ? 'VALID' : status === 'REVOKED' ? 'INVALID' : 'INDETERMINATE',
    ...(reason ? { reason } : {}),
  };
}
function check(raw, t, serial = 8n, at = t.thisUpdate + 30, knowledgeTime = at) {
  const result = verifyCRL(raw, { issuer, publicKey: key.publicKey, serial, at, knowledgeTime });
  assert.equal(Object.isFrozen(result), true);
  return result;
}
const invalidTime = { status: 'INVALID', overall: 'INVALID', reason: 'STATUS_TIME' };

for (const [id, iso, tags] of boundaries) {
  const t = instants(iso);
  test('CRL Time issuer selects each tag at ' + id, () => {
    const raw = issueCRL({
      issuer,
      privateKey: key.privateKey,
      number,
      thisUpdate: t.thisUpdate,
      nextUpdate: t.nextUpdate,
      entries: [{ serial: 7, reason: 1, revokedAt: t.revokedAt, invalidityDate: t.invalidityDate }],
    });
    const nodes = crlNodes(raw);
    for (const [i, field] of ['thisUpdate', 'nextUpdate', 'revokedAt'].entries()) {
      assert.equal(nodes[field].tag, tags[i], field);
      assert.deepEqual(
        nodes[field].value,
        Buffer.from(tags[i] === 23 ? text(t[field]).slice(2) : text(t[field]), 'ascii'),
        field,
      );
    }
    assert.equal(nodes.invalidityDate.tag, 24);
    assert.deepEqual(nodes.invalidityDate.value, Buffer.from(text(t.invalidityDate), 'ascii'));
    assert.deepEqual(check(raw, t), expected(t));
    assert.deepEqual(check(raw, t, 7n), expected(t, 'REVOKED', 'CRL_REVOKED'));
  });
  test('CRL Time consumer preserves complete decisions at ' + id, () => {
    const raw = signedCRL(t);
    crlNodes(raw);
    assert.deepEqual(check(raw, t), expected(t));
    assert.deepEqual(check(raw, t, 7n), expected(t, 'REVOKED', 'CRL_REVOKED'));
  });
}

const t = instants('2049-12-31T23:50:00Z');
for (const field of ['thisUpdate', 'nextUpdate', 'revokedAt']) {
  test('CRL Time consumer accepts isolated UTC ' + field, () => {
    const overrides = Object.fromEntries(
      ['thisUpdate', 'nextUpdate', 'revokedAt'].map((p) => [p, time(t[p], p === field ? 23 : 24)]),
    );
    const raw = signedCRL(t, overrides),
      nodes = crlNodes(raw);
    assert.equal(nodes[field].tag, 23);
    assert.deepEqual(check(raw, t), expected(t));
    assert.deepEqual(check(raw, t, 7n), expected(t, 'REVOKED', 'CRL_REVOKED'));
  });
}
for (const iso of ['1949-12-31T23:50:00Z', '2049-12-31T23:50:00Z', '2050-01-01T00:10:00Z']) {
  test('CRL Time consumer retains GeneralizedTime ' + iso.slice(0, 4), () => {
    const t = instants(iso);
    const raw = signedCRL(
      t,
      Object.fromEntries(['thisUpdate', 'nextUpdate', 'revokedAt'].map((p) => [p, time(t[p], 24)])),
    );
    assert.deepEqual(
      Object.values(crlNodes(raw)).map((n) => n.tag),
      [24, 24, 24, 24],
    );
    assert.deepEqual(check(raw, t), expected(t));
    assert.deepEqual(check(raw, t, 7n), expected(t, 'REVOKED', 'CRL_REVOKED'));
  });
}
const malformed = [
  ['nonleap-day', '490229120000Z'],
  ['april-31', '490431120000Z'],
  ['month-13', '491301120000Z'],
  ['zero-month-day', '490000120000Z'],
  ['hour-24', '490101240000Z'],
  ['minute-60', '490101126000Z'],
  ['second-60', '490101120060Z'],
  ['missing-seconds', '4901011200Z'],
  ['offset', '490101120000+0000'],
  ['fraction', '490101120000.0Z'],
  ['lowercase-zone', '490101120000z'],
  ['nondecimal', '49A101120000Z'],
];
for (const field of ['thisUpdate', 'nextUpdate', 'revokedAt']) {
  for (const [id, value] of malformed)
    test('CRL Time rejects UTC ' + field + ' ' + id, () => {
      const raw = signedCRL(t, { [field]: encoded(23, value) });
      const nodes = crlNodes(raw);
      assert.deepEqual(nodes[field].value, Buffer.from(value, 'ascii'));
      assert.deepEqual(check(raw, t), invalidTime);
    });
}
test('CRL Time preserves UTC revocation and knowledge boundaries', () => {
  const raw = signedCRL(t);
  assert.deepEqual(check(raw, t, 7n, t.revokedAt - 1, t.thisUpdate + 1), expected(t));
  assert.deepEqual(
    check(raw, t, 7n, t.revokedAt, t.thisUpdate + 1),
    expected(t, 'REVOKED', 'CRL_REVOKED'),
  );
  assert.deepEqual(
    check(raw, t, 8n, t.thisUpdate, t.thisUpdate - 1),
    expected(t, 'UNKNOWN', 'CRL_NOT_YET_KNOWN'),
  );
  assert.deepEqual(check(raw, t, 8n, t.thisUpdate, t.nextUpdate - 1), expected(t));
  assert.deepEqual(
    check(raw, t, 8n, t.thisUpdate, t.nextUpdate),
    expected(t, 'STALE', 'CRL_STALE'),
  );
  assert.deepEqual(
    check(raw, t, 7n, t.thisUpdate, t.nextUpdate),
    expected(t, 'REVOKED', 'CRL_REVOKED'),
  );
});
test('CRL Time retains actual signing-key verification', () => {
  const raw = signedCRL(t, {}, other),
    [tbs, , signature] = parseDER(raw).children;
  assert.equal(verify('sha256', tbs.raw, other.publicKey, signature.value.subarray(1)), true);
  assert.equal(verify('sha256', tbs.raw, key.publicKey, signature.value.subarray(1)), false);
  assert.deepEqual(check(raw, t), {
    status: 'INVALID',
    overall: 'INVALID',
    reason: 'CRL_SIGNATURE',
  });
});
test('CRL Time keeps invalidityDate GeneralizedTime-only', () => {
  const valid = signedCRL(t),
    invalid = signedCRL(t, { invalidityDate: time(t.invalidityDate, 23) });
  assert.equal(crlNodes(valid).invalidityDate.tag, 24);
  assert.equal(crlNodes(invalid).invalidityDate.tag, 23);
  assert.deepEqual(check(valid, t, 7n), expected(t, 'REVOKED', 'CRL_REVOKED'));
  assert.deepEqual(check(invalid, t, 7n), invalidTime);
});

const request = ocspRequest(
  { issuer, issuerPublicKey: key.publicKey, serial: 7 },
  { nonce: Buffer.alloc(20, 0x63) },
);
function ocspParts(raw) {
  const outer = parseDER(raw),
    response = outer.children[1].children[0];
  const basic = parseDER(response.children[1].value),
    tbs = basic.children[0];
  return { outer, response, basic, tbs, single: tbs.children[2].children[0] };
}
function utcOCSP(raw, field) {
  const q = ocspParts(raw),
    a = q.tbs.children.map((n) => n.raw),
    s = q.single.children.map((n) => n.raw);
  if (field === 'producedAt') a[1] = time(t.thisUpdate, 23);
  if (field === 'thisUpdate') s[2] = time(t.thisUpdate, 23);
  if (field === 'nextUpdate') s[3] = der(0xa0, time(t.nextUpdate, 23));
  if (field === 'revokedAt')
    s[1] = der(
      0xa1,
      Buffer.concat([
        time(t.revokedAt, 23),
        ...q.single.children[1].children.slice(1).map((n) => n.raw),
      ]),
    );
  a[2] = seq(seq(...s));
  const tbs = seq(...a),
    basic = seq(tbs, q.basic.children[1].raw, bit(sign('sha256', tbs, key.privateKey)));
  return seq(q.outer.children[0].raw, der(0xa0, seq(q.response.children[0].raw, octet(basic))));
}
for (const field of ['producedAt', 'thisUpdate', 'nextUpdate', 'revokedAt'])
  test('CRL Time change keeps OCSP ' + field + ' GeneralizedTime-only', () => {
    const valid = issueOCSP(request.raw, {
      issuer,
      issuerPublicKey: key.publicKey,
      privateKey: key.privateKey,
      records: new Map([['7', { status: 'REVOKED', revokedAt: t.revokedAt, reason: 1 }]]),
      thisUpdate: t.thisUpdate,
      nextUpdate: t.nextUpdate,
    });
    const invalid = utcOCSP(valid, field);
    for (const raw of [valid, invalid]) {
      const q = ocspParts(raw);
      assert.equal(
        verify('sha256', q.tbs.raw, key.publicKey, q.basic.children[2].value.subarray(1)),
        true,
      );
    }
    const options = {
      request: request.raw,
      issuerPublicKey: key.publicKey,
      at: t.thisUpdate + 30,
      knowledgeTime: t.thisUpdate + 30,
    };
    const result = verifyOCSP(valid, options);
    assert.deepEqual(result, {
      thisUpdate: t.thisUpdate,
      nextUpdate: t.nextUpdate,
      producedAt: t.thisUpdate,
      revokedAt: t.revokedAt,
      revocationReason: 1,
      status: 'REVOKED',
      overall: 'INVALID',
      reason: 'OCSP_REVOKED',
    });
    assert.equal(Object.isFrozen(result), true);
    assert.deepEqual(verifyOCSP(invalid, options), invalidTime);
  });

for (const field of ['thisUpdate', 'nextUpdate', 'revokedAt'])
  test('CRL Time rejects non-ASCII UTC octets in ' + field, () => {
    const bytes = Buffer.from(text(t[field]).slice(2), 'ascii').map((byte) => byte | 0x80);
    const raw = signedCRL(t, { [field]: der(23, bytes) });
    assert.equal(raw.includes(bytes), true);
    assert.throws(() => parseDER(raw), { code: 'DER_TIME_CHARACTER' });
    assert.deepEqual(check(raw, t), {
      status: 'INVALID',
      overall: 'INVALID',
      reason: 'DER_TIME_CHARACTER',
    });
    assert.deepEqual(check(signedCRL(t), t), expected(t));
  });
