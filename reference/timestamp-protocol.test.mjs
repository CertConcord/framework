import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import * as c from './core.mjs';
import {
  encodeTimestampRequest,
  parseTimestampRequest,
  encodeTimestampResponse,
  parseTimestampResponse,
  encodeTSTInfo,
} from './timestamp-protocol.mjs';
import { O, epoch, fixture } from './cades-fixtures.mjs';

let f, token;
const imprint = Buffer.alloc(32, 0x37);
before(() => {
  f = fixture();
  token = f.token(
    { hashOID: O.sha256, imprint, policy: O.policy, nonce: 42n },
    { genTime: epoch + 20 },
  );
});
after(() => f?.close());
const algorithm = (id, parameters = []) => c.seq(c.oid(id), ...parameters);
const request = (fields = [], hashOID = O.sha256, digest = imprint, parameters = []) =>
  c.seq(c.integer(1), c.seq(algorithm(hashOID, parameters), c.octet(digest)), ...fields);
const invalid = (operation, code) => assert.throws(operation, { code, overall: 'INVALID' });

test('independent minimal request uses RFC defaults for absent nonce, policy and certReq', () => {
  const raw = request(),
    parsed = parseTimestampRequest(raw);
  assert.equal(parsed.hashOID, O.sha256);
  assert.deepEqual(parsed.imprint, imprint);
  assert.equal(parsed.nonce, undefined);
  assert.equal(parsed.policyOID, undefined);
  assert.equal(parsed.certReq, false);
  assert.deepEqual(parsed.extensions, []);
});
for (const [hashAlgorithm, hashOID, length] of [
  ['sha256', O.sha256, 32],
  ['sha512', O.sha512, 64],
]) {
  for (const certReq of [false, true])
    test(`${hashAlgorithm} request has independently expected DER fields with certReq=${certReq}`, () => {
      const digest = Buffer.alloc(length, 0x72);
      const raw = encodeTimestampRequest({
        imprint: digest,
        hashAlgorithm,
        policyOID: O.policy,
        nonce: 42n,
        certReq,
      });
      assert.deepEqual(
        raw,
        request(
          [c.oid(O.policy), c.integer(42), ...(certReq ? [c.der(1, Buffer.from([255]))] : [])],
          hashOID,
          digest,
        ),
      );
      const parsed = parseTimestampRequest(raw);
      assert.equal(parsed.nonce, 42n);
      assert.equal(parsed.policyOID, O.policy);
      assert.equal(parsed.certReq, certReq);
      assert.deepEqual(parsed.imprint, digest);
    });
  test(`${hashAlgorithm} request parser accepts the standard NULL AlgorithmIdentifier parameter`, () => {
    assert.equal(
      parseTimestampRequest(request([], hashOID, Buffer.alloc(length), [c.der(5, Buffer.alloc(0))]))
        .hashOID,
      hashOID,
    );
  });
}
test('fresh default nonces are distinct positive 128-bit values and null deliberately omits nonce', () => {
  const first = parseTimestampRequest(encodeTimestampRequest({ imprint }));
  const second = parseTimestampRequest(encodeTimestampRequest({ imprint }));
  assert(first.nonce > 0n && first.nonce < 1n << 128n);
  assert(second.nonce > 0n && second.nonce < 1n << 128n);
  assert.notEqual(first.nonce, second.nonce);
  assert.equal(
    parseTimestampRequest(encodeTimestampRequest({ imprint, nonce: null })).nonce,
    undefined,
  );
});
for (const nonce of [0n, (1n << 256n) - 1n])
  test(`nonce boundary ${nonce === 0n ? 'zero' : '256-bit maximum'} is exact`, () => {
    assert.equal(parseTimestampRequest(encodeTimestampRequest({ imprint, nonce })).nonce, nonce);
  });
test('request input and parsed byte views have independent ownership', () => {
  const digest = Buffer.from(imprint),
    encoded = encodeTimestampRequest({ imprint: digest, nonce: 42n });
  const original = Buffer.from(encoded),
    parsed = parseTimestampRequest(encoded);
  digest.fill(0);
  encoded.fill(0);
  parsed.raw.fill(0);
  assert.deepEqual(parsed.imprint, imprint);
  parsed.imprint.fill(1);
  assert.deepEqual(parseTimestampRequest(original).imprint, imprint);
});
test('OpenSSL independently reads the selected request fields', () => {
  const raw = encodeTimestampRequest({ imprint, policyOID: O.policy, nonce: 42n });
  writeFileSync(f.file('application-request.der'), raw);
  const text = f.run('ts', '-query', '-in', f.file('application-request.der'), '-text');
  assert.match(text, /Version: 1/);
  assert.match(text, /Hash Algorithm: sha256/);
  assert.match(text, /Nonce: 0x2A/i);
  assert.match(text, /Certificate required: yes/);
});
test('recognized unselected request hash reports badAlg without aliasing it to SHA256', () => {
  assert.throws(
    () => parseTimestampRequest(request([], '2.16.840.1.101.3.4.2.2', Buffer.alloc(48))),
    {
      code: 'TSP_HASH_UNSUPPORTED',
      overall: 'UNSUPPORTED',
      failureBit: 0,
      failureInfo: 'badAlg',
    },
  );
});
test('a standard request extension reports unacceptedExtension rather than being ignored', () => {
  const extension = c.seq(c.oid('1.2.3.4'), c.octet(Buffer.from([1])));
  assert.throws(() => parseTimestampRequest(request([c.der(0xa0, extension)])), {
    code: 'TSP_EXTENSIONS_UNSUPPORTED',
    overall: 'UNSUPPORTED',
    failureBit: 16,
  });
});
for (const [name, fields, code] of [
  ['duplicate nonce', [c.integer(1), c.integer(2)], 'TSP_REQUEST_FIELD_ORDER'],
  ['policy after nonce', [c.integer(1), c.oid(O.policy)], 'TSP_REQUEST_FIELD_ORDER'],
  ['explicit DEFAULT FALSE', [c.der(1, Buffer.from([0]))], 'TSP_CERTREQ_ENCODING'],
])
  test(`request ${name} is rejected`, () =>
    invalid(() => parseTimestampRequest(request(fields)), code));
test('selected digest length mismatch is INVALID even when a request version is unselected', () => {
  const raw = c.seq(c.integer(2), c.seq(algorithm(O.sha256), c.octet(Buffer.alloc(31))));
  invalid(() => parseTimestampRequest(raw), 'TSP_IMPRINT_LENGTH');
});
test('nonce beyond the selected bound is explicit unsupported capability', () => {
  assert.throws(() => encodeTimestampRequest({ imprint, nonce: 1n << 256n }), {
    code: 'TSP_NONCE_RANGE',
    overall: 'UNSUPPORTED',
  });
});

for (const status of [0, 1])
  test(`successful response status ${status} retains exact genuine token bytes`, () => {
    const response = encodeTimestampResponse({
      status,
      tokenDER: token,
      statusStrings: ['Accordé', '时间戳'],
    });
    const parsed = parseTimestampResponse(response);
    assert.equal(parsed.status, status);
    assert.deepEqual(parsed.tokenDER, token);
    assert.deepEqual(parsed.statusStrings, ['Accordé', '时间戳']);
    assert.deepEqual(parsed.failureBits, []);
    assert.deepEqual(parsed.diagnostics, []);
  });
test('failure bits use RFC bit positions and canonical named-bit-list encoding', () => {
  const bits = [0, 2, 5, 14, 15, 16, 17, 25];
  const encoded = encodeTimestampResponse({ status: 2, failureBits: bits });
  assert.equal(c.parseDER(encoded).children[0].children[1].raw.toString('hex'), '030506a403c040');
  assert.deepEqual(parseTimestampResponse(encoded).failureBits, bits);
});
for (const status of [2, 3, 4, 5])
  test(`standard no-token response status ${status} remains information rather than a proof`, () => {
    const parsed = parseTimestampResponse(encodeTimestampResponse({ status }));
    assert.equal(parsed.status, status);
    assert.equal(parsed.tokenDER, undefined);
  });
for (const status of [0, 1])
  test(`successful response ${status} requires a token`, () => {
    invalid(
      () => parseTimestampResponse(c.seq(c.seq(c.integer(status)))),
      'TSP_STATUS_TOKEN_BINDING',
    );
  });
test('rejection with a token is INVALID but preserves safely extracted token for signature checking', () => {
  assert.throws(
    () => parseTimestampResponse(c.seq(c.seq(c.integer(2)), token)),
    (error) => {
      assert.equal(error.code, 'TSP_STATUS_TOKEN_BINDING');
      assert.equal(error.overall, 'INVALID');
      assert.deepEqual(error.partial.tokenDER, token);
      return true;
    },
  );
});
test('unknown status retains a bounded token and an explicit unsupported diagnostic', () => {
  const parsed = parseTimestampResponse(c.seq(c.seq(c.integer(6)), token));
  assert.deepEqual(parsed.tokenDER, token);
  assert.deepEqual(parsed.diagnostics, [
    { overall: 'UNSUPPORTED', reason: 'TSP_STATUS_UNSUPPORTED' },
  ]);
});
test('unknown failure bit is retained as an unsupported diagnostic', () => {
  const parsed = parseTimestampResponse(
    c.seq(c.seq(c.integer(2), c.der(3, Buffer.from([3, 0, 0, 8])))),
  );
  assert.deepEqual(parsed.failureBits, [20]);
  assert.deepEqual(parsed.diagnostics, [
    { overall: 'UNSUPPORTED', reason: 'TSP_FAILURE_BITS_UNSUPPORTED' },
  ]);
});
test('granted status cannot contradict itself with failure information', () => {
  invalid(
    () => encodeTimestampResponse({ status: 0, tokenDER: token, failureBits: [2] }),
    'TSP_STATUS_FAILURE_CONTRADICTION',
  );
});
test('response ownership and input byte limits are enforced', () => {
  const encoded = encodeTimestampResponse({ status: 0, tokenDER: token });
  const original = Buffer.from(encoded),
    parsed = parseTimestampResponse(encoded);
  encoded.fill(0);
  parsed.raw.fill(0);
  assert.deepEqual(parsed.tokenDER, token);
  parsed.tokenDER.fill(0);
  assert.deepEqual(parseTimestampResponse(original).tokenDER, token);
  assert.throws(() => parseTimestampRequest(Buffer.alloc(65537)), {
    code: 'TSP_REQUEST_LIMIT',
    overall: 'UNSUPPORTED',
  });
  assert.throws(() => parseTimestampResponse(Buffer.alloc(1048577)), {
    code: 'TSP_RESPONSE_LIMIT',
    overall: 'UNSUPPORTED',
  });
});
test('OpenSSL independently reads a genuine standard successful response', () => {
  writeFileSync(
    f.file('application-response.der'),
    encodeTimestampResponse({ status: 0, tokenDER: token }),
  );
  const text = f.run('ts', '-reply', '-in', f.file('application-response.der'), '-text');
  assert.match(text, /Status: Granted\./);
  assert.match(text, /Hash Algorithm: sha256/);
  assert.match(text, /Nonce: 0x2A/i);
});

for (const [accuracyMicros, expected] of [
  [0, '3003020100'],
  [1, '3003810101'],
  [999, '3004810203e7'],
  [1000, '3003800101'],
  [1001, '3006800101810101'],
  [999999, '3008800203e7810203e7'],
  [1000000, '3003020101'],
  [1234567, '300b020101800200ea81020237'],
  [60000000, '300302013c'],
])
  test(`TSTInfo accuracy ${accuracyMicros} microseconds has exact standard DER`, () => {
    const encoded = encodeTSTInfo({
      policyOID: O.policy,
      hashOID: O.sha256,
      imprint,
      serial: 1n,
      genTime: epoch + 20,
      accuracyMicros,
      nonce: 42n,
    });
    const fields = c.parseDER(encoded).children;
    assert.equal(fields[5].raw.toString('hex'), expected);
    assert.equal(fields[4].value.toString('ascii'), '20270115080020Z');
    assert.equal(c.intValue(fields[3]), 1n);
    assert.equal(c.intValue(fields[6]), 42n);
    assert.equal(fields.length, 7);
  });
test('TSTInfo positive serial bound and exact integral accuracy limits are explicit', () => {
  const input = {
    policyOID: O.policy,
    hashOID: O.sha256,
    imprint,
    serial: (1n << 160n) - 1n,
    genTime: epoch + 20,
    accuracyMicros: 0,
  };
  assert.equal(c.intValue(c.parseDER(encodeTSTInfo(input)).children[3]), input.serial);
  assert.throws(() => encodeTSTInfo({ ...input, serial: 0n }), {
    code: 'TSP_SERIAL_RANGE',
    overall: 'UNSUPPORTED',
  });
  assert.throws(() => encodeTSTInfo({ ...input, serial: 1n << 160n }), {
    code: 'TSP_SERIAL_RANGE',
    overall: 'UNSUPPORTED',
  });
  for (const accuracyMicros of [-1, 0.5, 60000001])
    invalid(() => encodeTSTInfo({ ...input, accuracyMicros }), 'TSP_ACCURACY_RANGE');
});
