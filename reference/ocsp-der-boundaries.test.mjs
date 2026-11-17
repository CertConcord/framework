import test from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { der, octet, parseDER, seq, verify } from './core.mjs';
import { parseOCSPRequest, verifyOCSP } from './revocation.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/ocsp-der-boundaries.json', import.meta.url)),
);
const request = Buffer.from(vectors.request, 'base64');
const issuerCertificate = Buffer.from(vectors.issuerCertificate, 'base64');
const issuerPublicKey = new X509Certificate(issuerCertificate).publicKey;
const options = { request, issuerPublicKey, ...vectors.query };
const response = (id) => Buffer.from(vectors.cases.find((row) => row.id === id).raw, 'base64');

function basicParts(raw) {
  const [status, wrapper] = parseDER(raw).children;
  const [responseType, payload] = wrapper.children[0].children;
  const basic = parseDER(payload.value);
  return { status, responseBytes: wrapper.children[0], responseType, payload, basic };
}

test('frozen signed OCSP response boundaries retain original structures', () => {
  assert.equal(vectors.schemaVersion, 1);
  assert.equal(vectors.profile, 'ocsp-der-boundaries');
  assert.deepEqual(
    vectors.cases.map((row) => row.id),
    [
      'valid-three-member',
      'responsebytes-extra-null',
      'basic-extra-null',
      'nonce-wrong-inner-tag',
      'responseextensions-extra-null',
      'responder-bykey-extra-null',
      'responses-set-tag',
      'singleresponse-context-tag',
      'nextupdate-wrong-wrapper',
      'nonce-outer-wrong-tag',
      'certs-malformed-certificate',
      'ocspresponse-root-context-tag',
    ],
  );
  const canonicalEnvelope = response('valid-three-member');
  const wrongEnvelope = response('ocspresponse-root-context-tag');
  assert.equal(canonicalEnvelope[0], 0x30);
  assert.equal(wrongEnvelope[0], 0xa0);
  assert.deepEqual(wrongEnvelope.subarray(1), canonicalEnvelope.subarray(1));
  const positive = basicParts(canonicalEnvelope);
  assert.deepEqual(
    positive.basic.children.map((n) => n.tag),
    [48, 48, 3],
  );
  assert.deepEqual(
    basicParts(response('basic-extra-null')).basic.children.map((n) => n.tag),
    [48, 48, 3, 5],
  );
  assert.deepEqual(
    basicParts(response('responsebytes-extra-null')).responseBytes.children.map((n) => n.tag),
    [6, 4, 5],
  );
  assert.equal(
    basicParts(
      response('nonce-wrong-inner-tag'),
    ).basic.children[0].children[3].children[0].children[0].children.at(-1).value[0],
    0x80,
  );
  assert.deepEqual(
    basicParts(
      response('responseextensions-extra-null'),
    ).basic.children[0].children[3].children.map((n) => n.tag),
    [48, 5],
  );
  assert.deepEqual(
    basicParts(response('responder-bykey-extra-null')).basic.children[0].children[0].children.map(
      (n) => n.tag,
    ),
    [4, 5],
  );
  assert.equal(basicParts(response('responses-set-tag')).basic.children[0].children[2].tag, 0x31);
  assert.equal(
    basicParts(response('singleresponse-context-tag')).basic.children[0].children[2].children[0]
      .tag,
    0xa0,
  );
  const nextUpdate = basicParts(response('nextupdate-wrong-wrapper')).basic.children[0].children[2]
    .children[0].children[3];
  assert.equal(nextUpdate.tag, 0xa1);
  assert.deepEqual(
    nextUpdate.children.map((n) => n.tag),
    [24],
  );
  assert.equal(
    basicParts(
      response('nonce-outer-wrong-tag'),
    ).basic.children[0].children[3].children[0].children[0].children.at(-1).tag,
    0x80,
  );
  assert.deepEqual(
    basicParts(
      response('certs-malformed-certificate'),
    ).basic.children[3].children[0].children[0].children.map((n) => n.tag),
    [5],
  );
});

for (const row of vectors.cases) {
  test(`frozen signed OCSP response ${row.id}`, () => {
    const raw = Buffer.from(row.raw, 'base64');
    assert.equal(createHash('sha256').update(raw).digest('hex'), row.sha256);
    const { basic } = basicParts(raw);
    const [tbs, , signature] = basic.children;
    assert.equal(verify(tbs.raw, signature.value.subarray(1), issuerPublicKey), true);
    assert.deepEqual(verifyOCSP(raw, options), row.expected);
  });
}

test('legal explicit certs preserve a signed BasicOCSPResponse', () => {
  const { status, responseType, basic } = basicParts(response('valid-three-member'));
  const withCerts = seq(
    status.raw,
    der(
      0xa0,
      seq(
        responseType.raw,
        octet(seq(...basic.children.map((n) => n.raw), der(0xa0, seq(issuerCertificate)))),
      ),
    ),
  );
  const decoded = basicParts(withCerts).basic;
  assert.deepEqual(
    decoded.children.map((n) => n.tag),
    [48, 48, 3, 0xa0],
  );
  assert.deepEqual(verifyOCSP(withCerts, options), vectors.cases[0].expected);
  const withExtra = seq(
    status.raw,
    der(
      0xa0,
      seq(
        responseType.raw,
        octet(seq(...decoded.children.map((n) => n.raw), der(5, Buffer.alloc(0)))),
      ),
    ),
  );
  assert.deepEqual(verifyOCSP(withExtra, options), {
    status: 'INVALID',
    overall: 'INVALID',
    reason: 'OCSP_SIGNATURE',
  });
});

test('outer OCSPRequest requires SEQUENCE before nonce and CertID binding', () => {
  const malformed = Buffer.from(vectors.requestOuterContextTag.raw, 'base64');
  assert.equal(malformed.length, vectors.requestOuterContextTag.bytes);
  assert.equal(
    createHash('sha256').update(malformed).digest('hex'),
    vectors.requestOuterContextTag.sha256,
  );
  assert.equal(request[0], 0x30);
  assert.equal(malformed[0], 0xa0);
  assert.deepEqual(malformed.subarray(1), request.subarray(1));
  assert.throws(() => parseOCSPRequest(malformed), /OCSP_REQUEST/);
  assert.deepEqual(verifyOCSP(response('valid-three-member'), { ...options, request: malformed }), {
    status: 'INVALID',
    overall: 'INVALID',
    reason: 'OCSP_REQUEST',
  });
});

test('requestList requires SEQUENCE before Request and nonce binding', () => {
  const malformed = Buffer.from(vectors.requestListContextTag.raw, 'base64');
  assert.equal(malformed.length, vectors.requestListContextTag.bytes);
  assert.equal(
    createHash('sha256').update(malformed).digest('hex'),
    vectors.requestListContextTag.sha256,
  );
  assert.equal(request[6], 0x30);
  assert.equal(malformed[6], 0xa0);
  assert.deepEqual(malformed.subarray(0, 6), request.subarray(0, 6));
  assert.deepEqual(malformed.subarray(7), request.subarray(7));
  const requestList = parseDER(malformed).children[0].children[0];
  assert.equal(requestList.tag, 0xa0);
  assert.throws(() => parseOCSPRequest(malformed), /OCSP_REQUEST/);
  assert.deepEqual(verifyOCSP(response('valid-three-member'), { ...options, request: malformed }), {
    status: 'INVALID',
    overall: 'INVALID',
    reason: 'OCSP_REQUEST',
  });
});

test('TBSRequest requires SEQUENCE before requestList and nonce binding', () => {
  const malformed = Buffer.from(vectors.tbsRequestContextTag.raw, 'base64');
  assert.equal(malformed.length, vectors.tbsRequestContextTag.bytes);
  assert.equal(
    createHash('sha256').update(malformed).digest('hex'),
    vectors.tbsRequestContextTag.sha256,
  );
  assert.equal(request[3], 0x30);
  assert.equal(malformed[3], 0xa0);
  assert.deepEqual(malformed.subarray(0, 3), request.subarray(0, 3));
  assert.deepEqual(malformed.subarray(4), request.subarray(4));
  assert.equal(parseDER(malformed).tag, 0x30);
  assert.equal(parseDER(malformed).children[0].tag, 0xa0);
  assert.throws(() => parseOCSPRequest(malformed), /OCSP_REQUEST/);
  assert.deepEqual(verifyOCSP(response('valid-three-member'), { ...options, request: malformed }), {
    status: 'INVALID',
    overall: 'INVALID',
    reason: 'OCSP_REQUEST',
  });
});

test('Request item requires SEQUENCE before reqCert and nonce binding', () => {
  const malformed = Buffer.from(vectors.requestItemContextTag.raw, 'base64');
  assert.equal(malformed.length, vectors.requestItemContextTag.bytes);
  assert.equal(
    createHash('sha256').update(malformed).digest('hex'),
    vectors.requestItemContextTag.sha256,
  );
  assert.equal(request[8], 0x30);
  assert.equal(malformed[8], 0xa0);
  assert.deepEqual(malformed.subarray(0, 8), request.subarray(0, 8));
  assert.deepEqual(malformed.subarray(9), request.subarray(9));
  assert.equal(parseDER(malformed).children[0].children[0].children[0].tag, 0xa0);
  assert.throws(() => parseOCSPRequest(malformed), /OCSP_REQUEST/);
  assert.deepEqual(verifyOCSP(response('valid-three-member'), { ...options, request: malformed }), {
    status: 'INVALID',
    overall: 'INVALID',
    reason: 'OCSP_REQUEST',
  });
});

test('signed response Extension item requires SEQUENCE', () => {
  const positiveRaw = response('valid-three-member');
  const row = vectors.responseExtensionItemContextTag;
  const malformed = Buffer.from(row.raw, 'base64');
  assert.equal(createHash('sha256').update(positiveRaw).digest('hex'), 'ab61af042bba4172113cb840a2a42420e3b2d3ddb14626d5bd6e4b63bfb3b3d7');
  assert.equal(malformed.length, row.bytes);
  assert.equal(createHash('sha256').update(malformed).digest('hex'), '2d3f8fbb6b2ff964c0e38027a95a5b112645edc3d38a2cc2c37e16f2fa06489c');
  const positiveBasic = basicParts(positiveRaw).basic;
  const negativeBasic = basicParts(malformed).basic;
  const positiveTBS = positiveBasic.children[0].raw;
  const negativeTBS = negativeBasic.children[0].raw;
  assert.equal(positiveTBS.length, negativeTBS.length);
  assert.equal(createHash('sha256').update(positiveTBS).digest('hex'), 'f5c3fa72aa3651b385dd5767b43785c63871c866921fe2f9e4e41c118a7da26c');
  assert.equal(createHash('sha256').update(negativeTBS).digest('hex'), '2c9a9e4bb20a67e8b43d2d447d53dbf1f8aca255db0142e2562b8d21ce03c03b');
  const changed = [...negativeTBS.keys()].filter((i) => negativeTBS[i] !== positiveTBS[i]);
  assert.deepEqual(changed, [176]);
  assert.deepEqual([positiveTBS[176], negativeTBS[176]], [0x30, 0xa1]);
  assert.equal(verify(positiveTBS, positiveBasic.children[2].value.subarray(1), issuerPublicKey), true);
  assert.equal(verify(negativeTBS, negativeBasic.children[2].value.subarray(1), issuerPublicKey), true);
  assert.deepEqual(verifyOCSP(positiveRaw, options), vectors.cases[0].expected);
  assert.deepEqual(verifyOCSP(malformed, options), {
    status: 'INVALID', overall: 'INVALID', reason: 'STATUS_EXTENSION',
  });
});

const requestExtensionsExpected = new Map([
  ['requestExtensions-wrapper', [96, 0xa2, 0xa3, 'OCSP_REQUEST']],
  ['extensions-collection', [98, 0x30, 0xa1, 'STATUS_EXTENSION']],
  ['extension-item', [100, 0x30, 0xa1, 'STATUS_EXTENSION']],
  ['extnValue-octet', [113, 0x04, 0x80, 'STATUS_EXTENSION']],
  ['nonce-inner-octet', [115, 0x04, 0x80, 'OCSP_NONCE']],
]);
for (const row of vectors.requestExtensionsMatrix)
  test(`requestExtensions tag matrix: ${row.id}`, () => {
    assert.equal(vectors.requestExtensionsMatrix.length, 5);
    const expected = requestExtensionsExpected.get(row.id);
    assert.ok(expected);
    assert.deepEqual([row.changedOffset, row.beforeTag, row.afterTag], expected.slice(0, 3));
    const malformed = Buffer.from(row.raw, 'base64');
    assert.equal(malformed.length, row.bytes);
    assert.equal(createHash('sha256').update(malformed).digest('hex'), row.sha256);
    assert.equal(malformed.length, request.length);
    const changed = [...malformed.keys()].filter((i) => malformed[i] !== request[i]);
    assert.deepEqual(changed, [row.changedOffset]);
    assert.equal(request[row.changedOffset], row.beforeTag);
    assert.equal(malformed[row.changedOffset], row.afterTag);
    const reason = expected[3];
    assert.throws(() => parseOCSPRequest(malformed), new RegExp(reason));
    assert.deepEqual(
      verifyOCSP(response('valid-three-member'), { ...options, request: malformed }),
      {
        status: 'INVALID',
        overall: 'INVALID',
        reason,
      },
    );
  });

test('request nonce requires inner OCTET STRING', () => {
  const tbs = parseDER(request).children[0];
  const [requestList, extensions] = tbs.children;
  const nonceExtension = extensions.children[0].children[0];
  const [id, extnValue] = nonceExtension.children;
  const nonce = parseDER(extnValue.value);
  assert.equal(nonce.tag, 4);
  const wrongRequest = seq(
    seq(requestList.raw, der(0xa2, seq(seq(id.raw, octet(der(0x80, nonce.value)))))),
  );
  assert.throws(() => parseOCSPRequest(wrongRequest), /OCSP_NONCE/);
  assert.deepEqual(
    verifyOCSP(response('valid-three-member'), {
      ...options,
      request: wrongRequest,
    }),
    { status: 'INVALID', overall: 'INVALID', reason: 'OCSP_NONCE' },
  );
});
