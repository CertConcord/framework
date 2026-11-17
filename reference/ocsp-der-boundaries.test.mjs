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
    ],
  );
  const positive = basicParts(response('valid-three-member'));
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
