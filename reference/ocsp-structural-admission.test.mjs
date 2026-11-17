import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { generate, parseDER, der, seq, octet } from './core.mjs';
import { name } from './pki.mjs';
import { issueOCSP, ocspRequest, verifyOCSP } from './revocation.mjs';

function fixture() {
  const issuer = name('Synthetic OCSP Issuer');
  const key = generate('ec');
  const at = 1_800_000_000;
  const request = ocspRequest(
    { issuer, issuerPublicKey: key.publicKey, serial: 41n },
    { nonce: Buffer.alloc(16, 0x41) },
  );
  const response = issueOCSP(request.raw, {
    issuer,
    issuerPublicKey: key.publicKey,
    privateKey: key.privateKey,
    records: new Map([['41', { status: 'GOOD' }]]),
    thisUpdate: at - 30,
    nextUpdate: at + 300,
  });
  const options = { request: request.raw, issuerPublicKey: key.publicKey, at, knowledgeTime: at };
  return { response, options };
}

test('OCSP admits only a complete successful status', () => {
  const { response, options } = fixture();
  const [, wrapper] = parseDER(response).children;

  const withStatus = (value) => seq(der(10, value), wrapper.raw);

  assert.equal(verifyOCSP(response, options).status, 'GOOD');
  assert.deepEqual(verifyOCSP(withStatus(Buffer.from([0, 0])), options), {
    status: 'INVALID',
    overall: 'INVALID',
    reason: 'OCSP_STATUS',
  });
  assert.deepEqual(verifyOCSP(withStatus(Buffer.from([0, 1])), options), {
    status: 'INVALID',
    overall: 'INVALID',
    reason: 'OCSP_STATUS',
  });
  assert.deepEqual(verifyOCSP(withStatus(Buffer.from([1])), options), {
    status: 'INVALID',
    overall: 'INVALID',
    reason: 'OCSP_STATUS',
  });
});

test('OCSP admits only a BIT STRING Basic signature', () => {
  const { response, options } = fixture();
  const [status, wrapper] = parseDER(response).children;
  const [responseType, basicOctets] = wrapper.children[0].children;
  const [tbs, algorithm, signature] = parseDER(basicOctets.value).children;
  const wrongTag = seq(
    status.raw,
    der(0xa0, seq(responseType.raw, octet(seq(tbs.raw, algorithm.raw, der(4, signature.value))))),
  );

  assert.equal(verifyOCSP(response, options).status, 'GOOD');
  assert.deepEqual(verifyOCSP(wrongTag, options), {
    status: 'INVALID',
    overall: 'INVALID',
    reason: 'OCSP_SIGNATURE',
  });
});

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/ocsp-structural-admission.json', import.meta.url)),
);
test('OCSP structural raw corpus retains original synthetic bytes and decisions', () => {
  assert.equal(vectors.schemaVersion, 1);
  assert.equal(vectors.profile, 'ocsp-structural-admission');
  assert.deepEqual(
    vectors.cases.map((row) => row.id),
    [
      'valid-successful',
      'redundant-zero-status',
      'leading-zero-nonzero-status',
      'non-success-status',
      'octet-string-signature',
    ],
  );
  const publicKey = createPublicKey({
    key: Buffer.from(vectors.publicKeySPKI, 'base64'),
    type: 'spki',
    format: 'der',
  });
  const request = Buffer.from(vectors.request, 'base64');
  for (const row of vectors.cases) {
    const raw = Buffer.from(row.raw, 'base64');
    assert.equal(createHash('sha256').update(raw).digest('hex'), row.sha256);
    assert.deepEqual(
      verifyOCSP(raw, {
        request,
        issuerPublicKey: publicKey,
        ...vectors.query,
      }),
      row.expected,
      row.id,
    );
  }
});
